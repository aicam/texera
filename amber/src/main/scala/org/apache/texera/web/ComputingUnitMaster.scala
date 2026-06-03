/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.texera.web

import com.fasterxml.jackson.module.scala.DefaultScalaModule
import com.typesafe.scalalogging.LazyLogging
import io.dropwizard.Configuration
import io.dropwizard.configuration.{EnvironmentVariableSubstitutor, SubstitutingSourceProvider}
import io.dropwizard.setup.{Bootstrap, Environment}
import io.dropwizard.websockets.WebsocketBundle
import org.apache.texera.amber.config.ApplicationConfig
import org.apache.texera.amber.core.workflow.{PhysicalPlan, WorkflowContext}
import org.apache.texera.amber.engine.architecture.controller.ControllerConfig
import org.apache.texera.amber.engine.architecture.rpc.controlreturns.WorkflowAggregatedState.KILLED
import org.apache.texera.amber.engine.common.client.AmberClient
import org.apache.texera.amber.engine.common.{AmberRuntime, Utils}
import org.apache.texera.amber.engine.common.Utils.maptoStatusCode
import org.apache.texera.amber.util.{ObjectMapperUtils, PhysicalPlanSerdeModule}
import org.apache.commons.jcs3.access.exception.InvalidArgumentException
import org.apache.texera.web.resource.{
  SyncExecutionResource,
  WebsocketPayloadSizeTuner,
  WorkflowWebsocketResource
}
import org.apache.texera.web.service.{ExecutionsMetadataPersistService, WorkflowService}
import org.eclipse.jetty.server.session.SessionHandler
import org.eclipse.jetty.servlet.FilterHolder
import org.eclipse.jetty.websocket.server.WebSocketUpgradeFilter
import org.apache.texera.web.resource.pythonvirtualenvironment.PveResource
import org.apache.texera.web.resource.pythonvirtualenvironment.PveWebsocketResource

import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean
import scala.annotation.tailrec

object ComputingUnitMaster {

  def createAmberRuntime(
      workflowContext: WorkflowContext,
      physicalPlan: PhysicalPlan,
      conf: ControllerConfig,
      errorHandler: Throwable => Unit
  ): AmberClient = {
    new AmberClient(
      AmberRuntime.actorSystem,
      workflowContext,
      physicalPlan,
      conf,
      errorHandler
    )
  }

  type OptionMap = Map[Symbol, Any]

  def parseArgs(args: Array[String]): OptionMap = {
    @tailrec
    def nextOption(map: OptionMap, list: List[String]): OptionMap = {
      list match {
        case Nil => map
        case "--cluster" :: value :: tail =>
          nextOption(map ++ Map(Symbol("cluster") -> value.toBoolean), tail)
        case option :: tail =>
          throw new InvalidArgumentException("unknown command-line arg")
      }
    }

    nextOption(Map(), args.toList)
  }

  def main(args: Array[String]): Unit = {
    val argMap = parseArgs(args)

    val clusterMode = argMap.get(Symbol("cluster")).asInstanceOf[Option[Boolean]].getOrElse(false)
    // start actor system master node
    AmberRuntime.startActorMaster(clusterMode)
    // start web server
    new ComputingUnitMaster().run(
      "server",
      Utils.amberHomePath
        .resolve("src")
        .resolve("main")
        .resolve("resources")
        .resolve("computing-unit-master-config.yml")
        .toString
    )
  }
}

class ComputingUnitMaster extends io.dropwizard.Application[Configuration] with LazyLogging {

  private val shutdownFlushed = new AtomicBoolean(false)

  /**
    * On graceful CU shutdown, finalize any execution still in a non-terminal state as KILLED. The CU
    * is going away, so an orphaned RUNNING/READY/PAUSED row would otherwise lock its workflow until
    * the staleness window elapsed; flushing it makes the unlock immediate. The write goes through the
    * same conditional, terminal-monotonic UPDATE, so a genuinely-finished run (already terminal) is
    * left untouched. Best-effort: a hard kill (SIGKILL/OOM) runs no hook and is handled by lazy
    * on-read staleness instead.
    */
  private def flushNonTerminalExecutions(): Unit = {
    if (!shutdownFlushed.compareAndSet(false, true)) return
    // Snapshot the registry so a concurrent lifecycle-cleanup removal can't perturb the iteration.
    WorkflowService.getAllWorkflowServices.toList.foreach { ws =>
      try {
        Option(ws.executionService.getValue).foreach { execService =>
          val code = maptoStatusCode(execService.executionStateStore.metadataStore.getState.state)
          if (code >= 0 && code < 3) {
            // Single-shot (no retry) under the shutdown deadline; lazy on-read staleness is the
            // backstop for any execution whose flush does not reach the dashboard in time.
            ExecutionsMetadataPersistService.updateExecutionStatus(
              execService.workflowContext.executionId,
              maptoStatusCode(KILLED).toShort,
              retryTerminal = false
            )
          }
        }
      } catch {
        case t: Throwable =>
          logger.warn(s"Best-effort shutdown status flush failed: ${t.getMessage}")
      }
    }
  }

  override def initialize(bootstrap: Bootstrap[Configuration]): Unit = {
    // enable environment variable substitution in YAML config
    bootstrap.setConfigurationSourceProvider(
      new SubstitutingSourceProvider(
        bootstrap.getConfigurationSourceProvider,
        new EnvironmentVariableSubstitutor(false)
      )
    )
    // add websocket bundle
    bootstrap.addBundle(
      new WebsocketBundle(
        classOf[WorkflowWebsocketResource],
        classOf[PveWebsocketResource]
      )
    )
    // register scala module to dropwizard default object mapper
    bootstrap.getObjectMapper.registerModule(DefaultScalaModule)
    // The execution request carries a pre-compiled PhysicalPlan; register its serializers so the
    // CU deserializes it byte-for-byte compatibly with the workflow-compiling-service's output.
    PhysicalPlanSerdeModule.register(bootstrap.getObjectMapper)
  }

  override def run(configuration: Configuration, environment: Environment): Unit = {
    ObjectMapperUtils.warmupObjectMapperForOperatorsSerde()

    // On graceful shutdown, finalize any still-running execution so a departing CU does not leave a
    // workflow locked until the staleness window elapses.
    environment
      .lifecycle()
      .manage(new io.dropwizard.lifecycle.Managed {
        override def start(): Unit = {}
        override def stop(): Unit = flushNonTerminalExecutions()
      })

    // The Computing Unit never connects to Postgres: it routes execution-metadata operations over
    // HTTP to the dashboard service and holds no database credentials of its own (issue #5011).
    // Because SqlServer is never initialized here, RemoteExecutionMetadata is always active.

    environment.jersey.setUrlPattern("/api/*")

    val webSocketUpgradeFilter =
      WebSocketUpgradeFilter.configureContext(environment.getApplicationContext)
    webSocketUpgradeFilter.getFactory.getPolicy.setIdleTimeout(Duration.ofHours(1).toMillis)
    environment.getApplicationContext.setAttribute(
      classOf[WebSocketUpgradeFilter].getName,
      webSocketUpgradeFilter
    )

    // register SessionHandler
    environment.jersey.register(classOf[SessionHandler])
    environment.servlets.setSessionHandler(new SessionHandler)

    environment.jersey.register(classOf[PveResource])

    // The Computing Unit performs no JWT authentication and holds no JWT secret (issue #5011): no
    // JwtAuthFilter, no RolesAllowedDynamicFeature, and no @Auth-injection binder are registered —
    // none of its endpoints are authenticated. The client ships a pre-compiled physical plan, and
    // anything needing auth (e.g. result export) is served by the dashboard service instead.
    // Contrast TexeraWebApplication, which keeps full JWT auth.
    environment
      .servlets()
      .addServletListeners(
        new WebsocketPayloadSizeTuner(ApplicationConfig.maxWorkflowWebsocketRequestPayloadSizeKb)
      )

    // Expired-result/log cleanup needs a database connection, so it is owned by the dashboard
    // service; the computing unit (which holds no Postgres credentials) does not run it.

    // The computing unit does not expose the /executions HTTP resource: result export (its only
    // client-facing endpoints) is handled by the dashboard service, which has the auth, database,
    // and shared Iceberg (Lakekeeper) catalog access to read and export results. The CU still calls
    // WorkflowExecutionsResource's companion-object helpers internally; it just doesn't serve them.
    environment.jersey.register(classOf[SyncExecutionResource])

    // Route request logs through SLF4J, controlled by TEXERA_SERVICE_LOG_LEVEL.
    // TODO: replace with RequestLoggingFilter.register() from common/auth once Dropwizard is upgraded to 4.x
    val requestLogger = org.slf4j.LoggerFactory.getLogger("org.eclipse.jetty.server.RequestLog")
    environment.getApplicationContext.addFilter(
      new FilterHolder(new javax.servlet.Filter {
        override def init(filterConfig: javax.servlet.FilterConfig): Unit = {}
        override def doFilter(
            request: javax.servlet.ServletRequest,
            response: javax.servlet.ServletResponse,
            chain: javax.servlet.FilterChain
        ): Unit = {
          chain.doFilter(request, response)
          if (requestLogger.isInfoEnabled) {
            val req = request.asInstanceOf[javax.servlet.http.HttpServletRequest]
            val resp = response.asInstanceOf[javax.servlet.http.HttpServletResponse]
            requestLogger.info(
              s"""${req.getRemoteAddr} - "${req.getMethod} ${req.getRequestURI} ${req.getProtocol}" ${resp.getStatus}"""
            )
          }
        }
        override def destroy(): Unit = {}
      }),
      "/*",
      java.util.EnumSet.allOf(classOf[javax.servlet.DispatcherType])
    )
  }

}
