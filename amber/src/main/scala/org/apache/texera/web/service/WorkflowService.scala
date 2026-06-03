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

package org.apache.texera.web.service

import com.google.protobuf.timestamp.Timestamp
import com.typesafe.scalalogging.LazyLogging
import io.reactivex.rxjava3.disposables.{CompositeDisposable, Disposable}
import io.reactivex.rxjava3.subjects.BehaviorSubject
import org.apache.texera.amber.config.ApplicationConfig
import org.apache.texera.amber.core.WorkflowRuntimeException
import org.apache.texera.amber.core.storage.DocumentFactory
import org.apache.texera.amber.core.storage.result.iceberg.OnIceberg
import org.apache.texera.amber.core.virtualidentity.{
  EmbeddedControlMessageIdentity,
  ExecutionIdentity,
  WorkflowIdentity
}
import org.apache.texera.amber.core.workflow.WorkflowContext
import org.apache.texera.amber.core.workflowruntimestate.FatalErrorType.EXECUTION_FAILURE
import org.apache.texera.amber.core.workflowruntimestate.WorkflowFatalError
import org.apache.texera.amber.engine.architecture.controller.ControllerConfig
import org.apache.texera.amber.engine.architecture.rpc.controlreturns.WorkflowAggregatedState.{
  COMPLETED,
  FAILED
}
import org.apache.texera.amber.engine.architecture.worker.WorkflowWorker.{
  FaultToleranceConfig,
  StateRestoreConfig
}
import org.apache.texera.amber.error.ErrorUtils.{
  getOperatorFromActorIdOpt,
  getStackTraceWithAllCauses
}
import org.apache.texera.dao.jooq.generated.tables.pojos.User
import org.apache.texera.service.util.LargeBinaryManager
import org.apache.texera.web.model.websocket.event.{CacheUsageUpdateEvent, TexeraWebSocketEvent}
import org.apache.texera.web.model.websocket.request.WorkflowExecuteRequest
import org.apache.texera.web.resource.dashboard.user.workflow.WorkflowExecutionsResource
import org.apache.texera.web.service.WorkflowService.mkWorkflowStateId
import org.apache.texera.web.storage.ExecutionStateStore.updateWorkflowState
import org.apache.texera.web.storage.{ExecutionStateStore, WorkflowStateStore}
import org.apache.texera.web.{SubscriptionManager, WorkflowLifecycleManager}
import org.apache.texera.amber.compiler.model.LogicalPlan
import play.api.libs.json.Json

import java.net.URI
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import scala.jdk.CollectionConverters.IterableHasAsScala

object WorkflowService {
  private val workflowServiceMapping = new ConcurrentHashMap[String, WorkflowService]()
  val cleanUpDeadlineInSeconds: Int = ApplicationConfig.executionStateCleanUpInSecs

  def getAllWorkflowServices: Iterable[WorkflowService] = workflowServiceMapping.values().asScala

  def mkWorkflowStateId(workflowId: WorkflowIdentity): String = {
    workflowId.toString
  }

  def getOrCreate(
      workflowId: WorkflowIdentity,
      computingUnitId: Int,
      cleanupTimeout: Int = cleanUpDeadlineInSeconds
  ): WorkflowService = {
    workflowServiceMapping.compute(
      mkWorkflowStateId(workflowId),
      (_, v) => {
        if (v == null) {
          new WorkflowService(workflowId, computingUnitId, cleanupTimeout)
        } else {
          v
        }
      }
    )
  }
}

class WorkflowService(
    val workflowId: WorkflowIdentity,
    val computingUnitId: Int,
    cleanUpTimeout: Int
) extends SubscriptionManager
    with LazyLogging {

  // state across execution:
  private val errorSubject = BehaviorSubject.create[TexeraWebSocketEvent]().toSerialized
  val stateStore = new WorkflowStateStore()
  var executionService: BehaviorSubject[WorkflowExecutionService] = BehaviorSubject.create()

  val resultService: ExecutionResultService =
    new ExecutionResultService(workflowId, computingUnitId, stateStore)
  // Operator-port-result cache. On a Postgres-free computing unit (issue #5011) the persistence is
  // routed to the Dashboard Service over HTTP (RemoteOperatorPortCacheService); on the dashboard
  // itself (which holds STORAGE_JDBC_*) it talks to Postgres directly.
  val cacheService: OperatorPortCache =
    if (RemoteExecutionMetadata.enabled) new RemoteOperatorPortCacheService()
    else
      new OperatorPortCacheService(
        new org.apache.texera.web.dao.OperatorPortCacheDao(org.apache.texera.dao.SqlServer.getInstance())
      )
  val lifeCycleManager: WorkflowLifecycleManager = new WorkflowLifecycleManager(
    s"workflowId=$workflowId",
    cleanUpTimeout,
    () => {
      // Clear execution-scoped artifacts (runtime stats, result/console docs, cache entries) for all
      // executions. This runs on a lifecycle timer with no request context (hence no per-execution
      // user token); it is best-effort, so a metadata failure here must never propagate and tear
      // down the session.
      try {
        val executionIds = WorkflowExecutionService.getExecutionIds(workflowId, computingUnitId)
        clearExecutionResources(executionIds)
      } catch {
        case e: Throwable =>
          logger.warn(s"Best-effort end-of-session cleanup failed (continuing): ${e.getMessage}")
      }
      WorkflowService.workflowServiceMapping.remove(mkWorkflowStateId(workflowId))
      if (executionService.getValue != null) {
        // shutdown client
        executionService.getValue.client.shutdown()
      }
      unsubscribeAll()
    }
  )

  var lastCompletedLogicalPlan: Option[LogicalPlan] = Option.empty

  executionService.subscribe { executionService: WorkflowExecutionService =>
    {
      executionService.executionStateStore.metadataStore.registerDiffHandler {
        (oldState, newState) =>
          {
            if (oldState.state != COMPLETED && newState.state == COMPLETED) {
              lastCompletedLogicalPlan = executionService.workflow.logicalPlan
            }
            Iterable.empty
          }
      }
    }
  }

  def connect(onNext: TexeraWebSocketEvent => Unit): Disposable = {
    lifeCycleManager.increaseUserCount()
    val subscriptions = stateStore.getAllStores
      .map(_.getWebsocketEventObservable)
      .map(evtPub =>
        evtPub.subscribe { evts: Iterable[TexeraWebSocketEvent] => evts.foreach(onNext) }
      )
      .toSeq
    val errorSubscription = errorSubject.subscribe { evt: TexeraWebSocketEvent => onNext(evt) }
    new CompositeDisposable(subscriptions :+ errorSubscription: _*)
  }

  /**
    * Subscribes to execution-scoped websocket events and emits cache usage snapshots
    * so refreshed sessions can rehydrate cached output labels.
    */
  def connectToExecution(onNext: TexeraWebSocketEvent => Unit): Disposable = {
    val localDisposable = new CompositeDisposable()
    val disposable = executionService.subscribe { execService: WorkflowExecutionService =>
      localDisposable.clear() // Clears previous subscriptions safely
      val subscriptions = execService.executionStateStore.getAllStores
        .map(_.getWebsocketEventObservable)
        .map(evtPub =>
          evtPub.subscribe { events: Iterable[TexeraWebSocketEvent] => events.foreach(onNext) }
        )
        .toSeq
      localDisposable.addAll(subscriptions: _*)
      emitCacheUsageSnapshot(execService, onNext)
    }
    // Note: this new CompositeDisposable is necessary. DO NOT OPTIMIZE.
    new CompositeDisposable(localDisposable, disposable)
  }

  /**
    * Sends the latest cache usage metadata for the current execution to a new subscriber.
    */
  private def emitCacheUsageSnapshot(
      execService: WorkflowExecutionService,
      onNext: TexeraWebSocketEvent => Unit
  ): Unit = {
    val cachedOutputs = execService.executionStateStore.cacheUsageStore.getState.cachedOutputs
    onNext(CacheUsageUpdateEvent(cachedOutputs))
  }

  def disconnect(): Unit = {
    lifeCycleManager.decreaseUserCount(
      Option(executionService.getValue).map(_.executionStateStore.metadataStore.getState.state)
    )
  }

  private[this] def createWorkflowContext(): WorkflowContext = {
    new WorkflowContext(workflowId = workflowId, cuid = Some(computingUnitId))
  }

  def initExecutionService(
      req: WorkflowExecuteRequest,
      userOpt: Option[User],
      sessionUri: URI
  ): Unit = {

    if (executionService.hasValue) {
      executionService.getValue.unsubscribeAll()
    }

    // The execution owner is optional here: a no-auth computing unit has no local user, so it sends
    // no uid and the dashboard service resolves the owner from the forwarded token. The DB's NOT NULL
    // constraint on uid is surfaced as a readable error by ExecutionsMetadataPersistService if needed.
    val (uidOpt, userEmailOpt) = userOpt.map(user => (user.getUid, user.getEmail)).unzip

    val workflowContext: WorkflowContext = createWorkflowContext()
    // The issuing user's JWT travels in the request; the CU forwards it on its outbound calls.
    workflowContext.userJwtToken = req.userJwtToken
    var controllerConf = ControllerConfig.default

    // NOTE: the previous run's results are intentionally NOT cleaned up here. Operator-port-result
    // caching reuses materialized outputs across executions of the same workflow, so prior results
    // must survive into the next run. Stale resources are reclaimed by the lifecycle-timer cleanup
    // (which invalidates cache entries by source execution). The new execution's per-execution token
    // is registered below via insertNewExecution -> RemoteExecutionMetadata.createExecution.

    workflowContext.executionId = ExecutionsMetadataPersistService.insertNewExecution(
      workflowContext.workflowId,
      uidOpt.orNull,
      req.executionName,
      convertToJson(req.engineVersion),
      req.computingUnitId,
      req.userJwtToken
    )

    if (ApplicationConfig.faultToleranceLogRootFolder.isDefined) {
      val writeLocation = ApplicationConfig.faultToleranceLogRootFolder.get.resolve(
        s"${workflowContext.workflowId}/${workflowContext.executionId}/"
      )
      ExecutionsMetadataPersistService.tryUpdateExistingExecution(workflowContext.executionId) {
        execution => execution.setLogLocation(writeLocation.toString)
      }
      controllerConf = controllerConf.copy(faultToleranceConfOpt =
        Some(FaultToleranceConfig(writeTo = writeLocation))
      )
    }
    if (req.replayFromExecution.isDefined) {
      val replayInfo = req.replayFromExecution.get
      ExecutionsMetadataPersistService
        .tryGetExistingExecution(ExecutionIdentity(replayInfo.eid))
        .foreach { execution =>
          val readLocation = new URI(execution.getLogLocation)
          controllerConf = controllerConf.copy(stateRestoreConfOpt =
            Some(
              StateRestoreConfig(
                readFrom = readLocation,
                replayDestination = EmbeddedControlMessageIdentity(replayInfo.interaction)
              )
            )
          )
        }
    }

    val executionStateStore = new ExecutionStateStore()
    // assign execution id to find the execution from DB in case the constructor fails.
    executionStateStore.metadataStore.updateState(state =>
      state.withExecutionId(workflowContext.executionId)
    )
    val errorHandler: Throwable => Unit = { t =>
      {
        val fromActorOpt = t match {
          case ex: WorkflowRuntimeException =>
            ex.relatedWorkerId
          case other =>
            None
        }
        val (operatorId, workerId) = getOperatorFromActorIdOpt(fromActorOpt)
        logger.error("error during execution", t)
        executionStateStore.statsStore.updateState(stats =>
          stats.withEndTimeStamp(System.currentTimeMillis())
        )
        executionStateStore.metadataStore.updateState { metadataStore =>
          updateWorkflowState(FAILED, metadataStore).addFatalErrors(
            WorkflowFatalError(
              EXECUTION_FAILURE,
              Timestamp(Instant.now),
              t.toString,
              getStackTraceWithAllCauses(t),
              operatorId,
              workerId
            )
          )
        }
      }
    }
    try {
      val execution = new WorkflowExecutionService(
        controllerConf,
        workflowContext,
        resultService,
        cacheService,
        req,
        executionStateStore,
        errorHandler,
        userEmailOpt,
        sessionUri
      )
      lifeCycleManager.registerCleanUpOnStateChange(executionStateStore)
      executionService.onNext(execution)
      execution.executeWorkflow()
    } catch {
      case e: Throwable => errorHandler(e)
    }

  }

  def convertToJson(frontendVersion: String): String = {
    val environmentVersionMap = Map(
      "engine_version" -> Json.toJson(frontendVersion)
    )
    Json.stringify(Json.toJson(environmentVersionMap))
  }

  override def unsubscribeAll(): Unit = {
    super.unsubscribeAll()
    Option(executionService.getValue).foreach(_.unsubscribeAll())
    resultService.unsubscribeAll()
  }

  /**
    * Cleans up all resources associated with workflow executions.
    *
    * This method performs resource cleanup in the following sequence:
    *  1. Retrieves all document URIs associated with the executions
    *  2. Invalidates cache entries produced by these executions (cache rows + cached docs + cache-linked operator_port_executions rows)
    *  3. Clears URI references from the execution registry
    *  4. Safely clears all result and console message documents
    *  5. Expires Iceberg snapshots for runtime statistics
    *  6. Deletes large binaries from MinIO
    *
    * @param executionIds execution identities to clean up resources for
    */
  private def clearExecutionResources(executionIds: Seq[ExecutionIdentity]): Unit = {
    if (executionIds.isEmpty) {
      return
    }
    // Cleanup is best-effort housekeeping: it reaches the dashboard for these executions' resource
    // URIs and cache rows, which can fail (e.g. no usable token for an execution this CU didn't
    // create this run). A failure here must not crash the run that triggered the cleanup, so swallow
    // and log it. The per-execution tokens are always dropped afterwards to keep the registry bounded.
    try {
      val runtimeStatsUris =
        executionIds.flatMap(eid =>
          WorkflowExecutionsResource.getRuntimeStatsUriByExecutionId(eid).toList
        )

      // Invalidate cache artifacts produced by these executions (cache rows + cached docs +
      // cache-linked operator_port_executions rows). On the Postgres-free CU this is routed to the
      // dashboard over HTTP.
      val cacheInvalidation =
        cacheService.invalidateCacheBySourceExecutionsWithArtifacts(executionIds)

      val resultUris = executionIds
        .flatMap(WorkflowExecutionsResource.getResultUrisByExecutionId)
        .filterNot(cacheInvalidation.deletedResultUris.contains)
      val consoleMessagesUris =
        executionIds.flatMap(WorkflowExecutionsResource.getConsoleMessagesUriByExecutionId)

      // Remove references from registry first
      executionIds.foreach(WorkflowExecutionsResource.deleteConsoleMessageAndExecutionResultUris)

      // Clean up all result and console message documents
      (resultUris ++ consoleMessagesUris).distinct.foreach { uri =>
        try DocumentFactory.openDocument(uri)._1.clear()
        catch {
          case error: Throwable =>
            logger.debug(s"Error processing document at $uri: ${error.getMessage}")
        }
      }

      // Expire any Iceberg snapshots for runtime statistics
      runtimeStatsUris.distinct.foreach { uri =>
        try {
          DocumentFactory.openDocument(uri)._1 match {
            case iceberg: OnIceberg => iceberg.expireSnapshots()
            case other =>
              logger.error(
                s"Cannot expire snapshots: document from URI [$uri] is of type ${other.getClass.getName}. " +
                  s"Expected an instance of ${classOf[OnIceberg].getName}."
              )
          }
        } catch {
          case error: Throwable =>
            logger.debug(s"Error processing document at $uri: ${error.getMessage}")
        }
      }
      // Delete large binaries
      LargeBinaryManager.deleteAllObjects()
    } catch {
      case e: Throwable =>
        logger.warn(
          s"Best-effort cleanup of executions ${executionIds.map(_.id).mkString(",")} failed " +
            s"(continuing): ${e.getMessage}"
        )
    } finally {
      // Drop any remembered per-execution tokens so the registry stays bounded to live executions.
      executionIds.foreach(eid => RemoteExecutionMetadata.clearExecutionToken(eid.id))
    }
  }
}
