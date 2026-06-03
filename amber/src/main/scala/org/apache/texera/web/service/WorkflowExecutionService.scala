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

import com.typesafe.scalalogging.LazyLogging
import org.apache.texera.amber.core.virtualidentity.{
  ExecutionIdentity,
  OperatorIdentity,
  WorkflowIdentity
}
import org.apache.texera.amber.core.workflow.{CachedOutput, GlobalPortIdentity, WorkflowContext}
import org.apache.texera.amber.engine.architecture.controller.{ControllerConfig, Workflow}
import org.apache.texera.amber.engine.architecture.rpc.controlcommands.EmptyRequest
import org.apache.texera.amber.engine.architecture.rpc.controlreturns.WorkflowAggregatedState._
import org.apache.texera.amber.engine.common.Utils
import org.apache.texera.amber.engine.common.client.AmberClient
import org.apache.texera.amber.engine.common.executionruntimestate.ExecutionMetadataStore
import org.apache.texera.amber.core.workflow.cache.FingerprintUtil
import org.apache.texera.amber.util.serde.GlobalPortIdentitySerde.SerdeOps
import org.apache.texera.web.model.websocket.event.{
  CacheUsageUpdateEvent,
  CachedPortUsage,
  TexeraWebSocketEvent,
  WorkflowErrorEvent,
  WorkflowStateEvent
}
import org.apache.texera.web.model.websocket.request.WorkflowExecuteRequest
import org.apache.texera.web.resource.dashboard.user.workflow.WorkflowExecutionsResource
import org.apache.texera.web.storage.{ExecutionCacheUsageStore, ExecutionStateStore}
import org.apache.texera.web.storage.ExecutionStateStore.updateWorkflowState
import org.apache.texera.web.{ComputingUnitMaster, SubscriptionManager, WebsocketInput}

import java.net.URI
import scala.collection.mutable

object WorkflowExecutionService {
  def getLatestExecutionId(
      workflowId: WorkflowIdentity,
      computingUnitId: Int,
      userJwtToken: Option[String] = None
  ): Option[ExecutionIdentity] = {
    WorkflowExecutionsResource
      .getLatestExecutionID(workflowId.id.toInt, computingUnitId, userJwtToken)
      .map(eid => new ExecutionIdentity(eid.longValue()))
  }

  /**
    * The non-internal output ports that need result storage so their results are viewable: the
    * output ports of every TERMINAL physical operator (no downstream links — i.e. the operators at
    * the end of each path, whose outputs are the workflow's results) UNION those of the explicitly
    * requested to-view ("eye-icon") operators.
    *
    * Since the client now ships a ready-to-run physical plan and the CU no longer compiles in
    * process, the CU re-derives this set here. It mirrors the in-process compiler's original rule
    * (`logicalPlan.getTerminalOperatorIds ++ opsToViewResult`), expressed on the physical plan via
    * downstream-link reachability. (Blocking/intermediate edges are materialized separately by the
    * schedule generator.)
    */
  def outputPortsForViewResult(
      physicalPlan: org.apache.texera.amber.core.workflow.PhysicalPlan,
      opsToViewResult: Seq[String]
  ): Set[GlobalPortIdentity] = {
    val viewOps = opsToViewResult.map(OperatorIdentity(_)).toSet
    physicalPlan.operators
      .filter { physicalOp =>
        // a terminal operator (no downstream physical links) is a workflow output, OR the operator
        // was explicitly requested for viewing.
        physicalPlan.getDownstreamPhysicalLinks(physicalOp.id).isEmpty ||
        viewOps.contains(physicalOp.id.logicalOpId)
      }
      .flatMap { physicalOp =>
        physicalOp.outputPorts.keys
          .filterNot(_.internal)
          .map(portId => GlobalPortIdentity(opId = physicalOp.id, portId = portId))
      }
      .toSet
  }

  /**
    * Retrieve all execution IDs for a workflow and computing unit.
    *
    * @param workflowId workflow identity
    * @param computingUnitId computing unit id
    * @return execution IDs ordered by newest first
    */
  def getExecutionIds(
      workflowId: WorkflowIdentity,
      computingUnitId: Int
  ): Seq[ExecutionIdentity] = {
    WorkflowExecutionsResource
      .getExecutionIDs(workflowId.id.toInt, computingUnitId)
      .map(eid => new ExecutionIdentity(eid.longValue()))
  }
}

class WorkflowExecutionService(
    controllerConfig: ControllerConfig,
    val workflowContext: WorkflowContext,
    resultService: ExecutionResultService,
    cacheService: OperatorPortCache,
    request: WorkflowExecuteRequest,
    val executionStateStore: ExecutionStateStore,
    errorHandler: Throwable => Unit,
    userEmailOpt: Option[String],
    sessionUri: URI
) extends SubscriptionManager
    with LazyLogging {

  workflowContext.workflowSettings = request.workflowSettings
  val wsInput = new WebsocketInput(errorHandler)

  addSubscription(
    executionStateStore.metadataStore.registerDiffHandler((oldState, newState) => {
      val outputEvents = new mutable.ArrayBuffer[TexeraWebSocketEvent]()

      if (newState.state != oldState.state || newState.isRecovering != oldState.isRecovering) {
        outputEvents.append(createStateEvent(newState))
      }

      if (newState.fatalErrors != oldState.fatalErrors) {
        outputEvents.append(WorkflowErrorEvent(newState.fatalErrors))
      }

      outputEvents
    })
  )
  addSubscription(
    executionStateStore.cacheUsageStore.registerDiffHandler((_, newState) => {
      Iterable(CacheUsageUpdateEvent(newState.cachedOutputs))
    })
  )
  addSubscription(
    executionStateStore.cacheEntryUpdateStore.registerDiffHandler((_, newState) => {
      newState.lastUpdate.toList
    })
  )

  private def createStateEvent(state: ExecutionMetadataStore): WorkflowStateEvent = {
    if (state.isRecovering && state.state != COMPLETED) {
      WorkflowStateEvent("Recovering")
    } else {
      WorkflowStateEvent(Utils.aggregatedStateToString(state.state))
    }
  }

  var workflow: Workflow = _

  // Runtime starts from here:
  logger.info("Initialing an AmberClient, runtime starting...")
  var client: AmberClient = _
  var executionReconfigurationService: ExecutionReconfigurationService = _
  var executionStatsService: ExecutionStatsService = _
  var executionRuntimeService: ExecutionRuntimeService = _
  var executionConsoleService: ExecutionConsoleService = _
  var executionCacheService: ExecutionCacheService = _

  /**
    * Lookup cached outputs for the physical plan and return them keyed by GlobalPortIdentity.
    *
    * This is used both for workflow settings (serialized key map) and for cache
    * metadata updates sent to the UI.
    */
  private def computeCachedOutputs(
      physicalPlan: org.apache.texera.amber.core.workflow.PhysicalPlan
  ): Map[GlobalPortIdentity, CachedOutput] = {
    cacheService.lookupCachedOutputs(workflowContext.workflowId, workflowContext.executionId, physicalPlan)
  }

  /**
    * Build cache usage metadata for the current execution from matched cached outputs.
    */
  private def buildCacheUsageEntries(
      physicalPlan: org.apache.texera.amber.core.workflow.PhysicalPlan,
      cachedOutputs: Map[GlobalPortIdentity, CachedOutput]
  ): List[CachedPortUsage] = {
    cachedOutputs.toList
      .map {
        case (gpid, cached) =>
          val fingerprint = FingerprintUtil.computeSubdagFingerprint(physicalPlan, gpid)
          CachedPortUsage(
            globalPortId = gpid.serializeAsString,
            logicalOpId = gpid.opId.logicalOpId.id,
            layerName = gpid.opId.layerName,
            portId = gpid.portId.id,
            internal = gpid.portId.internal,
            subdagHash = fingerprint.subdagHash,
            tupleCount = cached.tupleCount,
            sourceExecutionId = cached.sourceExecutionId.map(_.id)
          )
      }
      .sortBy(entry => (entry.logicalOpId, entry.layerName, entry.portId))
  }

  /**
    * Compiles the workflow, prepares cache metadata, initializes execution services, and starts execution.
    */
  def executeWorkflow(): Unit = {
    // The client (frontend / agent service) compiles the workflow against the
    // workflow-compiling-service and sends the ready-to-run physical plan; the CU just runs it —
    // no compilation, no authentication. The runtime does not need the logical plan (None).
    val physicalPlan = request.physicalPlan
    workflow = Workflow(workflowContext, None, physicalPlan)

    // Result-storage planning is an execution-time concern that does not travel in the physical
    // plan: mark the output ports of the to-view operators as needing storage. (Terminal sink
    // ports are materialized by the schedule generator regardless of this set.)
    val viewOutputPorts =
      WorkflowExecutionService.outputPortsForViewResult(physicalPlan, request.opsToViewResult)

    // Operator-port-result cache lookup against the client-supplied physical plan. Fingerprinting is
    // pure/local; on the Postgres-free CU the lookup itself is routed to the dashboard over HTTP.
    // Best-effort: a cache failure degrades to "no cache" and never fails the run.
    val cachedOutputs: Map[String, CachedOutput] =
      try {
        val cachedOutputsByPort = computeCachedOutputs(workflow.physicalPlan)
        val cacheUsageEntries = buildCacheUsageEntries(workflow.physicalPlan, cachedOutputsByPort)
        executionStateStore.cacheUsageStore.updateState(_ =>
          ExecutionCacheUsageStore(cacheUsageEntries)
        )
        cachedOutputsByPort.map { case (gpid, cached) => gpid.serializeAsString -> cached }
      } catch {
        case err: Throwable =>
          logger.warn(
            s"Operator-port-result cache lookup failed (continuing without cache): ${err.getMessage}"
          )
          Map.empty[String, CachedOutput]
      }

    workflowContext.workflowSettings = workflowContext.workflowSettings.copy(
      outputPortsNeedingStorage =
        workflowContext.workflowSettings.outputPortsNeedingStorage ++ viewOutputPorts,
      cachedOutputs = cachedOutputs
    )

    client = ComputingUnitMaster.createAmberRuntime(
      workflow.context,
      workflow.physicalPlan,
      controllerConfig,
      errorHandler
    )
    executionReconfigurationService =
      new ExecutionReconfigurationService(client, executionStateStore, workflow)
    executionStatsService = new ExecutionStatsService(client, executionStateStore, workflow.context)
    executionCacheService =
      new ExecutionCacheService(
        client,
        cacheService,
        workflow.context,
        workflow.physicalPlan,
        executionStateStore
      )
    executionRuntimeService = new ExecutionRuntimeService(
      client,
      executionStateStore,
      wsInput,
      executionReconfigurationService,
      controllerConfig.faultToleranceConfOpt,
      workflowContext.workflowId.id,
      request.emailNotificationEnabled,
      userEmailOpt,
      sessionUri
    )
    executionConsoleService =
      new ExecutionConsoleService(client, executionStateStore, wsInput, workflow.context)

    logger.info("Starting the workflow execution.")
    resultService.attachToExecution(
      workflow.context.executionId,
      executionStateStore,
      workflow.physicalPlan,
      client
    )
    executionStateStore.metadataStore.updateState(metadataStore =>
      updateWorkflowState(READY, metadataStore)
        .withFatalErrors(Seq.empty)
    )
    executionStateStore.statsStore.updateState(stats =>
      stats.withStartTimeStamp(System.currentTimeMillis())
    )
    client.controllerInterface
      .startWorkflow(EmptyRequest(), ())
      .onFailure(err => {
        errorHandler(err)
      })
      .onSuccess(resp =>
        executionStateStore.metadataStore.updateState(metadataStore =>
          if (metadataStore.state != FAILED && metadataStore.state != COMPLETED) {
            updateWorkflowState(resp.workflowState, metadataStore)
          } else {
            metadataStore
          }
        )
      )
  }

  override def unsubscribeAll(): Unit = {
    super.unsubscribeAll()
    if (client != null) {
      // runtime created
      client.shutdown()
      executionRuntimeService.unsubscribeAll()
      executionConsoleService.unsubscribeAll()
      executionStatsService.unsubscribeAll()
      executionCacheService.unsubscribeAll()
      executionReconfigurationService.unsubscribeAll()
    }

  }

}
