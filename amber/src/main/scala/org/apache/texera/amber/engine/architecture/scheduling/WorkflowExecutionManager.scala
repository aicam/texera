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

package org.apache.texera.amber.engine.architecture.scheduling

import com.twitter.util.Future
import com.typesafe.scalalogging.LazyLogging
import org.apache.texera.amber.core.workflow.{GlobalPortIdentity, PhysicalLink}
import org.apache.texera.amber.engine.architecture.scheduling.config.InputPortConfig
import org.apache.texera.amber.engine.architecture.common.{
  PekkoActorRefMappingService,
  PekkoActorService
}
import org.apache.texera.amber.engine.architecture.coordinator.CoordinatorConfig
import org.apache.texera.amber.engine.architecture.coordinator.ExecutionStateUpdate
import org.apache.texera.amber.engine.architecture.coordinator.execution.WorkflowExecution
import org.apache.texera.amber.engine.common.rpc.AsyncRPCClient

import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean
import scala.collection.mutable

class WorkflowExecutionManager(
    workflowExecution: WorkflowExecution,
    coordinatorConfig: CoordinatorConfig,
    asyncRPCClient: AsyncRPCClient
) extends LazyLogging {

  var schedule: Schedule = Schedule(Map.empty)

  // The regions of the schedule's current level.
  private var scheduleLevel: Set[RegionIdentity] = Set.empty

  /**
    * Operators added while the execution runs have their own schedule, which starts right away
    * and advances level by level independently of the main schedule and of other extensions.
    */
  private class Extension(val schedule: Schedule) extends Serializable {
    var level: Set[RegionIdentity] = Set.empty
  }
  private val extensions: mutable.ListBuffer[Extension] = mutable.ListBuffer()

  val liveInputs = new LiveInputTracker(workflowExecution)

  private val executedRegions: mutable.ListBuffer[Set[Region]] = mutable.ListBuffer()

  private val regionExecutionManagers: mutable.HashMap[RegionIdentity, RegionExecutionManager] =
    mutable.HashMap()
  private val completionNotified: AtomicBoolean = new AtomicBoolean(false)

  @transient var actorRefService: PekkoActorRefMappingService = _

  def setupActorRefService(actorRefService: PekkoActorRefMappingService): Unit = {
    this.actorRefService = actorRefService
  }

  /**
    * Loop bookkeeping addresses shipped to every worker at setup; semantics are
    * documented on `InitializeExecutorRequest.loopStartPortUris` (controlcommands.proto).
    * The value is the BASE URI of the materialized port the Loop Start's
    * input port READS FROM -- the upstream operator's output-port
    * materialization (`cfg.storagePairs.head._1` below), not a port of the
    * Loop Start itself. The Python worker derives the state URI (loop-back
    * write) and the result URI (the loop's input table, read at consume time)
    * from it.
    *
    * Derived from the final (resource-allocated) schedule, so the URIs are
    * exactly the ones `AssignPort` later ships to the Loop Start's input
    * readers. Kept a `def`: `schedule` is a `var` that is only populated after
    * `StartWorkflow`, and the first use is inside `coordinateRegionExecutors`.
    */
  private def loopStartPortUris: Map[String, String] =
    allScheduledRegions.flatMap { region =>
      region.getOperators.filter(_.isLoopStart).map { op =>
        require(
          op.inputPorts.size == 1,
          s"Loop Start ${op.id} must have exactly one input port, got ${op.inputPorts.size}"
        )
        val gpid = GlobalPortIdentity(op.id, op.inputPorts.keys.head, input = true)
        val cfg = region.resourceConfig.flatMap(_.portConfigs.get(gpid)) match {
          case Some(c: InputPortConfig) => c
          case other =>
            throw new IllegalStateException(
              s"Loop Start input port $gpid has no InputPortConfig (got $other) -- " +
                s"loop operators require a fully-materialized schedule"
            )
        }
        require(
          cfg.storagePairs.size == 1,
          s"Loop Start input port $gpid expected exactly one reader URI, " +
            s"got ${cfg.storagePairs.size}"
        )
        op.id.logicalOpId.id -> cfg.storagePairs.head._1.toString
      }
    }.toMap

  /**
    * Each invocation first syncs the internal statuses of each exisiting `RegionExecutionManager`, after which each
    * of the `RegionExecutionManager`s will launch the corresponding next phase of whenever needed until it is
    * in `Completed` status (phase).
    *
    * After the syncs, if there are no running region(s), it will start new regions (if available).
    *
    * Callers handling a worker-initiated request must not call this directly; they send themselves a
    * `CoordinatorInitiateAdvanceRegionExecutions` (see `PortCompletedHandler`) so the resulting
    * `EndWorker` cannot overtake the reply that request still owes.
    */
  /**
    * Every region of the main schedule and of the extensions, launched or not.
    */
  def allScheduledRegions: Seq[Region] =
    (schedule +: extensions.map(_.schedule).toSeq).flatMap(_.levelSets.values.flatten)

  /**
    * Adds the schedule of operators added to the running execution, and the stored output ports
    * (by URI) their inputs read. The next advance starts its first level.
    */
  def extend(addedSchedule: Schedule, readFrom: Map[URI, GlobalPortIdentity]): Unit = {
    readFrom.foreach { case (uri, producer) => liveInputs.attach(uri, producer) }
    extensions += new Extension(addedSchedule)
  }

  def hasPendingRegions: Boolean = schedule.hasNext || extensions.exists(_.schedule.hasNext)

  def advanceRegionExecutions(actorService: PekkoActorService): Future[Unit] = {
    val unfinishedRegionManagers =
      regionExecutionManagers.values.filter(!_.isCompleted).toSeq

    // Trigger sync for each unfinished region. The returned futures must not be dropped: a sync
    // may launch the next phase of a region, and a failure there (e.g., a worker failing to
    // initialize its executor) would otherwise be lost, leaving the execution RUNNING forever
    // with no error reported to the client.
    val syncFutures =
      unfinishedRegionManagers.map(_.syncStatusAndTransitionRegionExecutionPhase())

    Future
      .collect(syncFutures :+ advanceToNextRegions(actorService, unfinishedRegionManagers))
      .unit
  }

  private def advanceToNextRegions(
      actorService: PekkoActorService,
      unfinishedRegionManagers: Seq[RegionExecutionManager]
  ): Future[Unit] = {
    // Wait only for region termination futures (kill path), then re-run the advance loop.
    val terminationFutures = unfinishedRegionManagers.flatMap(_.getTerminationFutureOpt)
    if (terminationFutures.nonEmpty) {
      return Future
        .collect(terminationFutures)
        .unit
        .flatMap(_ => advanceRegionExecutions(actorService))
    }

    def levelDone(level: Set[RegionIdentity]): Boolean =
      level.forall(id => regionExecutionManagers.get(id).forall(_.isCompleted))

    // A schedule starts its next level once every region of its current level completed.
    val nextRegions = mutable.Set[Region]()
    if (levelDone(scheduleLevel) && schedule.hasNext) {
      val level = schedule.next()
      scheduleLevel = level.map(_.id)
      nextRegions ++= level
    }
    extensions.foreach { extension =>
      if (levelDone(extension.level) && extension.schedule.hasNext) {
        val level = extension.schedule.next()
        extension.level = level.map(_.id)
        nextRegions ++= level
      }
    }
    if (nextRegions.isEmpty) {
      if (
        !hasUnfinishedRegionManagers && !hasPendingRegions && workflowExecution.isCompleted &&
        completionNotified.compareAndSet(false, true)
      ) {
        asyncRPCClient.sendToClient(ExecutionStateUpdate(workflowExecution.getState))
      }
      return Future.Unit
    }

    executedRegions.append(nextRegions.toSet)
    val loopUris = loopStartPortUris
    Future
      .collect(
        nextRegions
          .map(region => {
            val isRestart = workflowExecution.hasRegionExecution(region.id)
            if (isRestart) {
              workflowExecution.restartRegionExecution(region)
            } else {
              workflowExecution.initRegionExecution(region)
            }
            regionExecutionManagers(region.id) = new RegionExecutionManager(
              region,
              isRestart,
              workflowExecution,
              asyncRPCClient,
              coordinatorConfig,
              actorService,
              actorRefService,
              loopStartPortUris = loopUris,
              liveInputs = Some(liveInputs)
            )
            regionExecutionManagers(region.id)
          })
          .map(_.syncStatusAndTransitionRegionExecutionPhase())
          .toSeq
      )
      .unit
  }

  def getRegionOfLink(link: PhysicalLink): Region = {
    getExecutingRegions.find(region => region.getLinks.contains(link)).get
  }

  def getRegionOfPortId(portId: GlobalPortIdentity): Option[Region] = {
    getExecutingRegions.find(region => region.getPorts.contains(portId))
  }

  def getExecutingRegions: Set[Region] = {
    executedRegions.flatten
      .filterNot(region => workflowExecution.getRegionExecution(region.id).isCompleted)
      .toSet
  }

  def hasUnfinishedRegionManagers: Boolean = {
    regionExecutionManagers.values.exists(!_.isCompleted)
  }

}
