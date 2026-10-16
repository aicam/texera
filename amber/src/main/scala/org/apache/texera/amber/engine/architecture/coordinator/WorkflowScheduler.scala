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

package org.apache.texera.amber.engine.architecture.coordinator

import org.apache.texera.amber.core.virtualidentity.ActorVirtualIdentity
import org.apache.texera.amber.core.workflow.{GlobalPortIdentity, PhysicalPlan, WorkflowContext}
import org.apache.texera.amber.engine.architecture.scheduling.config.OutputPortConfig
import org.apache.texera.amber.engine.architecture.scheduling.{
  CostBasedScheduleGenerator,
  Region,
  Schedule
}

import java.net.URI

class WorkflowScheduler(
    workflowContext: WorkflowContext,
    actorId: ActorVirtualIdentity
) extends java.io.Serializable {
  var physicalPlan: PhysicalPlan = _
  private var schedule: Schedule = _

  def getSchedule: Schedule = schedule

  /**
    * Update the schedule to be executed, based on the given physicalPlan.
    */
  def updateSchedule(physicalPlan: PhysicalPlan): Unit = {
    // generate a schedule using a region plan generator.
    val (generatedSchedule, updatedPhysicalPlan) =
      // CostBasedRegionPlanGenerator considers costs to try to find an optimal plan.
      new CostBasedScheduleGenerator(
        workflowContext,
        physicalPlan,
        actorId
      ).generate()
    this.schedule = generatedSchedule
    this.physicalPlan = updatedPhysicalPlan
  }

  /**
    * Plans the operators an edited plan adds to this running execution, on their own schedule.
    * Operators already running stay as they are: the edit may only add operators and links into
    * them. A link from a running operator becomes an input that reads that operator's
    * materialized output port, so that port must have been kept.
    *
    * @param newPlan            the whole edited plan, compiled for this execution
    * @param scheduledRegions   every region scheduled so far
    * @return the schedule of the added operators, and the stored output ports they read, by URI
    */
  def extend(
      newPlan: PhysicalPlan,
      outputPortsNeedingStorage: Set[GlobalPortIdentity],
      scheduledRegions: Iterable[Region]
  ): (Schedule, Map[URI, GlobalPortIdentity]) = {
    val runningIds = physicalPlan.operators.map(_.id)
    val removed = runningIds -- newPlan.operators.map(_.id)
    if (removed.nonEmpty) {
      throw new IllegalArgumentException(
        s"Operators cannot be removed while the workflow runs: ${removed.map(_.logicalOpId.id).mkString(", ")}"
      )
    }
    val addedOps = newPlan.operators.filterNot(op => runningIds.contains(op.id))
    val addedIds = addedOps.map(_.id)
    val addedLinks = newPlan.links -- physicalPlan.links
    addedLinks.find(link => !addedIds.contains(link.toOpId)).foreach { link =>
      throw new IllegalArgumentException(
        s"A running operator cannot get a new input: ${link.toOpId.logicalOpId.id}"
      )
    }
    if (addedOps.isEmpty) {
      throw new IllegalArgumentException("The edit adds no operators to the running workflow")
    }

    val storedOutputs: Map[GlobalPortIdentity, URI] = scheduledRegions
      .flatMap(_.resourceConfig)
      .flatMap(_.portConfigs.collect {
        case (portId, config: OutputPortConfig) => portId -> config.storageURIBase
      })
      .toMap
    val attachments = addedLinks.filter(link => runningIds.contains(link.fromOpId))
    def storageOf(producer: GlobalPortIdentity): URI =
      storedOutputs.getOrElse(
        producer,
        throw new IllegalArgumentException(
          s"The output of ${producer.opId.logicalOpId.id} is not kept, so nothing can be attached " +
            "to it while the workflow runs. Turn on live editing before running the workflow."
        )
      )
    val externalInputs = attachments
      .groupBy(link => GlobalPortIdentity(link.toOpId, link.toPortId, input = true))
      .map {
        case (input, links) =>
          input -> links.toList.map(link => storageOf(GlobalPortIdentity(link.fromOpId, link.fromPortId)))
      }

    workflowContext.workflowSettings =
      workflowContext.workflowSettings.copy(outputPortsNeedingStorage = outputPortsNeedingStorage)
    val (addedSchedule, _) = new CostBasedScheduleGenerator(
      workflowContext,
      PhysicalPlan(addedOps, addedLinks -- attachments),
      actorId,
      externalInputs,
      firstRegionId = scheduledRegions.map(_.id.id + 1).maxOption.getOrElse(0L)
    ).generate()
    physicalPlan = PhysicalPlan(physicalPlan.operators ++ addedOps, physicalPlan.links ++ addedLinks)
    val producers = attachments.map { link =>
      val producer = GlobalPortIdentity(link.fromOpId, link.fromPortId)
      storageOf(producer) -> producer
    }.toMap
    (addedSchedule, producers)
  }

  def getNextRegions: Set[Region] = if (!schedule.hasNext) Set() else schedule.next()

  def hasPendingRegions: Boolean = schedule != null && schedule.hasNext

}
