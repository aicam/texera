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

import org.apache.texera.amber.core.workflow.{
  GlobalPortIdentity,
  PortIdentity,
  WorkflowContext,
  WorkflowSettings
}
import org.apache.texera.amber.engine.common.virtualidentity.util.COORDINATOR
import org.apache.texera.amber.engine.e2e.TestUtils.buildWorkflow
import org.apache.texera.amber.operator.TestOperators
import org.apache.texera.common.compiler.model.LogicalLink
import org.scalatest.flatspec.AnyFlatSpec

class WorkflowSchedulerSpec extends AnyFlatSpec {

  private def buildHeaderlessCsvKeywordWorkflow() = {
    val csvOpDesc = TestOperators.headerlessSmallCsvScanOpDesc()
    val keywordOpDesc = TestOperators.keywordSearchOpDesc("column-1", "Asia")
    buildWorkflow(
      List(csvOpDesc, keywordOpDesc),
      List(
        LogicalLink(
          csvOpDesc.operatorIdentifier,
          PortIdentity(0),
          keywordOpDesc.operatorIdentifier,
          PortIdentity(0)
        )
      ),
      new WorkflowContext()
    )
  }

  "WorkflowScheduler.updateSchedule" should "populate the schedule and physicalPlan fields" in {
    val workflow = buildHeaderlessCsvKeywordWorkflow()
    val scheduler = new WorkflowScheduler(workflow.context, COORDINATOR)

    assert(scheduler.getSchedule == null)
    assert(scheduler.physicalPlan == null)

    scheduler.updateSchedule(workflow.physicalPlan)

    assert(scheduler.getSchedule != null)
    assert(scheduler.physicalPlan != null)
    assert(scheduler.getSchedule.getRegions.nonEmpty)
  }

  it should "include every workflow operator in some region of the produced schedule" in {
    val workflow = buildHeaderlessCsvKeywordWorkflow()
    val scheduler = new WorkflowScheduler(workflow.context, COORDINATOR)
    scheduler.updateSchedule(workflow.physicalPlan)

    val operatorsInSchedule = scheduler.getSchedule.getRegions
      .flatMap(_.getOperators.map(_.id.logicalOpId))
      .toSet
    val operatorsInPlan = scheduler.physicalPlan.operators.map(_.id.logicalOpId)

    assert(operatorsInPlan.subsetOf(operatorsInSchedule))
  }

  "WorkflowScheduler.getNextRegions" should "exhaust the schedule and then return an empty set" in {
    val workflow = buildHeaderlessCsvKeywordWorkflow()
    val scheduler = new WorkflowScheduler(workflow.context, COORDINATOR)
    scheduler.updateSchedule(workflow.physicalPlan)

    val pulledLevels = Iterator
      .continually(scheduler.getNextRegions)
      .takeWhile(_.nonEmpty)
      .toList

    assert(pulledLevels.nonEmpty)
    assert(scheduler.getNextRegions.isEmpty)
  }

  it should "yield region sets that together cover every region in the schedule" in {
    val workflow = buildHeaderlessCsvKeywordWorkflow()
    val scheduler = new WorkflowScheduler(workflow.context, COORDINATOR)
    scheduler.updateSchedule(workflow.physicalPlan)

    val expectedRegions = scheduler.getSchedule.getRegions.toSet
    val pulledRegions = Iterator
      .continually(scheduler.getNextRegions)
      .takeWhile(_.nonEmpty)
      .flatten
      .toSet

    assert(pulledRegions == expectedRegions)
  }

  // csv -> keyword, and the same plan with a second keyword search attached to the csv scan.
  private def runningAndEditedPlans(liveEditing: Boolean) = {
    val csvOpDesc = TestOperators.headerlessSmallCsvScanOpDesc()
    val keywordOpDesc = TestOperators.keywordSearchOpDesc("column-1", "Asia")
    val addedOpDesc = TestOperators.keywordSearchOpDesc("column-1", "Europe")
    val toKeyword = LogicalLink(
      csvOpDesc.operatorIdentifier,
      PortIdentity(0),
      keywordOpDesc.operatorIdentifier,
      PortIdentity(0)
    )
    val toAdded = LogicalLink(
      csvOpDesc.operatorIdentifier,
      PortIdentity(0),
      addedOpDesc.operatorIdentifier,
      PortIdentity(0)
    )
    val context = new WorkflowContext()
    context.workflowSettings = WorkflowSettings(liveEditing = liveEditing)
    val running = buildWorkflow(List(csvOpDesc, keywordOpDesc), List(toKeyword), context)
    val editedContext = new WorkflowContext()
    editedContext.workflowSettings = WorkflowSettings(liveEditing = liveEditing)
    val edited = buildWorkflow(
      List(csvOpDesc, keywordOpDesc, addedOpDesc),
      List(toKeyword, toAdded),
      editedContext
    )
    (running, edited, addedOpDesc)
  }

  "WorkflowScheduler.extend" should "schedule only the added operator, reading the running operator's kept output" in {
    val (running, edited, added) = runningAndEditedPlans(liveEditing = true)
    val scheduler = new WorkflowScheduler(running.context, COORDINATOR)
    scheduler.updateSchedule(running.physicalPlan)
    val runningRegions = scheduler.getSchedule.getRegions

    val (addedSchedule, readFrom) = scheduler.extend(
      edited.physicalPlan,
      edited.context.workflowSettings.outputPortsNeedingStorage,
      runningRegions
    )

    val addedRegions = addedSchedule.getRegions
    assert(addedRegions.flatMap(_.getOperators.map(_.id.logicalOpId)).toSet == Set(added.operatorIdentifier))
    assert(addedRegions.map(_.id).toSet.intersect(runningRegions.map(_.id).toSet).isEmpty)
    val csvPort = running.physicalPlan.operators
      .find(_.isSourceOperator)
      .map(op => GlobalPortIdentity(op.id, PortIdentity(0)))
      .get
    assert(readFrom.values.toSet == Set(csvPort))
    val inputUris = addedRegions.flatMap(_.resourceConfig.get.portConfigs.collect {
      case (port, config) if port.input => config.storageURIs
    }).flatten
    assert(inputUris == readFrom.keys.toList)
    assert(scheduler.physicalPlan.operators.size == edited.physicalPlan.operators.size)
  }

  it should "refuse to attach to an output that is not kept" in {
    val (running, edited, _) = runningAndEditedPlans(liveEditing = false)
    val scheduler = new WorkflowScheduler(running.context, COORDINATOR)
    scheduler.updateSchedule(running.physicalPlan)

    val error = intercept[IllegalArgumentException] {
      scheduler.extend(edited.physicalPlan, Set.empty, scheduler.getSchedule.getRegions)
    }
    assert(error.getMessage.contains("not kept"))
  }

  it should "refuse an edit that removes a running operator" in {
    val (running, edited, _) = runningAndEditedPlans(liveEditing = true)
    val scheduler = new WorkflowScheduler(edited.context, COORDINATOR)
    scheduler.updateSchedule(edited.physicalPlan)

    val error = intercept[IllegalArgumentException] {
      scheduler.extend(running.physicalPlan, Set.empty, scheduler.getSchedule.getRegions)
    }
    assert(error.getMessage.contains("cannot be removed"))
  }
}
