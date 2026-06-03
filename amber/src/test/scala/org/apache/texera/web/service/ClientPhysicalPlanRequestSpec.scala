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

import org.apache.texera.amber.compiler.model.{LogicalLink, LogicalPlanPojo}
import org.apache.texera.amber.core.virtualidentity.OperatorIdentity
import org.apache.texera.amber.core.workflow.{PhysicalPlan, PortIdentity, WorkflowContext, WorkflowSettings}
import org.apache.texera.amber.operator.TestOperators
import org.apache.texera.amber.operator.aggregate.AggregationFunction
import org.apache.texera.amber.util.JSONUtils.objectMapper
import org.apache.texera.web.model.websocket.request.{TexeraWebSocketRequest, WorkflowExecuteRequest}
import org.apache.texera.workflow.WorkflowCompiler
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

/**
  * The new architecture has the client compile the workflow and ship a ready-to-run
  * [[PhysicalPlan]] to the ComputingUnitMaster inside a [[WorkflowExecuteRequest]]. These tests pin
  * the two things that makes possible: the request (with its PhysicalPlan) survives the exact
  * polymorphic JSON round-trip the CU's websocket parser performs, and the CU re-derives the
  * result-storage ports from the plan + the to-view operators.
  */
class ClientPhysicalPlanRequestSpec extends AnyFlatSpec with Matchers {

  /**
    * Compile CSV scan -> group-by aggregate into a physical plan; return it, the (non-terminal) CSV
    * id, and the (terminal) aggregate id.
    */
  private def compiledPlanAndViewOp(): (PhysicalPlan, String, String) = {
    val csv = TestOperators.smallCsvScanOpDesc()
    val agg =
      TestOperators.aggregateAndGroupByDesc("Units Sold", AggregationFunction.SUM, List("Country"))
    val plan = new WorkflowCompiler(new WorkflowContext())
      .compile(
        LogicalPlanPojo(
          List(csv, agg),
          List(
            LogicalLink(csv.operatorIdentifier, PortIdentity(), agg.operatorIdentifier, PortIdentity())
          ),
          List.empty,
          List.empty
        )
      )
      .physicalPlan
    (plan, csv.operatorIdentifier.id, agg.operatorIdentifier.id)
  }

  private def buildRequest(
      plan: PhysicalPlan,
      viewOps: List[String],
      userJwtToken: Option[String] = None
  ): WorkflowExecuteRequest =
    WorkflowExecuteRequest(
      executionName = "test",
      engineVersion = "1.0",
      physicalPlan = plan,
      opsToViewResult = viewOps,
      replayFromExecution = None,
      workflowSettings = WorkflowSettings(dataTransferBatchSize = 400),
      emailNotificationEnabled = false,
      computingUnitId = 0,
      userJwtToken = userJwtToken
    )

  "A WorkflowExecuteRequest carrying a PhysicalPlan" should
    "survive the websocket polymorphic JSON round-trip with the plan intact" in {
    val (plan, _, aggId) = compiledPlanAndViewOp()
    val request: TexeraWebSocketRequest = buildRequest(plan, List(aggId))

    // Mirror WorkflowWebsocketResource: serialize via the polymorphic base ("type" discriminator),
    // then read it back as the base and dispatch on the concrete request type.
    val json = objectMapper.writeValueAsString(request)
    json should include(""""type":"WorkflowExecuteRequest"""")
    val back = objectMapper
      .readValue(json, classOf[TexeraWebSocketRequest])
      .asInstanceOf[WorkflowExecuteRequest]

    back.opsToViewResult shouldBe List(aggId)
    back.physicalPlan.operators.map(_.id) shouldBe plan.operators.map(_.id)
    back.physicalPlan.links shouldBe plan.links
    // The runtime-critical executor descriptor of every operator survives.
    plan.operators.foreach { op =>
      back.physicalPlan.getOperator(op.id).opExecInitInfo shouldBe op.opExecInitInfo
    }
  }

  it should "carry the issuing user's JWT through the round-trip (forwarded on the CU's outbound calls)" in {
    val (plan, _, aggId) = compiledPlanAndViewOp()
    val request: TexeraWebSocketRequest = buildRequest(plan, List(aggId), Some("jwt-abc-123"))

    val json = objectMapper.writeValueAsString(request)
    val back = objectMapper
      .readValue(json, classOf[TexeraWebSocketRequest])
      .asInstanceOf[WorkflowExecuteRequest]
    back.userJwtToken shouldBe Some("jwt-abc-123")

    // Absent token stays absent (the CU then falls back to its environment token, if any).
    val noToken = objectMapper
      .readValue(
        objectMapper.writeValueAsString(buildRequest(plan, List(aggId)): TexeraWebSocketRequest),
        classOf[TexeraWebSocketRequest]
      )
      .asInstanceOf[WorkflowExecuteRequest]
    noToken.userJwtToken shouldBe None
  }

  "outputPortsForViewResult" should "always include terminal operators' non-internal output ports" in {
    // Plan is csv -> aggregate, so the aggregate is the terminal (end-of-path) operator.
    val (plan, _, aggId) = compiledPlanAndViewOp()

    // Even with NO explicit to-view operators, the terminal operator's result is materialized
    // (this is the fix: terminal/end-of-path results must be viewable without an eye-icon mark).
    val terminalPorts = WorkflowExecutionService.outputPortsForViewResult(plan, List.empty)
    terminalPorts should not be empty
    terminalPorts.foreach(_.opId.logicalOpId shouldBe OperatorIdentity(aggId))
    terminalPorts.foreach(_.portId.internal shouldBe false)

    // An unknown to-view id adds nothing beyond the terminal ports.
    WorkflowExecutionService.outputPortsForViewResult(plan, List("does-not-exist")) shouldBe terminalPorts
    // Requesting the terminal op explicitly yields the same set (it's terminal anyway).
    WorkflowExecutionService.outputPortsForViewResult(plan, List(aggId)) shouldBe terminalPorts
  }

  it should "union to-view (non-terminal) operators with the terminal ports" in {
    val (plan, csvId, aggId) = compiledPlanAndViewOp()

    // The CSV scan is upstream (non-terminal); explicitly viewing it adds its ports on top of the
    // terminal aggregate's ports.
    val ports = WorkflowExecutionService.outputPortsForViewResult(plan, List(csvId))
    val viewedLogicalOps = ports.map(_.opId.logicalOpId)
    viewedLogicalOps should contain(OperatorIdentity(csvId))
    viewedLogicalOps should contain(OperatorIdentity(aggId))
    ports.foreach(_.portId.internal shouldBe false)
  }
}
