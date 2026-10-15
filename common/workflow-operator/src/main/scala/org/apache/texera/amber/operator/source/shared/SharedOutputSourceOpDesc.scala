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

package org.apache.texera.amber.operator.source.shared

import com.fasterxml.jackson.annotation.{JsonProperty, JsonPropertyDescription}
import com.kjetland.jackson.jsonSchema.annotations.JsonSchemaTitle
import org.apache.texera.amber.core.executor.OpExecWithClassName
import org.apache.texera.amber.core.storage.SharedOutputs
import org.apache.texera.amber.core.tuple.Schema
import org.apache.texera.amber.core.virtualidentity.{ExecutionIdentity, WorkflowIdentity}
import org.apache.texera.amber.core.workflow.{OutputPort, PhysicalOp, SchemaPropagationFunc}
import org.apache.texera.amber.operator.LogicalOp
import org.apache.texera.amber.operator.metadata.{OperatorGroupConstants, OperatorInfo}
import org.apache.texera.amber.util.JSONUtils.objectMapper

/**
  * Reads an operator output another workflow published, in place: the rows of the newest
  * execution that produced it, and, while that execution runs, the rows it keeps adding.
  */
class SharedOutputSourceOpDesc extends LogicalOp {

  @JsonProperty(required = true)
  @JsonSchemaTitle("Shared Output")
  @JsonPropertyDescription("<owner email>/<name> of a published output")
  var sharedOutput: String = ""

  @JsonProperty(required = true, defaultValue = "true")
  @JsonSchemaTitle("Follow While It Runs")
  @JsonPropertyDescription("Keep reading the rows the producing workflow adds until its run finishes")
  var follow: Boolean = true

  override def getPhysicalOp(
      workflowId: WorkflowIdentity,
      executionId: ExecutionIdentity
  ): PhysicalOp =
    PhysicalOp
      .sourcePhysicalOp(
        workflowId,
        executionId,
        operatorIdentifier,
        OpExecWithClassName(
          "org.apache.texera.amber.operator.source.shared.SharedOutputSourceOpExec",
          objectMapper.writeValueAsString(this)
        )
      )
      .withInputPorts(operatorInfo.inputPorts)
      .withOutputPorts(operatorInfo.outputPorts)
      .withPropagateSchema(
        SchemaPropagationFunc(_ => Map(operatorInfo.outputPorts.head.id -> schema))
      )

  private def schema: Schema = {
    val shared = SharedOutputs
      .find(sharedOutput)
      .getOrElse(throw new IllegalArgumentException(s"No output is shared as '$sharedOutput'"))
    SharedOutputs
      .schemaOf(shared)
      .getOrElse(
        throw new IllegalStateException(
          s"'$sharedOutput' has no result yet: run the workflow that produces it first"
        )
      )
  }

  override def operatorInfo: OperatorInfo =
    OperatorInfo(
      userFriendlyName = "Shared Output",
      operatorDescription =
        "Read an operator output another workflow published, following it while that workflow runs",
      operatorGroupName = OperatorGroupConstants.INPUT_GROUP,
      inputPorts = List.empty,
      outputPorts = List(OutputPort())
    )
}
