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

package org.apache.texera.amber.operator.activelearning

import com.fasterxml.jackson.annotation.{JsonProperty, JsonPropertyDescription}
import com.kjetland.jackson.jsonSchema.annotations.JsonSchemaTitle
import org.apache.texera.amber.core.tuple.{AttributeType, Schema}
import org.apache.texera.amber.core.workflow.OutputPort.OutputMode
import org.apache.texera.amber.core.workflow.{InputPort, OutputPort, PortIdentity}
import org.apache.texera.amber.operator.PythonOperatorDescriptor
import org.apache.texera.amber.operator.metadata.annotations.AutofillAttributeName
import org.apache.texera.amber.operator.metadata.{OperatorGroupConstants, OperatorInfo}
import org.apache.texera.amber.pybuilder.PyStringTypes.EncodableString
import org.apache.texera.amber.pybuilder.PythonTemplateBuilder.PythonTemplateBuilderStringContext

/**
  * A line chart that redraws on every row, unlike charts drawn once the input ends, so a training
  * run is watched while it goes.
  */
class LearningCurveOpDesc extends PythonOperatorDescriptor {
  @JsonProperty(required = true, defaultValue = "labeled_cases")
  @JsonSchemaTitle("X")
  @JsonPropertyDescription("Column on the horizontal axis")
  @AutofillAttributeName
  var x: EncodableString = "labeled_cases"

  @JsonProperty(required = true, defaultValue = "newest_dice, averaged_dice")
  @JsonSchemaTitle("Lines")
  @JsonPropertyDescription("Comma-separated columns, one line each")
  var lines: EncodableString = "newest_dice, averaged_dice"

  @JsonProperty(required = true, defaultValue = "Validation Dice")
  @JsonSchemaTitle("Title")
  var title: EncodableString = "Validation Dice"

  override def generatePythonCode(): String =
    pyb"""from pytexera import *
       |from pytexera.active_learning.charts import learning_curve_html
       |
       |class LearningCurveOperator(UDFOperatorV2):
       |    def open(self) -> None:
       |        self.rows = []
       |        self.lines = [column.strip() for column in $lines.split(",") if column.strip()]
       |
       |    @overrides
       |    def process_tuple(self, tuple_: Tuple, port: int) -> Iterator[Optional[TupleLike]]:
       |        self.rows.append(tuple_.as_dict())
       |        yield {"html-content": learning_curve_html(self.rows, $x, self.lines, $title)}""".encode

  override def operatorInfo: OperatorInfo =
    OperatorInfo(
      "Learning Curve",
      "A line chart that redraws with every new row, to watch a run while it trains",
      OperatorGroupConstants.ACTIVE_LEARNING_GROUP,
      inputPorts = List(InputPort()),
      outputPorts = List(OutputPort(mode = OutputMode.SINGLE_SNAPSHOT))
    )

  override def getOutputSchemas(inputSchemas: Map[PortIdentity, Schema]): Map[PortIdentity, Schema] =
    Map(operatorInfo.outputPorts.head.id -> Schema().add("html-content", AttributeType.STRING))
}
