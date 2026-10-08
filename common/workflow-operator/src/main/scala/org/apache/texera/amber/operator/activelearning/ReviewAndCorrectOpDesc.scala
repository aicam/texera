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
import com.kjetland.jackson.jsonSchema.annotations.{JsonSchemaInject, JsonSchemaTitle}
import org.apache.texera.amber.core.tuple.{AttributeType, Schema}
import org.apache.texera.amber.core.workflow.{InputPort, OutputPort, PortIdentity}
import org.apache.texera.amber.operator.PythonOperatorDescriptor
import org.apache.texera.amber.operator.metadata.{OperatorGroupConstants, OperatorInfo}
import org.apache.texera.amber.pybuilder.PyStringTypes.EncodableString
import org.apache.texera.amber.pybuilder.PythonTemplateBuilder.PythonTemplateBuilderStringContext

/**
  * Where a person labels the suggested cases, from the Review tab of the result
  * panel. Each label becomes its own version of the labels dataset, recording
  * which model version suggested it and how much the person changed it.
  */
class ReviewAndCorrectOpDesc extends PythonOperatorDescriptor with ActiveLabelingResources {
  @JsonProperty(required = true, defaultValue = "brain-mri")
  @JsonSchemaTitle("Scans Dataset")
  @JsonPropertyDescription("Dataset with cases.csv and scans/<case>.png")
  var scansDataset: EncodableString = "brain-mri"

  @JsonProperty(required = true, defaultValue = "brain-review-queue")
  @JsonSchemaTitle("Review Queue Dataset")
  var queueDataset: EncodableString = "brain-review-queue"

  @JsonProperty(required = true, defaultValue = "false")
  @JsonSchemaTitle("Simulated Annotator")
  @JsonPropertyDescription("Label the cases automatically from the expert masks instead of waiting for a person")
  var simulated: Boolean = false

  @JsonProperty(required = true, defaultValue = "brain-mri-gt")
  @JsonSchemaTitle("Expert Masks Dataset")
  @JsonPropertyDescription("Read only by the simulated annotator")
  var truthDataset: EncodableString = "brain-mri-gt"

  @JsonProperty(required = true)
  @JsonSchemaInject(json = """{ "default": 0.1 }""")
  @JsonSchemaTitle("Anchoring")
  @JsonPropertyDescription("Share of the suggestion's wrong pixels the simulated annotator leaves in place")
  var anchoring: Double = 0.1

  @JsonProperty(required = true)
  @JsonSchemaInject(json = """{ "default": 30 }""")
  @JsonSchemaTitle("Seconds per Case")
  @JsonPropertyDescription("Time the simulated annotator spends on a case that needs a full redraw")
  var secondsPerCase: Double = 30

  @JsonProperty(required = true)
  @JsonSchemaInject(json = """{ "default": 0.1 }""")
  @JsonSchemaTitle("Time Scale")
  @JsonPropertyDescription("Multiplies the simulated annotator's waiting time; 1 is real time")
  var timeScale: Double = 0.1

  override def generatePythonCode(): String = {
    val annotator = if (simulated) "simulated" else "person"
    pyb"""from pytexera import *
       |from pytexera.active_learning.loops import review
       |
       |class ReviewAndCorrectOperator(UDFOperatorV2):
       |    @overrides
       |    def process_tuple(self, tuple_: Tuple, port: int) -> Iterator[Optional[TupleLike]]:
       |        yield from review(tuple_.as_dict(), $labelsDataset, $queueDataset, $truthDataset,
       |                          $modelName, '$annotator', $anchoring, $secondsPerCase, $timeScale)""".encode
  }

  override def operatorInfo: OperatorInfo =
    OperatorInfo(
      "Review & Correct",
      "A person corrects each suggested case in the Review tab; every label is committed with the model version that suggested it",
      OperatorGroupConstants.ACTIVE_LEARNING_GROUP,
      inputPorts = List(InputPort()),
      outputPorts = List(OutputPort())
    )

  override def getOutputSchemas(inputSchemas: Map[PortIdentity, Schema]): Map[PortIdentity, Schema] =
    Map(
      operatorInfo.outputPorts.head.id -> Schema()
        .add("case", AttributeType.STRING)
        .add("round", AttributeType.INTEGER)
        .add("suggested_by", AttributeType.STRING)
        .add("suggested_by_id", AttributeType.INTEGER)
        .add("newest_model_at_submit", AttributeType.STRING)
        .add("newest_model_id_at_submit", AttributeType.INTEGER)
        .add("versions_behind", AttributeType.INTEGER)
        .add("uncertainty", AttributeType.DOUBLE)
        .add("dice_suggested_vs_final", AttributeType.DOUBLE)
        .add("pixels_changed", AttributeType.INTEGER)
        .add("seconds", AttributeType.DOUBLE)
        .add("annotator", AttributeType.STRING)
        .add("submitted_at", AttributeType.STRING)
        .add("labels_version", AttributeType.STRING)
    )
}
