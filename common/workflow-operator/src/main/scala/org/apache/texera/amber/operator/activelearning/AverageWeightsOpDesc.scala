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
import org.apache.texera.amber.core.workflow.{InputPort, OutputPort, PortIdentity}
import org.apache.texera.amber.operator.PythonOperatorDescriptor
import org.apache.texera.amber.operator.metadata.{OperatorGroupConstants, OperatorInfo}
import org.apache.texera.amber.pybuilder.PyStringTypes.EncodableString
import org.apache.texera.amber.pybuilder.PythonTemplateBuilder.PythonTemplateBuilderStringContext

/**
  * Each row from the trainer is a chance it published a version. When it did, publishes the
  * average of the trainer's last few versions as a version of another model, so Suggest Cases
  * can serve the average instead of the newest weights, and scores both on the validation cases.
  */
class AverageWeightsOpDesc extends PythonOperatorDescriptor with ActiveLabelingResources {
  @JsonProperty(required = true, defaultValue = "brain-mri")
  @JsonSchemaTitle("Scans Dataset")
  @JsonPropertyDescription("Dataset with cases.csv and scans/<case>.png")
  var scansDataset: EncodableString = "brain-mri"

  @JsonProperty(required = true, defaultValue = "brain-mri-gt")
  @JsonSchemaTitle("Validation Masks Dataset")
  @JsonPropertyDescription("Expert masks; only the validation cases are read")
  var truthDataset: EncodableString = "brain-mri-gt"

  @JsonProperty(required = true, defaultValue = "brain-unet-avg")
  @JsonSchemaTitle("Averaged Model")
  @JsonPropertyDescription("Model whose versions are the averages; point Suggest Cases at it to serve them")
  var averagedModel: EncodableString = "brain-unet-avg"

  @JsonProperty(required = true, defaultValue = "3")
  @JsonSchemaTitle("Versions Averaged")
  @JsonPropertyDescription("How many of the trainer's newest versions each average takes")
  var keep: Int = 3

  @JsonProperty(required = true, defaultValue = "200")
  @JsonSchemaTitle("Validation Cases")
  var validationSize: Int = 200

  override def generatePythonCode(): String =
    pyb"""from pytexera import *
       |from pytexera.active_learning.averaging import WeightAverager
       |
       |class AverageWeightsOperator(UDFOperatorV2):
       |    def open(self) -> None:
       |        self.averager = WeightAverager($scansDataset, $labelsDataset, $truthDataset, $modelName,
       |                                       $averagedModel, $keep, $validationSize)
       |
       |    @overrides
       |    def process_tuple(self, tuple_: Tuple, port: int) -> Iterator[Optional[TupleLike]]:
       |        if tuple_["published_model_version"]:
       |            yield from self.averager.update()""".encode

  override def operatorInfo: OperatorInfo =
    OperatorInfo(
      "Average Weights",
      "Publishes the average of the trainer's newest model versions and scores it against the newest version",
      OperatorGroupConstants.ACTIVE_LEARNING_GROUP,
      inputPorts = List(InputPort(displayName = "model updates")),
      outputPorts = List(OutputPort())
    )

  override def getOutputSchemas(inputSchemas: Map[PortIdentity, Schema]): Map[PortIdentity, Schema] =
    Map(
      operatorInfo.outputPorts.head.id -> Schema()
        .add("labeled_cases", AttributeType.INTEGER)
        .add("newest_version", AttributeType.STRING)
        .add("averaged_versions", AttributeType.INTEGER)
        .add("newest_dice", AttributeType.DOUBLE)
        .add("averaged_dice", AttributeType.DOUBLE)
        .add("gain", AttributeType.DOUBLE)
        .add("published_model_version", AttributeType.STRING)
        .add("time", AttributeType.STRING)
    )
}
