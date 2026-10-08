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
  * Trains on the labels dataset's newest version every epoch, scoring each epoch
  * on the cohort's validation cases, and publishes a model version whenever the
  * score improves. One row per epoch tells downstream operators a model may be new.
  */
class TrainSegmenterOpDesc extends PythonOperatorDescriptor with ActiveLabelingResources {
  @JsonProperty(required = true, defaultValue = "brain-mri")
  @JsonSchemaTitle("Scans Dataset")
  @JsonPropertyDescription("Dataset with scans/<case>.png")
  var scansDataset: EncodableString = "brain-mri"

  @JsonProperty(required = true, defaultValue = "brain-mri-gt")
  @JsonSchemaTitle("Validation Masks Dataset")
  @JsonPropertyDescription("Expert masks; only the validation cases are read")
  var truthDataset: EncodableString = "brain-mri-gt"

  @JsonProperty(required = true, defaultValue = "300")
  @JsonSchemaTitle("Epochs")
  var maxEpochs: Int = 300

  @JsonProperty(required = true, defaultValue = "16")
  @JsonSchemaTitle("Batch Size")
  var batchSize: Int = 16

  @JsonProperty(required = true, defaultValue = "200")
  @JsonSchemaTitle("Validation Cases")
  var validationSize: Int = 200

  @JsonProperty(required = true, defaultValue = "true")
  @JsonSchemaTitle("Resume From Newest Model")
  @JsonPropertyDescription("Continue from the newest model version instead of training from scratch")
  var warmStart: Boolean = true

  override def generatePythonCode(): String = {
    val resume = if (warmStart) "True" else "False"
    pyb"""from pytexera import *
       |from pytexera.active_learning.loops import train
       |
       |class TrainSegmenterOperator(UDFOperatorV2):
       |    def open(self) -> None:
       |        self.cohort = []
       |
       |    @overrides
       |    def process_tuple(self, tuple_: Tuple, port: int) -> Iterator[Optional[TupleLike]]:
       |        self.cohort.append(tuple_.as_dict())
       |        yield None
       |
       |    @overrides
       |    def on_finish(self, port: int) -> Iterator[Optional[TupleLike]]:
       |        yield from train(self.cohort, $scansDataset, $labelsDataset, $truthDataset, $modelName,
       |                         $maxEpochs, $batchSize, $validationSize, $resume)""".encode
  }

  override def operatorInfo: OperatorInfo =
    OperatorInfo(
      "Train Segmenter",
      "Trains a U-Net on the newest labels every epoch and publishes a model version whenever validation Dice improves",
      OperatorGroupConstants.ACTIVE_LEARNING_GROUP,
      inputPorts = List(InputPort(displayName = "cohort")),
      outputPorts = List(OutputPort())
    )

  override def getOutputSchemas(inputSchemas: Map[PortIdentity, Schema]): Map[PortIdentity, Schema] =
    Map(
      operatorInfo.outputPorts.head.id -> Schema()
        .add("epoch", AttributeType.INTEGER)
        .add("labels_version", AttributeType.STRING)
        .add("labeled_cases", AttributeType.INTEGER)
        .add("train_loss", AttributeType.DOUBLE)
        .add("validation_dice", AttributeType.DOUBLE)
        .add("published_model_version", AttributeType.STRING)
        .add("time", AttributeType.STRING)
    )
}
