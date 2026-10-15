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
  * Keeps the review queue topped up. The first input is the candidate pool; each
  * row on the second input is the trainer finishing an epoch, the moment to check
  * whether the queue needs a new round from the newest model version.
  *
  * The two inputs carry no port dependency on purpose: a dependency would make
  * the trainer's edge blocking, and training and labeling must run side by side.
  */
class SuggestCasesOpDesc extends PythonOperatorDescriptor with ActiveLabelingResources {
  @JsonProperty(required = true, defaultValue = "brain-mri")
  @JsonSchemaTitle("Scans Dataset")
  @JsonPropertyDescription("Dataset with scans/<case>.png")
  var scansDataset: EncodableString = "brain-mri"

  @JsonProperty(required = true, defaultValue = "brain-review-queue")
  @JsonSchemaTitle("Review Queue Dataset")
  @JsonPropertyDescription("Each round of suggestions is published here as a new version")
  var queueDataset: EncodableString = "brain-review-queue"

  @JsonProperty(required = true, defaultValue = "uncertainty")
  @JsonSchemaTitle("Ranking")
  @JsonSchemaInject(json = """{ "enum": ["uncertainty", "random"] }""")
  @JsonPropertyDescription("Suggest the cases the model is least sure about, or a random sample as a baseline")
  var ranking: EncodableString = "uncertainty"

  @JsonProperty(required = true, defaultValue = "8")
  @JsonSchemaTitle("Cases per Round")
  var batchSize: Int = 8

  @JsonProperty(required = true, defaultValue = "6")
  @JsonSchemaTitle("Refill Below")
  @JsonPropertyDescription(
    "Start the next round when fewer than this many suggested cases are still unlabeled, so a reviewer never waits"
  )
  var refillBelow: Int = 6

  @JsonProperty(required = true, defaultValue = "600")
  @JsonSchemaTitle("Unlabeled Cases Scored per Round")
  var poolSample: Int = 600

  @JsonProperty(required = true, defaultValue = "200")
  @JsonSchemaTitle("Rounds")
  var maxRounds: Int = 200

  override def generatePythonCode(): String =
    pyb"""from pytexera import *
       |from pytexera.active_learning.loops import Suggester
       |
       |class SuggestCasesOperator(UDFOperatorV2):
       |    def open(self) -> None:
       |        self.suggester = Suggester($scansDataset, $labelsDataset, $queueDataset, $modelName,
       |                                   $batchSize, $refillBelow, $poolSample, $maxRounds, $ranking)
       |
       |    def on_reconfigure(self) -> None:
       |        self.suggester.reconfigure($modelName, $batchSize, $refillBelow, $poolSample, $maxRounds, $ranking)
       |
       |    @overrides
       |    def process_tuple(self, tuple_: Tuple, port: int) -> Iterator[Optional[TupleLike]]:
       |        if port == 0:
       |            self.suggester.add_to_pool(str(tuple_["case"]))
       |            yield None
       |        else:
       |            yield from self.suggester.tick()
       |
       |    @overrides
       |    def on_finish(self, port: int) -> Iterator[Optional[TupleLike]]:
       |        if port == 0:
       |            yield from self.suggester.tick()
       |        else:
       |            yield from self.suggester.drain()""".encode

  override def operatorInfo: OperatorInfo =
    OperatorInfo(
      "Suggest Cases",
      "Scores the unlabeled pool with the newest model version and publishes the cases to review next",
      OperatorGroupConstants.ACTIVE_LEARNING_GROUP,
      inputPorts = List(
        InputPort(PortIdentity(), displayName = "pool"),
        InputPort(PortIdentity(1), displayName = "model updates")
      ),
      outputPorts = List(OutputPort()),
      // Its model, ranking and round sizes can change while people label; the pool and the
      // open suggestions carry over.
      supportReconfiguration = true
    )

  override def getOutputSchemas(inputSchemas: Map[PortIdentity, Schema]): Map[PortIdentity, Schema] =
    Map(
      operatorInfo.outputPorts.head.id -> Schema()
        .add("round", AttributeType.INTEGER)
        .add("case", AttributeType.STRING)
        .add("uncertainty", AttributeType.DOUBLE)
        .add("suggested_by", AttributeType.STRING)
        .add("suggested_by_id", AttributeType.INTEGER)
        .add("queue_version", AttributeType.STRING)
    )
}
