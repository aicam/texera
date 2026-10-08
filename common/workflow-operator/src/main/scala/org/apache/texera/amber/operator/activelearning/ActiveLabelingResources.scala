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
import org.apache.texera.amber.pybuilder.PyStringTypes.EncodableString

/**
  * The versioned resources an active-labeling run shares. Training and labeling
  * never exchange tuples; they meet only through new versions of these.
  */
trait ActiveLabelingResources {
  @JsonProperty(required = true, defaultValue = "brain-masks")
  @JsonSchemaTitle("Labels Dataset")
  @JsonPropertyDescription("Dataset that receives every submitted label as a new version")
  var labelsDataset: EncodableString = "brain-masks"

  @JsonProperty(required = true, defaultValue = "brain-unet")
  @JsonSchemaTitle("Model")
  @JsonPropertyDescription("Model whose versions are the snapshots the trainer publishes")
  var modelName: EncodableString = "brain-unet"
}
