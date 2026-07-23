/**
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

import type { TexeraClient } from "../client";

export interface InputPortInfo {
  displayName?: string;
  disallowMultiLinks?: boolean;
  dependencies?: { id: number; internal: boolean }[];
}

export interface OutputPortInfo {
  displayName?: string;
}

export interface OperatorAdditionalMetadata {
  userFriendlyName: string;
  operatorGroupName: string;
  operatorDescription?: string;
  inputPorts: InputPortInfo[];
  outputPorts: OutputPortInfo[];
  dynamicInputPorts?: boolean;
  dynamicOutputPorts?: boolean;
  supportReconfiguration?: boolean;
  allowPortCustomization?: boolean;
}

export interface OperatorSchema {
  operatorType: string;
  jsonSchema: any;
  additionalMetadata: OperatorAdditionalMetadata;
  operatorVersion: string;
}

export interface GroupInfo {
  groupName: string;
  children?: GroupInfo[] | null;
}

export interface OperatorMetadata {
  operators: OperatorSchema[];
  groups: GroupInfo[];
}

/**
 * The operator catalogue: every operator type with the JSON Schema for its
 * properties and its port layout.
 *
 * `SystemMetadataResource` carries no `@RolesAllowed`, so this is readable
 * without a token — which lets a client validate operator properties before it
 * has authenticated.
 */
export async function fetchOperatorMetadata(client: TexeraClient): Promise<OperatorMetadata> {
  return client.request<OperatorMetadata>("dashboard", "/api/resources/operator-metadata", { anonymous: true });
}
