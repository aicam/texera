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

import type { WorkflowContent } from "@texera/sdk";

/**
 * A two-operator catalogue shaped like the real `/api/resources/operator-metadata`
 * payload: one source with a required property, one transform with one input.
 * Enough to exercise schema validation, port wiring and error paths.
 */
export const OPERATOR_METADATA = {
  operators: [
    {
      operatorType: "CSVFileScan",
      operatorVersion: "1.0",
      jsonSchema: {
        type: "object",
        required: ["fileName"],
        properties: {
          fileName: { type: "string", title: "File" },
          customDelimiter: { type: "string", default: "," },
          hasHeader: { type: "boolean", default: true },
        },
      },
      additionalMetadata: {
        userFriendlyName: "CSV File Scan",
        operatorGroupName: "Source",
        operatorDescription: "Read a CSV file from a dataset",
        inputPorts: [],
        outputPorts: [{ displayName: "output" }],
      },
    },
    {
      operatorType: "Filter",
      operatorVersion: "1.0",
      jsonSchema: {
        type: "object",
        required: ["predicate"],
        properties: {
          predicate: { type: "string", title: "Predicate" },
        },
      },
      additionalMetadata: {
        userFriendlyName: "Filter",
        operatorGroupName: "Transform",
        operatorDescription: "Keep rows matching a predicate",
        inputPorts: [{ displayName: "input", disallowMultiLinks: true }],
        outputPorts: [{ displayName: "output" }],
      },
    },
    {
      operatorType: "Join",
      operatorVersion: "1.0",
      jsonSchema: {
        type: "object",
        required: [],
        properties: { joinKey: { type: "string" } },
      },
      additionalMetadata: {
        userFriendlyName: "Join",
        operatorGroupName: "Transform",
        operatorDescription: "Join two inputs",
        inputPorts: [{ displayName: "left" }, { displayName: "right" }],
        outputPorts: [{ displayName: "output" }],
      },
    },
  ],
  groups: [{ groupName: "Source" }, { groupName: "Transform" }],
};

export const EMPTY_CONTENT: WorkflowContent = {
  operators: [],
  operatorPositions: {},
  links: [],
  commentBoxes: [],
  settings: { dataTransferBatchSize: 400 },
};

/** A stored workflow: one CSV scan feeding one filter. */
export function twoOperatorContent(): WorkflowContent {
  return {
    operators: [
      {
        operatorID: "scan1",
        operatorType: "CSVFileScan",
        operatorVersion: "1.0",
        operatorProperties: { fileName: "/alice@example.org/covid/v1/cases.csv", hasHeader: true },
        inputPorts: [],
        outputPorts: [{ portID: "output-0", displayName: "output" }],
        showAdvanced: false,
      },
      {
        operatorID: "filter1",
        operatorType: "Filter",
        operatorVersion: "1.0",
        operatorProperties: { predicate: "cases > 100" },
        inputPorts: [{ portID: "input-0", displayName: "input", disallowMultiInputs: true }],
        outputPorts: [{ portID: "output-0", displayName: "output" }],
        showAdvanced: false,
      },
    ],
    operatorPositions: { scan1: { x: 0, y: 0 }, filter1: { x: 200, y: 0 } },
    links: [
      {
        linkID: "link-1",
        source: { operatorID: "scan1", portID: "output-0" },
        target: { operatorID: "filter1", portID: "input-0" },
      },
    ],
    commentBoxes: [],
    settings: { dataTransferBatchSize: 400 },
  };
}

export function workflowResponse(
  overrides: Partial<{
    wid: number;
    name: string;
    description: string;
    content: WorkflowContent;
    lastModifiedTime: number;
    readonly: boolean;
    isPublished: boolean;
  }> = {}
) {
  const content = overrides.content ?? twoOperatorContent();
  return {
    wid: overrides.wid ?? 42,
    name: overrides.name ?? "Covid analysis",
    description: overrides.description ?? "",
    content: JSON.stringify(content),
    creationTime: 1_700_000_000_000,
    lastModifiedTime: overrides.lastModifiedTime ?? 1_700_000_500_000,
    isPublished: overrides.isPublished ?? false,
    readonly: overrides.readonly ?? false,
  };
}

export function datasetResponse(
  overrides: Partial<{ did: number; name: string; isPublic: boolean; isDownloadable: boolean; ownerEmail: string }> = {}
) {
  const did = overrides.did ?? 3;
  return {
    dataset: {
      did,
      name: overrides.name ?? "covid",
      description: "Case counts",
      ownerUid: 7,
      isPublic: overrides.isPublic ?? false,
      isDownloadable: overrides.isDownloadable ?? false,
      creationTime: 1_700_000_000_000,
      repositoryName: `dataset-${did}`,
    },
    ownerEmail: overrides.ownerEmail ?? "alice@example.org",
    accessPrivilege: "WRITE",
    isOwner: true,
    size: 2048,
  };
}

export function computingUnitResponse(overrides: Partial<{ cuid: number; name: string; status: string }> = {}) {
  return {
    computingUnit: {
      cuid: overrides.cuid ?? 1,
      uid: 7,
      name: overrides.name ?? "default-unit",
      creationTime: 1_700_000_000_000,
      terminateTime: null,
      type: "kubernetes",
    },
    status: overrides.status ?? "Running",
    metrics: { cpuUsage: "0.1", memoryUsage: "512Mi" },
    isOwner: true,
    accessPrivilege: "WRITE",
    ownerName: "alice",
  };
}
