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

import { describe, expect, test } from "bun:test";
import {
  WorkflowSystemMetadata,
  getExcludedOperatorTypes,
  DEFAULT_EXCLUDED_OPERATOR_TYPES,
} from "./workflow-system-metadata";

function makeOp(operatorType: string) {
  return {
    operatorType,
    operatorVersion: "1",
    jsonSchema: { properties: {}, required: [], definitions: {} },
    additionalMetadata: {
      userFriendlyName: operatorType,
      operatorGroupName: "g",
      operatorDescription: operatorType,
      inputPorts: [],
      outputPorts: [{}],
    },
  };
}

describe("WorkflowSystemMetadata operator exclusion", () => {
  test("hides obsolete operator types from the agent but keeps supported ones", () => {
    const store = new WorkflowSystemMetadata();
    store.loadFromMetadata({
      // The three supported keepers plus all 8 built-in default-excluded types.
      operators: [
        makeOp("CSVFileScan"),
        makeOp("PythonUDFV2"),
        makeOp("RUDF"),
        ...DEFAULT_EXCLUDED_OPERATOR_TYPES.map(makeOp),
      ],
      groups: [],
    } as any);

    const types = Object.keys(store.getAllOperatorTypes());
    expect(types).toContain("CSVFileScan");
    expect(types).toContain("PythonUDFV2");
    expect(types).toContain("RUDF");

    // Every one of the 8 built-in defaults is hidden (covers all entries, not just a subset).
    for (const hidden of DEFAULT_EXCLUDED_OPERATOR_TYPES) {
      expect(types).not.toContain(hidden);
      expect(store.operatorTypeExists(hidden)).toBe(false);
      expect(store.getCompactSchema(hidden)).toBeNull();
    }

    expect(store.operatorTypeExists("PythonUDFV2")).toBe(true);
    expect(store.getOperatorCount()).toBe(3);
  });
});

describe("getExcludedOperatorTypes", () => {
  test("always includes all built-in defaults, even with no extra exclusions", () => {
    const excluded = getExcludedOperatorTypes("");
    for (const t of DEFAULT_EXCLUDED_OPERATOR_TYPES) {
      expect(excluded.has(t)).toBe(true);
    }
    expect(excluded.size).toBe(DEFAULT_EXCLUDED_OPERATOR_TYPES.length);
  });

  test("unions extra types on top of the defaults (additive, not replacing) and trims whitespace", () => {
    const excluded = getExcludedOperatorTypes("CSVFileScan, RUDF ");
    // Extra types are now excluded...
    expect(excluded.has("CSVFileScan")).toBe(true);
    expect(excluded.has("RUDF")).toBe(true);
    // ...AND the built-in defaults remain excluded (not replaced by the extra list).
    expect(excluded.has("Dummy")).toBe(true);
    expect(excluded.has("PythonUDFSourceV2")).toBe(true);
    expect(excluded.size).toBe(DEFAULT_EXCLUDED_OPERATOR_TYPES.length + 2);
  });

  test("ignores empty/blank entries from trailing or doubled commas", () => {
    const excluded = getExcludedOperatorTypes("Foo,, ,Bar,");
    expect(excluded.has("Foo")).toBe(true);
    expect(excluded.has("Bar")).toBe(true);
    expect(excluded.has("")).toBe(false);
    expect(excluded.size).toBe(DEFAULT_EXCLUDED_OPERATOR_TYPES.length + 2);
  });
});
