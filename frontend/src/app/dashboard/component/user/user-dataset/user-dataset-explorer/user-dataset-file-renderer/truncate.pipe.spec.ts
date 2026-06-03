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

import { TruncatePipe } from "./truncate.pipe";

describe("TruncatePipe", () => {
  const pipe = new TruncatePipe();

  it("returns an empty string for null or undefined", () => {
    expect(pipe.transform(null)).toBe("");
    expect(pipe.transform(undefined)).toBe("");
  });

  it("coerces non-string values to strings", () => {
    expect(pipe.transform(7.2)).toBe("7.2");
    expect(pipe.transform(0)).toBe("0");
  });

  it("leaves a short string unchanged", () => {
    expect(pipe.transform("Released")).toBe("Released");
    expect(pipe.transform("")).toBe("");
  });

  it("does not truncate a string at exactly the limit", () => {
    const exact = "a".repeat(500);
    expect(pipe.transform(exact)).toBe(exact);
    expect(pipe.transform(exact).length).toBe(500);
  });

  it("truncates an over-limit string and appends an ellipsis", () => {
    const long = "a".repeat(13000);
    expect(pipe.transform(long)).toBe("a".repeat(500) + "…");
    expect(pipe.transform(long).length).toBe(501);
  });

  it("respects a custom limit and ellipsis", () => {
    expect(pipe.transform("abcdef", 3)).toBe("abc…");
    expect(pipe.transform("abcdef", 3, "...")).toBe("abc...");
  });
});
