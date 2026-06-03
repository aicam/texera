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

import { Pipe, PipeTransform } from "@angular/core";

/**
 * Caps a value's string length so an oversized cell (e.g. a stringified-JSON
 * column tens of thousands of characters long) doesn't produce an unwieldy
 * native title tooltip. Pure, so it only recomputes when the input changes.
 * Non-string inputs are coerced; null/undefined become an empty string.
 */
@Pipe({ name: "truncate" })
export class TruncatePipe implements PipeTransform {
  transform(value: unknown, limit: number = 500, ellipsis: string = "…"): string {
    const text = value == null ? "" : String(value);
    return text.length > limit ? text.slice(0, limit) + ellipsis : text;
  }
}
