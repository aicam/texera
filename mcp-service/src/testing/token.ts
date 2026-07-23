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

/**
 * Builds an unsigned JWT for tests. The signature is never checked client-side
 * — only the deployment holds the HMAC secret — so a dummy one is enough to
 * exercise every code path that reads claims.
 */
export function makeToken(claims: Record<string, unknown> = {}): string {
  const payload: Record<string, unknown> = {
    sub: "alice",
    userId: 7,
    email: "alice@example.org",
    role: "REGULAR",
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600,
    ...claims,
  };
  for (const [key, value] of Object.entries(payload)) {
    if (value === undefined) delete payload[key];
  }
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url").replace(/=+$/, "");
  return `${encode({ alg: "HS256" })}.${encode(payload)}.signature`;
}
