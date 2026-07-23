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

/**
 * Logging seam for the SDK.
 *
 * The SDK is consumed by hosts with incompatible logging constraints: the
 * agent-service logs structured JSON through pino, while an MCP server speaking
 * stdio must never write to stdout at all (it would corrupt the JSON-RPC
 * stream). So the SDK ships a no-op logger and lets the host install its own
 * via {@link setSdkLoggerFactory}. The signature is pino's `(obj, msg)` order so
 * a pino child logger can be passed straight through.
 */

export interface SdkLogger {
  debug(obj: unknown, msg?: string): void;
  info(obj: unknown, msg?: string): void;
  warn(obj: unknown, msg?: string): void;
  error(obj: unknown, msg?: string): void;
}

export type SdkLoggerFactory = (module: string) => SdkLogger;

const noopLogger: SdkLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

let loggerFactory: SdkLoggerFactory = () => noopLogger;

/** Install the host's logger. Call once, before any SDK call that may log. */
export function setSdkLoggerFactory(factory: SdkLoggerFactory): void {
  loggerFactory = factory;
}

/** Reset to the silent default. Exists for tests. */
export function resetSdkLoggerFactory(): void {
  loggerFactory = () => noopLogger;
}

/**
 * Resolve a logger lazily on every call rather than caching the module-scoped
 * one: modules are imported before the host installs its factory, so caching
 * at import time would pin every logger to the no-op default.
 */
export function createSdkLogger(module: string): SdkLogger {
  return {
    debug: (obj, msg) => loggerFactory(module).debug(obj, msg),
    info: (obj, msg) => loggerFactory(module).info(obj, msg),
    warn: (obj, msg) => loggerFactory(module).warn(obj, msg),
    error: (obj, msg) => loggerFactory(module).error(obj, msg),
  };
}
