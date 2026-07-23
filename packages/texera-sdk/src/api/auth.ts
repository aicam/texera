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
import type { UserInfo } from "../types/user";

export type { UserInfo } from "../types/user";

/**
 * Claims minted by `JwtAuth.jwtClaims` (amber). `sub` is the username; the
 * numeric user id lives in the non-standard `userId` claim.
 */
export interface TexeraJwtClaims {
  sub?: string;
  userId?: number;
  email?: string;
  role?: string;
  googleId?: string;
  googleAvatar?: string;
  exp?: number;
  [claim: string]: unknown;
}

/**
 * Decodes a JWT payload **without verifying the signature** — the shared HMAC
 * secret lives only inside the deployment, so a client can never verify. This
 * is safe for what it is used for here (reading `exp` and identity for display
 * and for pre-flight error messages); the backend is the only authority on
 * whether a token is actually valid.
 */
export function decodeJwtClaims(token: string): TexeraJwtClaims {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format: expected three dot-separated segments");
  }
  try {
    // base64url -> base64, then pad. atob is available in Node 18+, Bun and browsers.
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const json = typeof atob === "function" ? atob(padded) : Buffer.from(padded, "base64").toString("binary");
    // Recover UTF-8 from the binary string so non-ASCII names/emails survive.
    const bytes = Uint8Array.from(json, char => char.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)) as TexeraJwtClaims;
  } catch (error) {
    throw new Error(`Failed to decode JWT: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** @deprecated Use {@link decodeJwtClaims}. Kept for callers that expect the old name. */
export const decodeJWT = decodeJwtClaims;

export function extractUserFromToken(token: string): UserInfo {
  const payload = decodeJwtClaims(token);
  return {
    uid: payload.userId as number,
    name: payload.sub ?? "",
    email: payload.email || "",
    role: payload.role || "REGULAR",
  };
}

/** Expiry instant in epoch milliseconds, or `undefined` for a token without `exp`. */
export function tokenExpiresAt(token: string): number | undefined {
  const { exp } = decodeJwtClaims(token);
  return typeof exp === "number" ? exp * 1000 : undefined;
}

/**
 * Whether the token is past `exp`. A token with no `exp` is treated as
 * non-expiring here; the backend requires one (`setRequireExpirationTime`) and
 * would reject it, which is the correct place for that judgement.
 */
export function isTokenExpired(token: string, now: number = Date.now()): boolean {
  try {
    const expiresAt = tokenExpiresAt(token);
    return expiresAt === undefined ? false : now >= expiresAt;
  } catch {
    // Undecodable means unusable.
    return true;
  }
}

export function validateToken(token: string): boolean {
  return !isTokenExpired(token);
}

export function extractBearerToken(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const [scheme, token] = header.split(" ");
  return scheme?.toLowerCase() === "bearer" && token ? token : undefined;
}

export function createAuthHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

export interface TokenIssueResponse {
  accessToken: string;
}

/**
 * Exchanges credentials for a JWT via `POST /api/auth/login`.
 *
 * Only usable on deployments with local login enabled
 * (`/api/config/pre-login` -> `localLogin`); Google-only deployments issue
 * tokens through the Google flow instead.
 */
export async function login(client: TexeraClient, username: string, password: string): Promise<string> {
  const response = await client.request<TokenIssueResponse>("dashboard", "/api/auth/login", {
    method: "POST",
    json: { username, password },
    anonymous: true,
  });
  return response.accessToken;
}
