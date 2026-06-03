// Core shared types for the BioMCP server.
//
// NOTE: this file was reconstructed from the compiled `dist/` output (the
// published Docker image ships no `src/`). Interfaces are inferred from how
// the values are used across the codebase; field optionality and exact names
// of purely-structural types may differ slightly from the original source.

/** Rate-limiter configuration consumed by {@link BaseApiClient}. */
export interface RateLimiterConfig {
  points: number;
  duration: number;
}

/** Construction config for an API client. */
export interface ApiClientConfig {
  baseUrl: string;
  timeout?: number;
  userAgent?: string;
  rateLimiter?: RateLimiterConfig;
}

export type ResponseType = "json" | "text";

/** Per-request options for {@link BaseApiClient.makeRequest}. */
export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  params?: Record<string, string>;
  body?: string;
  responseType?: ResponseType;
}

/** Uniform envelope returned by every API client call. */
export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}

/** Snapshot of the global rate-limiter budget. */
export interface RateLimitInfo {
  limit: number;
  remaining: number;
  resetTime: Date;
}

/** A single entry held by {@link MemoryCache}. */
export interface CacheEntry<T = unknown> {
  data: T;
  timestamp: number;
  ttl: number;
}
