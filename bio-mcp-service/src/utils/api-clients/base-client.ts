import { RateLimiterMemory } from "rate-limiter-flexible";
import type { ApiClientConfig, RequestOptions, ApiResponse, RateLimitInfo } from "../../types/index.js";

export class BaseApiClient {
  protected baseUrl: string;
  private rateLimiter?: RateLimiterMemory;
  private timeout: number;
  private userAgent: string;
  constructor(config: ApiClientConfig) {
    this.baseUrl = config.baseUrl;
    this.timeout = config.timeout || 30000;
    this.userAgent = config.userAgent || "BioMCP/1.0.0";
    if (config.rateLimiter) {
      this.rateLimiter = new RateLimiterMemory({
        points: config.rateLimiter.points,
        duration: config.rateLimiter.duration,
      });
    }
  }
  protected async makeRequest<T = unknown>(endpoint: string, options: RequestOptions = {}): Promise<ApiResponse<T>> {
    try {
      if (this.rateLimiter) {
        await this.rateLimiter.consume("global");
      }
      const url = new URL(endpoint, this.baseUrl);
      if (options.params) {
        Object.entries(options.params).forEach(([key, value]) => {
          url.searchParams.append(key, value);
        });
      }
      const responseType = options.responseType || "json";
      const fetchOptions: {
        method: string;
        headers: Record<string, string>;
        signal: AbortSignal;
        body?: string;
      } = {
        method: options.method || "GET",
        headers: {
          "User-Agent": this.userAgent,
          Accept: responseType === "json" ? "application/json" : "text/plain",
          ...options.headers,
        },
        signal: AbortSignal.timeout(this.timeout),
      };
      if (options.body) {
        fetchOptions.body = options.body;
        fetchOptions.headers = {
          ...fetchOptions.headers,
          "Content-Type": "application/json",
        };
      }
      const finalUrl = url.toString();
      const response = await fetch(finalUrl, fetchOptions);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      let data: T;
      if (responseType === "text") {
        data = (await response.text()) as T;
      } else {
        data = (await response.json()) as T;
      }
      return { success: true, data, timestamp: new Date().toISOString() };
    } catch (error) {
      const message = (() => {
        if (error instanceof Error) return error.message;
        if (error && typeof error === "object") {
          const maybeMsg =
            (error as { message?: string; toString?: () => string }).message ||
            (error as { toString?: () => string }).toString?.();
          if (typeof maybeMsg === "string" && maybeMsg.length > 0) return maybeMsg;
        }
        try {
          return String(error);
        } catch {
          return "Unknown error";
        }
      })();
      return { success: false, error: message, timestamp: new Date().toISOString() };
    }
  }
  async getRateLimitInfo(): Promise<RateLimitInfo | null> {
    if (!this.rateLimiter) return null;
    try {
      const res = await this.rateLimiter.get("global");
      if (!res) return null;
      return {
        limit: this.rateLimiter.points,
        remaining: res.remainingPoints,
        resetTime: new Date(Date.now() + (res.msBeforeNext || 0)),
      };
    } catch {
      return null;
    }
  }
  protected buildQueryString(params: Record<string, unknown>): string {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      searchParams.append(key, String(value));
    });
    return searchParams.toString();
  }
}
