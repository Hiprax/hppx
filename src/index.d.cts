/**
 * hppx — Superior HTTP Parameter Pollution protection middleware
 *
 * - Protects against parameter and prototype pollution
 * - Supports nested whitelists via dot-notation and leaf matching
 * - Merge strategies: keepFirst | keepLast | combine
 * - Multiple middleware compatibility: arrays are "put aside" once and selectively restored
 * - Exposes req.queryPolluted / req.bodyPolluted / req.paramsPolluted
 * - TypeScript-first API
 */

type RequestSource = "query" | "body" | "params";
type MergeStrategy = "keepFirst" | "keepLast" | "combine";

interface SanitizeOptions {
  whitelist?: string[] | string;
  mergeStrategy?: MergeStrategy;
  maxDepth?: number;
  maxKeys?: number;
  maxArrayLength?: number;
  maxKeyLength?: number;
  trimValues?: boolean;
  preserveNull?: boolean;
}

interface HppxOptions extends SanitizeOptions {
  sources?: RequestSource[];
  /** When to process req.body */
  checkBodyContentType?: "urlencoded" | "any" | "none";
  excludePaths?: string[];
  strict?: boolean;
  onPollutionDetected?: (
    req: Record<string, unknown>,
    info: {
      source: RequestSource;
      pollutedKeys: string[];
    },
  ) => void;
  logger?: (err: Error | unknown) => void;
  /** Enable logging when pollution is detected (default: true) */
  logPollution?: boolean;
}

interface SanitizedResult<T> {
  cleaned: T;
  pollutedTree: Record<string, unknown>;
  pollutedKeys: string[];
}

type ExpressLikeNext = (err?: unknown) => void;

/**
 * Main hppx middleware function
 */
declare function hppx(options?: HppxOptions): (req: any, res: any, next: ExpressLikeNext) => any;

declare namespace hppx {
  export type { RequestSource, MergeStrategy, SanitizeOptions, HppxOptions, SanitizedResult };

  export function sanitize<T extends Record<string, unknown>>(
    input: T,
    options?: SanitizeOptions,
  ): T;

  export const DANGEROUS_KEYS: Set<string>;
  export const DEFAULT_SOURCES: RequestSource[];
  export const DEFAULT_STRATEGY: MergeStrategy;
}

export = hppx;
