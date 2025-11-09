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

export type RequestSource = "query" | "body" | "params";
export type MergeStrategy = "keepFirst" | "keepLast" | "combine";

export interface SanitizeOptions {
  whitelist?: string[] | string;
  mergeStrategy?: MergeStrategy;
  maxDepth?: number;
  maxKeys?: number;
  maxArrayLength?: number;
  maxKeyLength?: number;
  trimValues?: boolean;
  preserveNull?: boolean;
}

export interface HppxOptions extends SanitizeOptions {
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

export interface SanitizedResult<T> {
  cleaned: T;
  pollutedTree: Record<string, unknown>;
  pollutedKeys: string[];
}

export declare const DEFAULT_SOURCES: RequestSource[];
export declare const DEFAULT_STRATEGY: MergeStrategy;
export declare const DANGEROUS_KEYS: Set<string>;

export declare function sanitize<T extends Record<string, unknown>>(
  input: T,
  options?: SanitizeOptions,
): T;

type ExpressLikeNext = (err?: unknown) => void;

/**
 * Main hppx middleware function with named exports attached
 */
interface HppxFunction {
  (options?: HppxOptions): (req: any, res: any, next: ExpressLikeNext) => any;
  sanitize: typeof sanitize;
  DANGEROUS_KEYS: typeof DANGEROUS_KEYS;
  DEFAULT_SOURCES: typeof DEFAULT_SOURCES;
  DEFAULT_STRATEGY: typeof DEFAULT_STRATEGY;
}

declare const hppx: HppxFunction;

export = hppx;
