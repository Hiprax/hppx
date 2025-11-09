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
    info: { source: RequestSource; pollutedKeys: string[] },
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

const DEFAULT_SOURCES: RequestSource[] = ["query", "body", "params"];
const DEFAULT_STRATEGY: MergeStrategy = "keepLast";
const DANGEROUS_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function sanitizeKey(key: string, maxKeyLength?: number): string | null {
  /* istanbul ignore next */ if (typeof key !== "string") return null;
  if (DANGEROUS_KEYS.has(key)) return null;
  if (key.includes("\u0000")) return null;
  // Prevent excessively long keys that could cause DoS
  const maxLen = maxKeyLength ?? 200;
  if (key.length > maxLen) return null;
  // Prevent keys that are only dots or brackets (malformed) - but allow single dot as it's valid
  if (key.length > 1 && /^[.\[\]]+$/.test(key)) return null;
  return key;
}

// Cache for parsed path segments to improve performance
const pathSegmentCache = new Map<string, string[]>();

function parsePathSegments(key: string): string[] {
  // Check cache first
  const cached = pathSegmentCache.get(key);
  if (cached) return cached;

  // Convert bracket notation to dots, then split
  // a[b][c] -> a.b.c
  const dotted = key.replace(/\]/g, "").replace(/\[/g, ".");
  const result = dotted.split(".").filter((s) => s.length > 0);

  // Cache the result (limit cache size)
  if (pathSegmentCache.size < 500) {
    pathSegmentCache.set(key, result);
  }

  return result;
}

function expandObjectPaths(
  obj: Record<string, unknown>,
  maxKeyLength?: number,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const rawKey of Object.keys(obj)) {
    const safeKey = sanitizeKey(rawKey, maxKeyLength);
    if (!safeKey) continue;
    const value = obj[rawKey];

    // Recursively expand nested objects first
    const expandedValue = isPlainObject(value)
      ? expandObjectPaths(value as Record<string, unknown>, maxKeyLength)
      : value;

    if (safeKey.includes(".") || safeKey.includes("[")) {
      const segments = parsePathSegments(safeKey);
      if (segments.length > 0) {
        setIn(result, segments, expandedValue);
        continue;
      }
    }
    result[safeKey] = expandedValue;
  }
  return result;
}

function setReqPropertySafe(target: Record<string, unknown>, key: string, value: unknown): void {
  try {
    const desc = Object.getOwnPropertyDescriptor(target, key);
    if (desc && desc.configurable === false && desc.writable === false) {
      // Non-configurable and not writable: skip
      return;
    }
    if (!desc || desc.configurable !== false) {
      Object.defineProperty(target, key, {
        value,
        writable: true,
        configurable: true,
        enumerable: true,
      });
      return;
    }
  } catch (_) {
    // fall back to assignment below
  }
  try {
    target[key] = value;
  } catch (_) {
    // last resort: skip if cannot assign
  }
}

function safeDeepClone<T>(input: T, maxKeyLength?: number, maxArrayLength?: number): T {
  if (Array.isArray(input)) {
    // Limit array length to prevent memory exhaustion
    const limit = maxArrayLength ?? 1000;
    const limited = input.slice(0, limit);
    return limited.map((v) => safeDeepClone(v, maxKeyLength, maxArrayLength)) as T;
  }
  if (isPlainObject(input)) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(input)) {
      if (!sanitizeKey(k, maxKeyLength)) continue;
      out[k] = safeDeepClone((input as Record<string, unknown>)[k], maxKeyLength, maxArrayLength);
    }
    return out as T;
  }
  return input;
}

function mergeValues(values: unknown[], strategy: MergeStrategy): unknown {
  switch (strategy) {
    case "keepFirst":
      return values[0];
    case "keepLast":
      return values[values.length - 1];
    case "combine":
      return values.reduce<unknown[]>((acc, v) => {
        if (Array.isArray(v)) acc.push(...v);
        else acc.push(v);
        return acc;
      }, []);
    default:
      return values[values.length - 1];
  }
}

function isUrlEncodedContentType(req: any): boolean {
  const ct = String(req?.headers?.["content-type"] || "").toLowerCase();
  return ct.startsWith("application/x-www-form-urlencoded");
}

function shouldExcludePath(path: string | undefined, excludePaths: string[]): boolean {
  if (!path || excludePaths.length === 0) return false;
  const currentPath = path;
  for (const p of excludePaths) {
    if (p.endsWith("*")) {
      if (currentPath.startsWith(p.slice(0, -1))) return true;
    } else if (currentPath === p) {
      return true;
    }
  }
  return false;
}

function normalizeWhitelist(whitelist?: string[] | string): string[] {
  if (!whitelist) return [];
  if (typeof whitelist === "string") return [whitelist];
  return whitelist.filter((w) => typeof w === "string");
}

function buildWhitelistHelpers(whitelist: string[]) {
  const exact = new Set(whitelist);
  const prefixes = whitelist.filter((w) => w.length > 0);
  // Pre-build a cache for commonly checked paths for performance
  const pathCache = new Map<string, boolean>();

  return {
    exact,
    prefixes,
    isWhitelistedPath(pathParts: string[]): boolean {
      if (pathParts.length === 0) return false;
      const full = pathParts.join(".");

      // Check cache first for performance
      const cached = pathCache.get(full);
      if (cached !== undefined) return cached;

      let result = false;

      // Exact match
      if (exact.has(full)) {
        result = true;
      }
      // Leaf match
      else if (exact.has(pathParts[pathParts.length - 1]!)) {
        result = true;
      }
      // Prefix match (treat any listed segment as prefix of a subtree)
      else {
        for (const p of prefixes) {
          if (full === p || full.startsWith(p + ".")) {
            result = true;
            break;
          }
        }
      }

      // Cache the result (limit cache size to prevent memory issues)
      if (pathCache.size < 1000) {
        pathCache.set(full, result);
      }

      return result;
    },
  };
}

function setIn(target: Record<string, unknown>, path: string[], value: unknown): void {
  /* istanbul ignore if */
  if (path.length === 0) {
    return;
  }
  let cur: Record<string, unknown> = target;
  for (let i = 0; i < path.length - 1; i++) {
    const k = path[i]!;
    // Additional prototype pollution protection
    if (DANGEROUS_KEYS.has(k)) return;
    if (!isPlainObject(cur[k])) {
      // Create a new plain object to avoid pollution
      cur[k] = {};
    }
    cur = cur[k] as Record<string, unknown>;
  }
  const lastKey = path[path.length - 1]!;
  // Final check on the last key
  if (DANGEROUS_KEYS.has(lastKey)) return;
  cur[lastKey] = value;
}

function moveWhitelistedFromPolluted(
  reqPart: Record<string, unknown>,
  polluted: Record<string, unknown>,
  isWhitelisted: (path: string[]) => boolean,
): void {
  function walk(node: Record<string, unknown>, path: string[] = []) {
    for (const k of Object.keys(node)) {
      const v = node[k];
      const curPath = [...path, k];
      if (isPlainObject(v)) {
        walk(v as Record<string, unknown>, curPath);
        // prune empty objects
        if (Object.keys(v as Record<string, unknown>).length === 0) {
          delete node[k];
        }
      } else {
        if (isWhitelisted(curPath)) {
          // put back into request
          const normalizedPath = curPath.flatMap((seg) =>
            seg.includes(".") ? seg.split(".") : [seg],
          );
          setIn(reqPart, normalizedPath, v);
          delete node[k];
        }
      }
    }
  }
  walk(polluted);
}

function detectAndReduce(
  input: Record<string, unknown>,
  opts: Required<
    Pick<
      SanitizeOptions,
      | "mergeStrategy"
      | "maxDepth"
      | "maxKeys"
      | "maxArrayLength"
      | "maxKeyLength"
      | "trimValues"
      | "preserveNull"
    >
  >,
): SanitizedResult<Record<string, unknown>> {
  let keyCount = 0;
  const polluted: Record<string, unknown> = {};
  const pollutedKeys: string[] = [];

  function processNode(node: unknown, path: string[] = [], depth = 0): unknown {
    if (node === null || node === undefined) return opts.preserveNull ? node : node;

    if (Array.isArray(node)) {
      // Limit array length to prevent DoS
      const limit = opts.maxArrayLength ?? 1000;
      const limitedNode = node.slice(0, limit);

      const mapped = limitedNode.map((v) => processNode(v, path, depth));
      if (opts.mergeStrategy === "combine") {
        // combine: do not record pollution, but flatten using mergeValues
        return mergeValues(mapped, "combine");
      }
      // Other strategies: record pollution and reduce
      setIn(polluted, path, safeDeepClone(limitedNode, opts.maxKeyLength, opts.maxArrayLength));
      pollutedKeys.push(path.join("."));
      const reduced = mergeValues(mapped, opts.mergeStrategy);
      return reduced;
    }

    if (isPlainObject(node)) {
      if (depth > opts.maxDepth)
        throw new Error(`Maximum object depth (${opts.maxDepth}) exceeded`);
      const out: Record<string, unknown> = {};
      for (const rawKey of Object.keys(node)) {
        keyCount++;
        if (keyCount > (opts.maxKeys ?? Number.MAX_SAFE_INTEGER)) {
          throw new Error(`Maximum key count (${opts.maxKeys}) exceeded`);
        }
        const safeKey = sanitizeKey(rawKey, opts.maxKeyLength);
        if (!safeKey) continue;
        const child = (node as Record<string, unknown>)[rawKey];
        const childPath = path.concat([safeKey]);
        let value = processNode(child, childPath, depth + 1);
        if (typeof value === "string" && opts.trimValues) value = value.trim();
        out[safeKey] = value;
      }
      return out;
    }

    return node;
  }

  const cloned = safeDeepClone(input, opts.maxKeyLength, opts.maxArrayLength);
  const cleaned = processNode(cloned, [], 0) as Record<string, unknown>;
  return { cleaned, pollutedTree: polluted, pollutedKeys };
}

export function sanitize<T extends Record<string, unknown>>(
  input: T,
  options: SanitizeOptions = {},
): T {
  // Normalize and expand keys prior to sanitization
  const maxKeyLength = options.maxKeyLength ?? 200;
  const expandedInput = isPlainObject(input) ? expandObjectPaths(input, maxKeyLength) : input;
  const whitelist = normalizeWhitelist(options.whitelist);
  const { isWhitelistedPath } = buildWhitelistHelpers(whitelist);
  const {
    mergeStrategy = DEFAULT_STRATEGY,
    maxDepth = 20,
    maxKeys = 5000,
    maxArrayLength = 1000,
    trimValues = false,
    preserveNull = true,
  } = options;

  // First: reduce arrays and collect polluted
  const { cleaned, pollutedTree } = detectAndReduce(expandedInput, {
    mergeStrategy,
    maxDepth,
    maxKeys,
    maxArrayLength,
    maxKeyLength,
    trimValues,
    preserveNull,
  });

  // Second: move back whitelisted arrays
  moveWhitelistedFromPolluted(cleaned, pollutedTree, isWhitelistedPath);

  return cleaned as T;
}

type ExpressLikeNext = (err?: unknown) => void;

function validateOptions(options: HppxOptions): void {
  if (
    options.maxDepth !== undefined &&
    (typeof options.maxDepth !== "number" || options.maxDepth < 1 || options.maxDepth > 100)
  ) {
    throw new TypeError("maxDepth must be a number between 1 and 100");
  }
  if (
    options.maxKeys !== undefined &&
    (typeof options.maxKeys !== "number" || options.maxKeys < 1)
  ) {
    throw new TypeError("maxKeys must be a positive number");
  }
  if (
    options.maxArrayLength !== undefined &&
    (typeof options.maxArrayLength !== "number" || options.maxArrayLength < 1)
  ) {
    throw new TypeError("maxArrayLength must be a positive number");
  }
  if (
    options.maxKeyLength !== undefined &&
    (typeof options.maxKeyLength !== "number" ||
      options.maxKeyLength < 1 ||
      options.maxKeyLength > 1000)
  ) {
    throw new TypeError("maxKeyLength must be a number between 1 and 1000");
  }
  if (
    options.mergeStrategy !== undefined &&
    !["keepFirst", "keepLast", "combine"].includes(options.mergeStrategy)
  ) {
    throw new TypeError("mergeStrategy must be 'keepFirst', 'keepLast', or 'combine'");
  }
  if (options.sources !== undefined && !Array.isArray(options.sources)) {
    throw new TypeError("sources must be an array");
  }
  if (options.sources !== undefined) {
    for (const source of options.sources) {
      if (!["query", "body", "params"].includes(source)) {
        throw new TypeError("sources must only contain 'query', 'body', or 'params'");
      }
    }
  }
  if (
    options.checkBodyContentType !== undefined &&
    !["urlencoded", "any", "none"].includes(options.checkBodyContentType)
  ) {
    throw new TypeError("checkBodyContentType must be 'urlencoded', 'any', or 'none'");
  }
  if (options.excludePaths !== undefined && !Array.isArray(options.excludePaths)) {
    throw new TypeError("excludePaths must be an array");
  }
}

export default function hppx(options: HppxOptions = {}) {
  // Validate options on middleware creation
  validateOptions(options);

  const {
    whitelist = [],
    mergeStrategy = DEFAULT_STRATEGY,
    sources = DEFAULT_SOURCES,
    checkBodyContentType = "urlencoded",
    excludePaths = [],
    maxDepth = 20,
    maxKeys = 5000,
    maxArrayLength = 1000,
    maxKeyLength = 200,
    trimValues = false,
    preserveNull = true,
    strict = false,
    onPollutionDetected,
    logger,
    logPollution = true,
  } = options;

  const whitelistArr = normalizeWhitelist(whitelist);
  const { isWhitelistedPath } = buildWhitelistHelpers(whitelistArr);

  return function hppxMiddleware(req: any, res: any, next: ExpressLikeNext) {
    try {
      if (shouldExcludePath(req?.path, excludePaths)) return next();

      let anyPollutionDetected = false;
      const allPollutedKeys: string[] = [];

      for (const source of sources) {
        /* istanbul ignore next */
        if (!req || typeof req !== "object") break;
        if (req[source] === undefined) continue;

        if (source === "body") {
          if (checkBodyContentType === "none") continue;
          if (checkBodyContentType === "urlencoded" && !isUrlEncodedContentType(req)) continue;
        }

        const part = req[source];
        if (!isPlainObject(part)) continue;

        // Preprocess: expand dotted and bracketed keys into nested objects
        const expandedPart = expandObjectPaths(part, maxKeyLength);

        const pollutedKey = `${source}Polluted`;
        const processedKey = `__hppxProcessed_${source}`;
        const hasProcessedBefore = Boolean(req[processedKey]);

        if (!hasProcessedBefore) {
          // First pass for this request part: reduce arrays and collect polluted
          const { cleaned, pollutedTree, pollutedKeys } = detectAndReduce(expandedPart, {
            mergeStrategy,
            maxDepth,
            maxKeys,
            maxArrayLength,
            maxKeyLength,
            trimValues,
            preserveNull,
          });

          setReqPropertySafe(req, source, cleaned);

          // Attach polluted object (always present as {} when source processed)
          setReqPropertySafe(req, pollutedKey, pollutedTree);
          req[processedKey] = true;

          // Apply whitelist now: move whitelisted arrays back
          const sourceData = req[source];
          const pollutedData = req[pollutedKey];
          if (isPlainObject(sourceData) && isPlainObject(pollutedData)) {
            moveWhitelistedFromPolluted(sourceData, pollutedData, isWhitelistedPath);
          }

          if (pollutedKeys.length > 0) {
            anyPollutionDetected = true;
            for (const k of pollutedKeys) allPollutedKeys.push(`${source}.${k}`);
          }
        } else {
          // Subsequent middleware: only put back whitelisted entries
          const sourceData = req[source];
          const pollutedData = req[pollutedKey];
          if (isPlainObject(sourceData) && isPlainObject(pollutedData)) {
            moveWhitelistedFromPolluted(sourceData, pollutedData, isWhitelistedPath);
          }
          // pollution already accounted for in previous pass
        }
      }

      if (anyPollutionDetected) {
        // Log pollution detection if enabled
        if (logPollution) {
          const logMessage = `[hppx] HTTP Parameter Pollution detected - ${allPollutedKeys.length} parameter(s) affected: ${allPollutedKeys.join(", ")}`;
          if (logger) {
            try {
              logger(logMessage);
            } catch (_) {
              // Fallback to console.warn if logger fails
              console.warn(logMessage);
            }
          } else {
            console.warn(logMessage);
          }
        }

        if (onPollutionDetected) {
          try {
            // Determine which sources had pollution
            for (const source of sources) {
              const pollutedKey = `${source}Polluted`;
              const pollutedData = req[pollutedKey];
              if (pollutedData && Object.keys(pollutedData).length > 0) {
                const sourcePollutedKeys = allPollutedKeys.filter((k) =>
                  k.startsWith(`${source}.`),
                );
                if (sourcePollutedKeys.length > 0) {
                  onPollutionDetected(req, {
                    source: source,
                    pollutedKeys: sourcePollutedKeys,
                  });
                }
              }
            }
          } catch (_) {
            /* ignore user callback errors */
          }
        }
        if (strict && res && typeof res.status === "function") {
          return res.status(400).json({
            error: "Bad Request",
            message: "HTTP Parameter Pollution detected",
            pollutedParameters: allPollutedKeys,
            code: "HPP_DETECTED",
          });
        }
      }

      return next();
    } catch (err) {
      // Enhanced error handling with detailed logging
      const error = err instanceof Error ? err : new Error(String(err));

      if (logger) {
        try {
          logger(error);
        } catch (logErr) {
          // If custom logger fails, use console.error as fallback in development
          if (process.env.NODE_ENV !== "production") {
            console.error("[hppx] Logger failed:", logErr);
            console.error("[hppx] Original error:", error);
          }
        }
      }

      // Pass error to next middleware for proper error handling
      return next(error);
    }
  };
}

export { DANGEROUS_KEYS, DEFAULT_STRATEGY, DEFAULT_SOURCES };
