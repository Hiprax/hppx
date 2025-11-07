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
  trimValues?: boolean;
  preserveNull?: boolean;
}

export interface HppxOptions extends SanitizeOptions {
  sources?: RequestSource[];
  /** When to process req.body */
  checkBodyContentType?: "urlencoded" | "any" | "none";
  excludePaths?: string[];
  strict?: boolean;
  onPollutionDetected?: (req: any, info: { source: RequestSource; pollutedKeys: string[] }) => void;
  logger?: (err: unknown) => void;
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

function sanitizeKey(key: string): string | null {
  /* istanbul ignore next */ if (typeof key !== "string") return null;
  if (DANGEROUS_KEYS.has(key)) return null;
  if (key.includes("\u0000")) return null;
  return key;
}

function parsePathSegments(key: string): string[] {
  // Convert bracket notation to dots, then split
  // a[b][c] -> a.b.c
  const dotted = key.replace(/\]/g, "").replace(/\[/g, ".");
  return dotted.split(".").filter((s) => s.length > 0);
}

function expandObjectPaths(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const rawKey of Object.keys(obj)) {
    const safeKey = sanitizeKey(rawKey);
    if (!safeKey) continue;
    const value = (obj as any)[rawKey];

    // Recursively expand nested objects first
    const expandedValue = isPlainObject(value)
      ? expandObjectPaths(value as Record<string, unknown>)
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

function setReqPropertySafe(target: any, key: string, value: unknown): void {
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

function safeDeepClone<T>(input: T): T {
  if (Array.isArray(input)) {
    return input.map((v) => safeDeepClone(v)) as T;
  }
  if (isPlainObject(input)) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(input)) {
      if (!sanitizeKey(k)) continue;
      out[k] = safeDeepClone((input as Record<string, unknown>)[k]);
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
  return {
    exact,
    prefixes,
    isWhitelistedPath(pathParts: string[]): boolean {
      if (pathParts.length === 0) return false;
      const full = pathParts.join(".");
      if (exact.has(full)) return true;
      // leaf match
      const leaf = pathParts[pathParts.length - 1]!;
      if (exact.has(leaf)) return true;
      // prefix match (treat any listed segment as prefix of a subtree)
      for (const p of prefixes) {
        if (full === p || full.startsWith(p + ".")) return true;
      }
      return false;
    },
  };
}

function setIn(target: Record<string, unknown>, path: string[], value: unknown): void {
  /* istanbul ignore if */
  if (path.length === 0) {
    return;
  }
  let cur: any = target;
  for (let i = 0; i < path.length - 1; i++) {
    const k = path[i]!;
    if (!isPlainObject(cur[k])) cur[k] = {};
    cur = cur[k];
  }
  const lastKey = path[path.length - 1]!;
  cur[lastKey] = value;
}

function moveWhitelistedFromPolluted(
  reqPart: Record<string, unknown>,
  polluted: Record<string, unknown>,
  isWhitelisted: (path: string[]) => boolean,
): void {
  function walk(
    node: Record<string, unknown>,
    path: string[] = [],
    parent?: Record<string, unknown>,
  ) {
    for (const k of Object.keys(node)) {
      const v = node[k];
      const curPath = [...path, k];
      if (isPlainObject(v)) {
        walk(v as Record<string, unknown>, curPath, node);
        // prune empty objects
        if (Object.keys(v as Record<string, unknown>).length === 0) {
          delete (node as any)[k];
        }
      } else {
        if (isWhitelisted(curPath)) {
          // put back into request
          const normalizedPath = curPath.flatMap((seg) =>
            seg.includes(".") ? seg.split(".") : [seg],
          );
          setIn(reqPart, normalizedPath, v);
          delete (node as any)[k];
        }
      }
    }
  }
  walk(polluted);
}

function detectAndReduce(
  input: Record<string, unknown>,
  opts: Required<
    Pick<SanitizeOptions, "mergeStrategy" | "maxDepth" | "maxKeys" | "trimValues" | "preserveNull">
  >,
): SanitizedResult<Record<string, unknown>> {
  let keyCount = 0;
  const polluted: Record<string, unknown> = {};
  const pollutedKeys: string[] = [];

  function processNode(node: unknown, path: string[] = [], depth = 0): unknown {
    if (node === null || node === undefined) return opts.preserveNull ? node : node;

    if (Array.isArray(node)) {
      const mapped = node.map((v) => processNode(v, path, depth));
      if (opts.mergeStrategy === "combine") {
        // combine: do not record pollution, but flatten using mergeValues
        return mergeValues(mapped, "combine");
      }
      // Other strategies: record pollution and reduce
      setIn(polluted, path, safeDeepClone(node));
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
        const safeKey = sanitizeKey(rawKey);
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

  const cloned = safeDeepClone(input);
  const cleaned = processNode(cloned, [], 0) as Record<string, unknown>;
  return { cleaned, pollutedTree: polluted, pollutedKeys };
}

export function sanitize<T extends Record<string, unknown>>(
  input: T,
  options: SanitizeOptions = {},
): T {
  // Normalize and expand keys prior to sanitization
  const expandedInput = isPlainObject(input) ? expandObjectPaths(input) : input;
  const whitelist = normalizeWhitelist(options.whitelist);
  const { isWhitelistedPath } = buildWhitelistHelpers(whitelist);
  const {
    mergeStrategy = DEFAULT_STRATEGY,
    maxDepth = 20,
    maxKeys = 5000,
    trimValues = false,
    preserveNull = true,
  } = options;

  // First: reduce arrays and collect polluted
  const { cleaned, pollutedTree } = detectAndReduce(expandedInput, {
    mergeStrategy,
    maxDepth,
    maxKeys,
    trimValues,
    preserveNull,
  });

  // Second: move back whitelisted arrays
  moveWhitelistedFromPolluted(cleaned, pollutedTree, isWhitelistedPath);

  return cleaned as T;
}

type ExpressLikeNext = (err?: any) => void;

export default function hppx(options: HppxOptions = {}) {
  const {
    whitelist = [],
    mergeStrategy = DEFAULT_STRATEGY,
    sources = DEFAULT_SOURCES,
    checkBodyContentType = "urlencoded",
    excludePaths = [],
    maxDepth = 20,
    maxKeys = 5000,
    trimValues = false,
    preserveNull = true,
    strict = false,
    onPollutionDetected,
    logger,
  } = options;

  const whitelistArr = normalizeWhitelist(whitelist);
  const { isWhitelistedPath } = buildWhitelistHelpers(whitelistArr);

  return function hppxMiddleware(req: any, res: any, next: ExpressLikeNext) {
    try {
      if (shouldExcludePath(req?.path, excludePaths)) return next();

      let anyPollutionDetected = false;
      const allPollutedKeys: string[] = [];

      for (const source of sources) {
        /* istanbul ignore next */ if (!req || typeof req !== "object") break;
        if (req[source] === undefined) continue;

        if (source === "body") {
          if (checkBodyContentType === "none") continue;
          if (checkBodyContentType === "urlencoded" && !isUrlEncodedContentType(req)) continue;
        }

        const part = req[source];
        if (!isPlainObject(part)) continue;

        // Preprocess: expand dotted and bracketed keys into nested objects
        const expandedPart = expandObjectPaths(part);

        const pollutedKey = `${source}Polluted`;
        const processedKey = `__hppxProcessed_${source}`;
        const hasProcessedBefore = Boolean((req as any)[processedKey]);

        if (!hasProcessedBefore) {
          // First pass for this request part: reduce arrays and collect polluted
          const { cleaned, pollutedTree, pollutedKeys } = detectAndReduce(expandedPart, {
            mergeStrategy,
            maxDepth,
            maxKeys,
            trimValues,
            preserveNull,
          });

          setReqPropertySafe(req, source, cleaned);

          // Attach polluted object (always present as {} when source processed)
          setReqPropertySafe(req, pollutedKey, pollutedTree);
          (req as any)[processedKey] = true;

          // Apply whitelist now: move whitelisted arrays back
          moveWhitelistedFromPolluted(req[source], req[pollutedKey], isWhitelistedPath);

          if (pollutedKeys.length > 0) {
            anyPollutionDetected = true;
            for (const k of pollutedKeys) allPollutedKeys.push(`${source}.${k}`);
          }
        } else {
          // Subsequent middleware: only put back whitelisted entries
          moveWhitelistedFromPolluted(req[source], req[pollutedKey], isWhitelistedPath);
          // pollution already accounted for in previous pass
        }
      }

      if (anyPollutionDetected) {
        if (onPollutionDetected) {
          try {
            onPollutionDetected(req, {
              source: "query",
              pollutedKeys: allPollutedKeys,
            });
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
      if (logger) {
        try {
          logger(err);
        } catch (_) {
          /* noop */
        }
      }
      return next(err);
    }
  };
}

export { DANGEROUS_KEYS, DEFAULT_STRATEGY, DEFAULT_SOURCES };
