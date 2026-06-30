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

// Augment the Express Request interface with hppx-specific properties so that
// consumers importing this package automatically get typed access to the
// polluted-tree fields. The `declare module` block lives here (rather than in
// a separate `.d.ts` file) so that tsup emits it into both `dist/index.d.ts`
// and `dist/index.d.cts`, which are kept in symbol-parity by
// `scripts/check-dts-parity.mjs`.
//
// The `import type` below is required for TypeScript 6.0+ DTS rollup, which no
// longer resolves augmentation targets through transitive `@types` packages.
// It pulls the augmentation module into scope without affecting the JS output.
import type {} from "express-serve-static-core";

declare module "express-serve-static-core" {
  interface Request {
    queryPolluted?: Record<string, unknown>;
    bodyPolluted?: Record<string, unknown>;
    paramsPolluted?: Record<string, unknown>;
  }
}

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

// Pre-compiled, ReDoS-safe character class that rejects keys containing any of:
//   - ASCII C0 controls (U+0000..U+001F) and DEL (U+007F)
//   - C1 controls (U+0080..U+009F)
//   - Unicode bidirectional control characters: U+200E/U+200F (LRM/RLM),
//     U+202A..U+202E (LRE/RLE/PDF/LRO/RLO), U+2066..U+2069 (LRI/RLI/FSI/PDI)
//   - U+FEFF (BOM / zero-width no-break space) — typically accidental in keys
//     and used to bypass naive key-based logic.
// Rejecting these prevents bypass of downstream key-based logic, log injection,
// and DB/log corruption when output is not properly quoted. The character
// class contains no quantifiers, so it cannot trigger ReDoS.
/* eslint-disable no-control-regex -- intentional: this regex must include control characters in order to reject them */
const FORBIDDEN_KEY_CHARS =
  /[\u0000-\u001F\u007F-\u009F\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/;
/* eslint-enable no-control-regex */

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function sanitizeKey(key: string, maxKeyLength?: number): string | null {
  /* istanbul ignore next */ if (typeof key !== "string") return null;
  if (DANGEROUS_KEYS.has(key)) return null;
  // Reject keys containing ASCII/Unicode control characters or bidirectional
  // override characters. Subsumes the previous explicit NUL-byte check.
  if (FORBIDDEN_KEY_CHARS.test(key)) return null;
  // Prevent excessively long keys that could cause DoS
  /* istanbul ignore next -- defensive: callers always pass maxKeyLength explicitly */
  const maxLen = maxKeyLength ?? 200;
  if (key.length > maxLen) return null;
  // Prevent keys that are only dots or brackets (malformed) - but allow single dot as it's valid
  if (key.length > 1 && /^[.\[\]]+$/.test(key)) return null;
  return key;
}

// Cache for parsed path segments to improve performance.
// Uses a clear-on-full eviction policy: when the cache reaches capacity, it is
// cleared in its entirety so future entries can still be cached. This prevents
// a one-shot poisoning attack where an attacker pumps unique keys into a single
// request to permanently disable the cache for legitimate traffic.
const PATH_SEGMENT_CACHE_LIMIT = 500;
const pathSegmentCache = new Map<string, string[]>();

/**
 * Parse a (possibly composite) key into an array of path segments.
 *
 * Accepted forms (and how they're parsed):
 *   - Dotted:           "a.b.c"        -> ["a", "b", "c"]
 *   - Bracket:          "a[b][c]"      -> ["a", "b", "c"]
 *   - Mixed:            "a.b[c].d"     -> ["a", "b", "c", "d"]
 *   - Numeric brackets: "a[0][1]"      -> ["a", "0", "1"]   (indexes become string segments)
 *   - Trailing/empty:   "a..b" / "a[]" -> ["a", "b"] / ["a"] (empty segments dropped)
 *
 * **The parser is intentionally lenient.** Malformed inputs like `a]]b[[c`
 * collapse to `["a", "b", "c"]` rather than being rejected. Justification:
 *
 *   1. Every key reaching this function has already passed `sanitizeKey`,
 *      which rejects truly hostile inputs — dangerous keys (`__proto__`,
 *      `prototype`, `constructor`), control characters, bidirectional
 *      override characters, dot/bracket-only patterns, and overly long
 *      strings. The remaining surface is benign syntactic noise.
 *
 *   2. Lenient parsing is acceptable defense-in-depth: even if an attacker
 *      crafts unusual bracket placement, the parsed segments are still
 *      passed through `sanitizeKey` again at every level by `setIn`, which
 *      blocks dangerous keys at the segment level too.
 *
 *   3. Strict grammar enforcement here would be a behavioral change that
 *      could break legitimate users with unusual key shapes, while
 *      providing little additional security beyond what `sanitizeKey`
 *      already enforces.
 *
 * The regexes are character-class only (no quantifiers), so this function is
 * ReDoS-safe.
 */
function parsePathSegments(key: string): string[] {
  // Check cache first
  const cached = pathSegmentCache.get(key);
  if (cached) return cached;

  // Convert bracket notation to dots, then split
  // a[b][c] -> a.b.c
  const dotted = key.replace(/\]/g, "").replace(/\[/g, ".");
  const result = dotted.split(".").filter((s) => s.length > 0);

  // Clear-on-full eviction: prevents permanent cache disablement after a flood
  // of unique keys, while keeping the implementation O(1) on insert.
  if (pathSegmentCache.size >= PATH_SEGMENT_CACHE_LIMIT) {
    pathSegmentCache.clear();
  }
  pathSegmentCache.set(key, result);

  return result;
}

/**
 * @internal — test-only helper that resets the module-level path segment cache.
 * Public callers must not depend on this; it exists solely so tests can verify
 * cache eviction behavior without exposing the internal Map.
 */
export function __resetPathSegmentCache(): void {
  pathSegmentCache.clear();
}

function expandObjectPaths(
  obj: Record<string, unknown>,
  maxKeyLength?: number,
  maxDepth = 20,
  currentDepth = 0,
  seen?: WeakSet<object>,
): Record<string, unknown> {
  if (currentDepth > maxDepth) {
    throw new Error(`Maximum object depth (${maxDepth}) exceeded`);
  }
  // Path-stack cycle detection: only detect references currently on the recursion
  // stack (true cycles), not previously-visited-but-fully-emitted nodes (shared
  // acyclic subtrees, which must be fully cloned at each occurrence).
  const seenSet = seen ?? new WeakSet<object>();
  if (seenSet.has(obj)) return {};
  seenSet.add(obj);
  try {
    const result: Record<string, unknown> = {};
    for (const rawKey of Object.keys(obj)) {
      const safeKey = sanitizeKey(rawKey, maxKeyLength);
      if (!safeKey) continue;
      const value = obj[rawKey];

      // Recursively expand nested objects first
      const expandedValue = isPlainObject(value)
        ? expandObjectPaths(
            value as Record<string, unknown>,
            maxKeyLength,
            maxDepth,
            currentDepth + 1,
            seenSet,
          )
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
  } finally {
    seenSet.delete(obj);
  }
}

/**
 * Attempts to set a property on a request-like object.
 *
 * Returns `true` if the property is observable as the requested value after the call,
 * `false` if every attempt failed.
 *
 * Strategy:
 * 1. If no own descriptor exists, or the descriptor is configurable, redefine via
 *    `Object.defineProperty` so the assigned value shadows any prototype-level getter
 *    (e.g. Express 5's lazy `req.query` getter on `IncomingMessage.prototype`).
 * 2. If the descriptor is non-configurable BUT writable, fall through to direct
 *    assignment.
 * 3. If the descriptor is non-configurable AND non-writable, attempt direct assignment
 *    in a `try/catch` (in strict mode it will throw); on failure, surface a warning via
 *    the supplied logger so the user knows the request continues to expose the original
 *    (potentially polluted) value.
 */
function setReqPropertySafe(
  target: Record<string, unknown>,
  key: string,
  value: unknown,
  onFailure?: (message: string) => void,
): boolean {
  try {
    const desc = Object.getOwnPropertyDescriptor(target, key);
    if (!desc || desc.configurable !== false) {
      Object.defineProperty(target, key, {
        value,
        writable: true,
        configurable: true,
        enumerable: true,
      });
      return true;
    }
    // desc is non-configurable; defineProperty cannot be used.
    if (desc.writable) {
      target[key] = value;
      return true;
    }
    // Non-configurable + non-writable: attempt direct assignment which will throw in
    // strict mode. Do NOT silently skip — surface the failure.
    try {
      target[key] = value;
      /* istanbul ignore next -- sloppy-mode read-back unreachable here:
         this module is ESM (implicitly strict mode), so the assignment above
         throws on any non-writable target. The read-back guards against the
         sloppy-mode case where the assignment silently no-ops. */
      if (target[key] === value) return true;
    } catch (_assignErr) {
      // fall through to the warning below
    }
    if (onFailure) {
      onFailure(
        `[hppx] Could not write sanitized value to req.${key}: property is non-configurable and non-writable. The original (potentially polluted) value remains on req.${key}.`,
      );
    }
    return false;
  } catch (_definePropErr) {
    // defineProperty itself threw — try plain assignment as a last resort.
    try {
      target[key] = value;
      if (target[key] === value) return true;
    } catch (_assignErr) {
      // fall through
    }
    /* istanbul ignore next -- defensive fallback for an extreme edge case:
       reaching here requires defineProperty to throw AND the subsequent
       direct assignment to either throw or silently no-op AND an onFailure
       callback to be configured. Exercised indirectly via the assignment
       fallback test (which patches defineProperty to throw). */
    {
      if (onFailure) {
        onFailure(`[hppx] Could not write sanitized value to req.${key}: defineProperty failed.`);
      }
      return false;
    }
  }
}

function safeDeepClone<T>(
  input: T,
  maxKeyLength?: number,
  maxArrayLength?: number,
  maxDepth = 20,
  currentDepth = 0,
  seen?: WeakSet<object>,
): T {
  // Path-stack cycle detection: a node is added to `seen` on entry and removed
  // on exit (via `finally`). This correctly distinguishes true cycles
  // (currently on the recursion stack) from shared acyclic subtrees (already
  // emitted but no longer on the stack — must be cloned independently).
  if (Array.isArray(input)) {
    if (currentDepth > maxDepth) {
      throw new Error(`Maximum object depth (${maxDepth}) exceeded`);
    }
    const seenSet = seen ?? new WeakSet<object>();
    if (seenSet.has(input)) return [] as T;
    seenSet.add(input);
    try {
      // Limit array length to prevent memory exhaustion
      const limit = maxArrayLength ?? 1000;
      const limited = input.slice(0, limit);
      return limited.map((v) =>
        safeDeepClone(v, maxKeyLength, maxArrayLength, maxDepth, currentDepth + 1, seenSet),
      ) as T;
    } finally {
      seenSet.delete(input);
    }
  }
  if (isPlainObject(input)) {
    if (currentDepth > maxDepth) {
      throw new Error(`Maximum object depth (${maxDepth}) exceeded`);
    }
    const seenSet = seen ?? new WeakSet<object>();
    if (seenSet.has(input as object)) return {} as T;
    seenSet.add(input as object);
    try {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(input)) {
        if (!sanitizeKey(k, maxKeyLength)) continue;
        out[k] = safeDeepClone(
          (input as Record<string, unknown>)[k],
          maxKeyLength,
          maxArrayLength,
          maxDepth,
          currentDepth + 1,
          seenSet,
        );
      }
      return out as T;
    } finally {
      seenSet.delete(input as object);
    }
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
    /* istanbul ignore next -- exhaustiveness check unreachable from outside:
       validateSanitizeOptions rejects every non-listed strategy at construction
       time, so the only way to reach this branch is a programmer error (a new
       MergeStrategy union member added without updating this switch). Failing
       loudly here is preferable to a silent fallback. */
    default: {
      const _exhaustive: never = strategy;
      throw new Error(`Unknown mergeStrategy: ${_exhaustive as string}`);
    }
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

const WHITELIST_PATH_CACHE_LIMIT = 1000;

function buildWhitelistHelpers(whitelist: string[]) {
  const exact = new Set(whitelist);
  const prefixes = whitelist.filter((w) => w.length > 0);
  // Pre-build a cache for commonly checked paths for performance. Uses a
  // clear-on-full eviction policy (matching `pathSegmentCache`) to prevent a
  // poisoning attack where an attacker pumps unique paths to permanently
  // disable caching for legitimate paths.
  const pathCache = new Map<string, boolean>();

  return {
    exact,
    prefixes,
    isWhitelistedPath(pathParts: string[]): boolean {
      /* istanbul ignore if -- defensive: always called with non-empty path from walk() */
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

      // Clear-on-full eviction: prevents permanent cache disablement after a
      // flood of unique paths, while keeping the implementation O(1) on insert.
      if (pathCache.size >= WHITELIST_PATH_CACHE_LIMIT) {
        pathCache.clear();
      }
      pathCache.set(full, result);

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
          /* istanbul ignore next -- defensive: polluted tree keys never contain dots after expansion */
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
  // Use a Set for de-duplication. Multiple arrays can land at the same dotted
  // path (e.g. `[{tags:[...]}, {tags:[...]}]` produces two array sites at
  // `items.tags`); the user-facing `pollutedKeys` list should report each
  // affected leaf path exactly once, not once per occurrence. The `inArray`
  // flag below also prevents nested array-in-array recursion from recording
  // duplicate entries at the same path (e.g. `{a: [[1,2],[3,4]]}`).
  const pollutedKeysSet = new Set<string>();

  // === Detachment invariant ===
  //
  // The single upfront `safeDeepClone` enforces maxKeyLength / maxArrayLength /
  // maxDepth and produces `cloned`, a tree fully detached from `input`:
  //
  //   1. No reference inside `cloned` aliases back into the caller-owned input
  //      tree. This holds because safeDeepClone walks plain objects and arrays
  //      recursively and only re-emits primitives / freshly-created containers.
  //   2. Cycles in `input` are broken by safeDeepClone's path-stack `WeakSet`
  //      (a node currently on the recursion stack is replaced with `{}` / `[]`
  //      on its second visit), so `cloned` is acyclic.
  //
  // processNode walks `cloned` (NOT `input`) and:
  //   - records `node` (a reference INTO `cloned`) into the polluted tree,
  //     which is safe precisely because (1) guarantees no caller-owned data
  //     is exposed via the polluted tree, and
  //   - rebuilds the cleaned output as a fresh structure (objects via the
  //     `out` literal in this function; arrays via `Array.prototype.map`).
  //
  // No nested safeDeepClone is performed here — it would be redundant work
  // and, if invoked with a fresh WeakSet, could re-introduce traversal of
  // cycles that the upfront clone already broke.
  const cloned = safeDeepClone(input, opts.maxKeyLength, opts.maxArrayLength, opts.maxDepth);

  function processNode(node: unknown, path: string[] = [], depth = 0, inArray = false): unknown {
    if (node === null) return opts.preserveNull ? null : undefined;
    if (node === undefined) return node;

    if (Array.isArray(node)) {
      // Array is already truncated to maxArrayLength by the upfront clone, so
      // we can use it directly without re-slicing.
      //
      // Pollution is recorded only at the OUTERMOST array site for a given
      // `path`. When `inArray` is true, we are recursing into elements of an
      // already-recorded outer array (e.g. `{a: [[1,2],[3,4]]}` reaches the
      // inner arrays at the same `path` as the outer one); in that case we
      // skip the redundant `setIn` / `pollutedKeys.push` so consumers of
      // `pollutedKeys` and `pollutedTree` see one entry per affected leaf.
      const mapped = node.map((v) => processNode(v, path, depth, true));
      if (!inArray) {
        // Record pollution for ALL strategies (including combine). The combined
        // output remains the cleaned value, but the security signal — polluted
        // tree, pollutedKeys, onPollutionDetected callback — must still fire so
        // consumers of those signals are not silently bypassed in combine mode.
        //
        // Per the detachment invariant above, `node` is part of `cloned` (NOT
        // `input`); storing it in the polluted tree therefore cannot leak any
        // caller-owned reference, and the polluted tree is itself acyclic
        // because `cloned` is acyclic.
        setIn(polluted, path, node);
        pollutedKeysSet.add(path.join("."));
      }
      return mergeValues(mapped, opts.mergeStrategy);
    }

    if (isPlainObject(node)) {
      /* istanbul ignore if -- defensive: safeDeepClone enforces the same depth limit first */
      if (depth > opts.maxDepth)
        throw new Error(`Maximum object depth (${opts.maxDepth}) exceeded`);
      const out: Record<string, unknown> = {};
      for (const rawKey of Object.keys(node)) {
        keyCount++;
        /* istanbul ignore if -- defensive: opts.maxKeys is always provided by callers */
        if (keyCount > (opts.maxKeys ?? Number.MAX_SAFE_INTEGER)) {
          throw new Error(`Maximum key count (${opts.maxKeys}) exceeded`);
        }
        const safeKey = sanitizeKey(rawKey, opts.maxKeyLength);
        /* istanbul ignore if -- defensive: keys already filtered by expandObjectPaths + safeDeepClone */
        if (!safeKey) continue;
        const child = (node as Record<string, unknown>)[rawKey];
        const childPath = path.concat([safeKey]);
        // Walking into an object key resets `inArray` — each key starts a fresh
        // path under which a new array site can record pollution exactly once.
        let value = processNode(child, childPath, depth + 1, false);
        if (typeof value === "string" && opts.trimValues) value = value.trim();
        out[safeKey] = value;
      }
      return out;
    }

    return node;
  }

  const cleaned = processNode(cloned, [], 0, false) as Record<string, unknown>;
  return { cleaned, pollutedTree: polluted, pollutedKeys: Array.from(pollutedKeysSet) };
}

export function sanitize<T extends Record<string, unknown>>(
  input: T,
  options: SanitizeOptions = {},
): T {
  validateSanitizeOptions(options);
  // Normalize and expand keys prior to sanitization
  const maxKeyLength = options.maxKeyLength ?? 200;
  const maxDepthVal = options.maxDepth ?? 20;
  const expandedInput = isPlainObject(input)
    ? expandObjectPaths(input, maxKeyLength, maxDepthVal)
    : input;
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

function validateSanitizeOptions(options: SanitizeOptions): void {
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
  if (options.trimValues !== undefined && typeof options.trimValues !== "boolean") {
    throw new TypeError("trimValues must be a boolean");
  }
  if (options.preserveNull !== undefined && typeof options.preserveNull !== "boolean") {
    throw new TypeError("preserveNull must be a boolean");
  }
  if (options.whitelist !== undefined) {
    if (typeof options.whitelist !== "string" && !Array.isArray(options.whitelist)) {
      throw new TypeError("whitelist must be a string or an array of strings");
    }
    if (Array.isArray(options.whitelist)) {
      for (const entry of options.whitelist) {
        if (typeof entry !== "string") {
          throw new TypeError("whitelist must be a string or an array of strings");
        }
      }
    }
  }
}

function validateOptions(options: HppxOptions): void {
  validateSanitizeOptions(options);
  if (options.sources !== undefined && !Array.isArray(options.sources)) {
    throw new TypeError("sources must be an array");
  }
  if (options.sources !== undefined) {
    if (options.sources.length === 0) {
      throw new TypeError("sources must contain at least one of 'query', 'body', 'params'");
    }
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
  if (options.excludePaths !== undefined) {
    if (!Array.isArray(options.excludePaths)) {
      throw new TypeError("excludePaths must be an array");
    }
    for (const entry of options.excludePaths) {
      if (typeof entry !== "string") {
        throw new TypeError("excludePaths must contain only strings");
      }
    }
  }
  if (options.logger !== undefined && typeof options.logger !== "function") {
    throw new TypeError("logger must be a function");
  }
  if (
    options.onPollutionDetected !== undefined &&
    typeof options.onPollutionDetected !== "function"
  ) {
    throw new TypeError("onPollutionDetected must be a function");
  }
  if (options.strict !== undefined && typeof options.strict !== "boolean") {
    throw new TypeError("strict must be a boolean");
  }
  if (options.logPollution !== undefined && typeof options.logPollution !== "boolean") {
    throw new TypeError("logPollution must be a boolean");
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
      // Read req.path defensively. Some upstream middleware decorates `req`
      // with a `path` getter that throws under specific conditions; if so,
      // that error must NOT propagate as a 500 — exclusion lookup is best
      // effort. On failure, treat the path as unknown (no exclusion match,
      // proceed to process the request normally) and surface a warning via
      // the configured logger so the upstream bug stays visible.
      let pathForExclusion: string | undefined;
      try {
        pathForExclusion = req?.path;
      } catch (pathErr) {
        const message = `[hppx] Failed to read req.path during exclusion check; proceeding without path-based exclusion. Underlying error: ${
          pathErr instanceof Error ? pathErr.message : String(pathErr)
        }`;
        if (logger) {
          try {
            logger(message);
          } catch (_) {
            console.warn(message);
          }
        } else {
          console.warn(message);
        }
        pathForExclusion = undefined;
      }
      if (shouldExcludePath(pathForExclusion, excludePaths)) return next();

      let anyPollutionDetected = false;
      const allPollutedKeys: string[] = [];

      // Per-request, per-source warning de-dup: don't spam the logger if writes fail
      // for both the cleaned source and the polluted-tree property on the same request.
      const warned = new Set<string>();
      const warn = (message: string) => {
        if (warned.has(message)) return;
        warned.add(message);
        if (logger) {
          try {
            logger(message);
          } catch (_) {
            // Logger failed; surface via console as a last-resort signal.
            console.warn(message);
          }
        } else {
          console.warn(message);
        }
      };

      for (const source of sources) {
        /* istanbul ignore next -- defensive: Express always invokes middleware
           with a non-null request object; this guard exists only so the loop
           degrades gracefully if a non-Express harness invokes the middleware
           with a missing/non-object req. */
        if (!req || typeof req !== "object") break;
        if (req[source] === undefined) continue;

        if (source === "body") {
          if (checkBodyContentType === "none") continue;
          if (checkBodyContentType === "urlencoded" && !isUrlEncodedContentType(req)) continue;
        }

        const part = req[source];
        if (!isPlainObject(part)) continue;

        // Preprocess: expand dotted and bracketed keys into nested objects
        const expandedPart = expandObjectPaths(part, maxKeyLength, maxDepth);

        const pollutedKey = `${source}Polluted`;
        const processedKey = `__hppxProcessed_${source}`;
        // Use hasOwnProperty.call to avoid prototype-chain traversal — protects against
        // upstream prototype pollution gadgets that set `Object.prototype.__hppxProcessed_*`.
        const hasProcessedBefore = Object.prototype.hasOwnProperty.call(req, processedKey);

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

          // Express 5 exposes `req.query` only as a getter on the prototype chain (no
          // own descriptor by default), so the standard defineProperty path inside
          // setReqPropertySafe shadows it cleanly. If a downstream framework version
          // ever installs a non-configurable, non-writable descriptor, the helper
          // surfaces a clear warning instead of failing silently.
          setReqPropertySafe(req, source, cleaned, warn);

          // Attach polluted object (always present as {} when source processed)
          setReqPropertySafe(req, pollutedKey, pollutedTree, warn);
          // Mark as processed in a tamper-resistant, non-enumerable way so it is not
          // visible to user code, response serializers, or attackers.
          try {
            Object.defineProperty(req, processedKey, {
              value: true,
              writable: false,
              configurable: false,
              enumerable: false,
            });
          } catch (_) {
            // If req is frozen or defineProperty otherwise fails, fall back to assignment
            // so behavior is at least correct for the current request.
            try {
              req[processedKey] = true;
            } catch (_assignErr) {
              // Last resort: skip; downstream middleware will simply re-process.
            }
          }

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
          // If custom logger fails, surface via console.error so the developer
          // sees their logger bug regardless of NODE_ENV. Using `process.env`
          // directly here would crash in edge runtimes (Cloudflare Workers,
          // Vercel Edge, Deno without Node-compat) where `process` may be
          // undefined or `process.env` may be a throwing Proxy.
          console.error("[hppx] Logger failed:", logErr);
          console.error("[hppx] Original error:", error);
        }
      }

      // Pass error to next middleware for proper error handling
      return next(error);
    }
  };
}

export { DANGEROUS_KEYS, DEFAULT_STRATEGY, DEFAULT_SOURCES };
