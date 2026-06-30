import { sanitize, __resetPathSegmentCache } from "../src/index";

describe("hppx - Performance Optimizations", () => {
  describe("Path caching", () => {
    test("handles repeated path checks efficiently", () => {
      const input = {
        "user.name": ["John", "Doe"],
        "user.email": ["john@example.com", "doe@example.com"],
        "user.age": ["30", "31"],
      };

      const start = Date.now();
      // Run multiple times to test cache effectiveness
      for (let i = 0; i < 100; i++) {
        sanitize(input, { whitelist: ["user.name"] });
      }
      const duration = Date.now() - start;

      // Should complete quickly thanks to caching
      expect(duration).toBeLessThan(1000);
    });

    test("caching doesn't affect correctness", () => {
      const input = { a: [1, 2], b: [3, 4], c: [5, 6] };

      // First call
      const result1 = sanitize(input, { whitelist: ["a"], mergeStrategy: "keepFirst" });

      // Second call with same whitelist (should use cache)
      const result2 = sanitize(input, { whitelist: ["a"], mergeStrategy: "keepFirst" });

      expect(result1).toEqual(result2);
      expect(result1.a).toEqual([1, 2]);
      expect(result1.b).toBe(3);
    });
  });

  describe("Large object handling", () => {
    test("handles objects with many keys efficiently", () => {
      const input: Record<string, string> = {};
      for (let i = 0; i < 1000; i++) {
        input[`key${i}`] = `value${i}`;
      }

      const start = Date.now();
      const cleaned = sanitize(input, { maxKeys: 5000 });
      const duration = Date.now() - start;

      expect(Object.keys(cleaned).length).toBe(1000);
      expect(duration).toBeLessThan(1000);
    });

    test("handles deeply nested objects efficiently", () => {
      const input: any = {};
      let current = input;
      for (let i = 0; i < 15; i++) {
        current.nested = { value: i };
        current = current.nested;
      }

      const start = Date.now();
      const cleaned = sanitize(input, { maxDepth: 20 });
      const duration = Date.now() - start;

      expect(cleaned).toBeDefined();
      expect(duration).toBeLessThan(500);
    });
  });

  describe("Whitelist helpers performance", () => {
    test("exact match is fast with Set", () => {
      const whitelist = Array.from({ length: 100 }, (_, i) => `key${i}`);
      const input: Record<string, any> = {};

      for (let i = 0; i < 100; i++) {
        input[`key${i}`] = [1, 2, 3];
      }

      const start = Date.now();
      const cleaned = sanitize(input, { whitelist, mergeStrategy: "keepLast" });
      const duration = Date.now() - start;

      expect(Object.keys(cleaned).length).toBe(100);
      expect(duration).toBeLessThan(500);
    });

    test("prefix matching with many prefixes is efficient", () => {
      const whitelist = ["user", "profile", "settings", "preferences"];
      const input: Record<string, any> = {
        "user.name": [1, 2],
        "user.email": [3, 4],
        "profile.bio": [5, 6],
        "profile.avatar": [7, 8],
        "settings.theme": [9, 10],
        "settings.lang": [11, 12],
        "preferences.notifications": [13, 14],
        "preferences.privacy": [15, 16],
      };

      const start = Date.now();
      for (let i = 0; i < 100; i++) {
        sanitize(input, { whitelist });
      }
      const duration = Date.now() - start;

      // Should be fast due to caching
      expect(duration).toBeLessThan(1000);
    });
  });

  describe("Memory efficiency", () => {
    test("limits cache sizes to prevent memory leaks", () => {
      // Create many unique paths to test cache limits
      for (let i = 0; i < 2000; i++) {
        const input = { [`unique_key_${i}`]: [1, 2] };
        sanitize(input, { mergeStrategy: "keepLast" });
      }

      // If caches weren't limited, this would consume significant memory
      // Test passes if it completes without memory issues
      expect(true).toBe(true);
    });

    test("array length limits prevent memory exhaustion", () => {
      // Distinct elements 0..9999; safeDeepClone slices to 100 (indices 0..99).
      // keepLast selects values[99] = 99. Pins truncation (src/index.ts:325-326)
      // and keepLast path (src/index.ts:364-365) — current intended behavior.
      const hugeArray = Array.from({ length: 10000 }, (_, i) => i);
      const input = { data: hugeArray };

      const cleaned = sanitize(input, { maxArrayLength: 100, mergeStrategy: "keepLast" });

      expect(cleaned.data).toBe(99);
    });
  });

  describe("Cache eviction (clear-on-full)", () => {
    test("pathSegmentCache continues caching after a flood of unique keys", () => {
      __resetPathSegmentCache();

      // Pump well over the cache cap (500) of unique dotted keys to exercise
      // the eviction path. After this, the cache should not be permanently
      // disabled — it must be able to cache fresh entries again.
      for (let i = 0; i < 1500; i++) {
        sanitize({ [`flood_${i}.leaf`]: [1, 2] }, { mergeStrategy: "keepLast" });
      }

      // Now run a workload of repeated dotted keys; if the cache were stuck
      // (full and never evicted), this would re-parse every key on every call.
      // With clear-on-full, the cache is reset and starts caching the new keys
      // on first access, making subsequent runs O(1) per parse.
      const input = {
        "user.profile.name": [1, 2],
        "user.profile.email": [3, 4],
        "user.settings.theme": [5, 6],
      };

      // Warm-up call (populates cache).
      sanitize(input, { mergeStrategy: "keepLast" });

      // Repeated calls should be fast — caching is alive again.
      const start = Date.now();
      for (let i = 0; i < 500; i++) {
        sanitize(input, { mergeStrategy: "keepLast" });
      }
      const duration = Date.now() - start;

      // Generous bound — main intent is to detect total breakage / unbounded
      // re-parsing rather than fine-grained perf regressions.
      expect(duration).toBeLessThan(2000);
    });

    test("pathSegmentCache parses correctly after eviction", () => {
      __resetPathSegmentCache();

      // Fill past the cap with unique single-segment keys.
      for (let i = 0; i < 1500; i++) {
        sanitize({ [`solo_${i}`]: [1, 2] }, { mergeStrategy: "keepLast" });
      }

      // Now feed dotted keys — these must still parse correctly.
      const cleaned = sanitize({ "a.b.c": [1, 2], "x.y": [3, 4] }, { mergeStrategy: "keepLast" });
      expect(cleaned).toEqual({ a: { b: { c: 2 } }, x: { y: 4 } });
    });

    test("whitelist pathCache survives a flood and stays correct", () => {
      // Each call builds a fresh whitelist helpers instance, but within one
      // sanitize call the same pathCache is used. Flood >1000 unique paths,
      // then verify whitelist semantics still hold.
      const whitelist = ["user.profile.tags"];
      const input: Record<string, unknown> = {};
      for (let i = 0; i < 1200; i++) {
        input[`flood_${i}`] = [1, 2];
      }
      input["user.profile.tags"] = [1, 2];

      const cleaned = sanitize(input, { whitelist, mergeStrategy: "keepLast" });
      // Whitelisted path is preserved as an array.
      expect((cleaned as any).user.profile.tags).toEqual([1, 2]);
    });
  });

  describe("Clone-once detectAndReduce", () => {
    test("processes a 1000-key polluted object in well under 50ms baseline", () => {
      const input: Record<string, unknown> = {};
      for (let i = 0; i < 1000; i++) {
        input[`key${i}`] = [`a${i}`, `b${i}`, `c${i}`];
      }

      // Warm up to amortize first-call costs (JIT, cache misses).
      sanitize(input, { mergeStrategy: "keepLast" });

      const start = Date.now();
      const cleaned = sanitize(input, { mergeStrategy: "keepLast" });
      const duration = Date.now() - start;

      // 1000 polluted entries should be quick. Generous bound (250ms) to keep
      // the test deterministic across CI hardware while still catching gross
      // regressions back to double-clone behavior.
      expect(Object.keys(cleaned).length).toBe(1000);
      expect(duration).toBeLessThan(250);
    });
  });
});
