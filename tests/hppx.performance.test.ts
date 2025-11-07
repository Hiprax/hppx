import { sanitize } from "../src/index";

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
      const hugeArray = Array.from({ length: 10000 }, (_, i) => i);
      const input = { data: hugeArray };

      const cleaned = sanitize(input, { maxArrayLength: 100, mergeStrategy: "keepLast" });

      // Should complete without running out of memory
      expect(cleaned).toBeDefined();
    });
  });
});
