# Changelog

## v0.1.5 (CommonJS Default Export Fix)

- **Fixed:** CommonJS default export now works correctly without requiring `.default`
- **Enhanced:** Added esbuild footer to properly merge default and named exports in CommonJS
- **Note:** Users can now use `require("hppx")()` directly instead of `require("hppx").default()`

## v0.1.4 (CommonJS Support & Pollution Logging)

- **Added:** Basic CommonJS support with `cjsInterop: true`
- **Added:** Automatic logging when pollution is detected (default: enabled)
- **Added:** `logPollution` option to control pollution logging (default: true)
- **Enhanced:** Logger now handles both errors and pollution warnings
- **Documentation:** Added CommonJS examples throughout README
- **Documentation:** Added custom logging examples

## v0.1.3 (Build Configuration Fix)

- **Fixed:** Build configuration to generate correct file extensions (.mjs for ESM, .cjs for CJS)
- **Fixed:** Module resolution errors when importing the package
- **Changed:** Updated tsup config to use `outExtension` for proper file naming
- **Testing:** All 81 tests passing with 97.09% statement coverage

## v0.1.2 (Changelog Added)

- **Added:** CHANGELOG.md to keep track of changes

## v0.1.1 (Security & Performance Update)

- **Security Enhancements:**
  - Added `maxArrayLength` to prevent memory exhaustion attacks
  - Added `maxKeyLength` to prevent long key DoS attacks
  - Enhanced prototype pollution protection in nested operations
  - Fixed validation of malformed keys (null bytes, bracket/dot-only keys)
  - Added comprehensive options validation with helpful error messages
- **Bug Fixes:**
  - Fixed `onPollutionDetected` callback receiving correct source information
  - Improved error handling with proper error propagation
- **Performance:**
  - Added path caching for faster whitelist checks
  - Added path segment caching to reduce parsing overhead
  - Optimized repeated sanitization operations
- **Developer Experience:**
  - Improved TypeScript types and removed unnecessary `any` types
  - Enhanced error messages and logging
  - Added comprehensive test suite for security features
