import "express-serve-static-core";

declare module "express-serve-static-core" {
  interface Request {
    queryPolluted?: Record<string, unknown>;
    bodyPolluted?: Record<string, unknown>;
    paramsPolluted?: Record<string, unknown>;
  }
}
