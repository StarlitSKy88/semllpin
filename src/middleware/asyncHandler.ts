import { Request, Response, NextFunction } from 'express';

/**
 * Async handler middleware to catch and forward async errors
 * This eliminates the need to wrap every async route handler in try-catch
 */
export const asyncHandler = (fn: Function) => 
  (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };

export default asyncHandler;