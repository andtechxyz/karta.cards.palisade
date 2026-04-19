import type { NextFunction, Request, Response } from 'express';
import type { ZodSchema } from 'zod';

/**
 * Validates `req.body` against the given zod schema and replaces it with the
 * parsed result.  Throws ZodError on failure which is caught by errorMiddleware.
 */
export function validateBody<T>(schema: ZodSchema<T>) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    req.body = schema.parse(req.body);
    next();
  };
}

export function validateQuery<T>(schema: ZodSchema<T>) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    (req as Request & { validatedQuery: T }).validatedQuery = schema.parse(req.query);
    next();
  };
}
