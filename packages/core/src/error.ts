import type { NextFunction, Request, Response } from 'express';
import { ZodError } from 'zod';

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export const badRequest = (code: string, message: string, details?: unknown) =>
  new ApiError(400, code, message, details);

export const notFound = (code: string, message: string) =>
  new ApiError(404, code, message);

export const conflict = (code: string, message: string, details?: unknown) =>
  new ApiError(409, code, message, details);

export const gone = (code: string, message: string) => new ApiError(410, code, message);

export const unauthorized = (code: string, message: string) =>
  new ApiError(401, code, message);

export const forbidden = (code: string, message: string) =>
  new ApiError(403, code, message);

export const internal = (code: string, message: string, details?: unknown) =>
  new ApiError(500, code, message, details);

/**
 * Express error middleware — MUST be registered after all routes.
 */
export function errorMiddleware(
  err: unknown,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  if (err instanceof ApiError) {
    // Server-side log includes path + code + internal details (for audit).
    // Client-side response deliberately omits `details` to avoid leaking
    // internal schema / field names / regex shapes to probing attackers
    // (PCI 6.2.4 / 10.2).
    // eslint-disable-next-line no-console
    console.log(
      `[err] ${req.method} ${req.path} ApiError ${err.status} ${err.code}: ${err.message}` +
        (err.details ? ` details=${JSON.stringify(err.details).slice(0, 500)}` : ''),
    );
    res.status(err.status).json({
      error: { code: err.code, message: err.message },
    });
    return;
  }
  if (err instanceof ZodError) {
    // ZodError `issues` contain field names + expected types + regex shapes
    // which are useful to a probing attacker.  Log server-side, return a
    // generic error to the client.
    const issuePaths = err.issues.map((i) => i.path.join('.') || '<root>').join(',');
    // eslint-disable-next-line no-console
    console.log(
      `[err] ${req.method} ${req.path} ZodError 400 validation_failed paths=[${issuePaths}]`,
    );
    res.status(400).json({
      error: {
        code: 'validation_failed',
        message: 'Request failed validation',
      },
    });
    return;
  }
  const msg = err instanceof Error ? err.message : String(err);
  // eslint-disable-next-line no-console
  console.error(`[unhandled] ${req.method} ${req.path}:`, msg);
  res.status(500).json({
    error: { code: 'internal_error', message: 'Internal server error' },
  });
}
