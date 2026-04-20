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

export const internal = (code: string, message: string, details?: unknown) =>
  new ApiError(500, code, message, details);

/**
 * Express error middleware — MUST be registered after all routes.
 */
export function errorMiddleware(
  err: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void {
  if (err instanceof ApiError) {
    // eslint-disable-next-line no-console
    console.log(`[err] ApiError ${err.status} ${err.code}: ${err.message}`);
    res.status(err.status).json({
      error: { code: err.code, message: err.message, details: err.details ?? undefined },
    });
    return;
  }
  if (err instanceof ZodError) {
    // eslint-disable-next-line no-console
    console.log(`[err] ZodError 400 validation_failed: ${JSON.stringify(err.issues).slice(0, 500)}`);
    res.status(400).json({
      error: {
        code: 'validation_failed',
        message: 'Request failed validation',
        details: err.issues,
      },
    });
    return;
  }
  const msg = err instanceof Error ? err.message : String(err);
  // eslint-disable-next-line no-console
  console.error('[unhandled]', msg);
  res.status(500).json({
    error: { code: 'internal_error', message: 'Internal server error' },
  });
}
