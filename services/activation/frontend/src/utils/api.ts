// Minimal fetch wrapper.  Everything lives under /api and is served from the
// same origin (Vite proxies to localhost:3000 in dev; Cloudflare Tunnel
// collapses front+back into pay.karta.cards in the demo).

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const raw = await res.text();
  const data = raw ? JSON.parse(raw) : undefined;
  if (!res.ok) {
    throw new ApiError(
      res.status,
      data?.error?.code ?? 'unknown_error',
      data?.error?.message ?? res.statusText,
      data,
    );
  }
  return data as T;
}

export const api = {
  get: <T>(p: string) => request<T>('GET', p),
  post: <T>(p: string, body?: unknown) => request<T>('POST', p, body),
  patch: <T>(p: string, body?: unknown) => request<T>('PATCH', p, body),
};

/** Format an error from `request()` (or any throw) for human display. */
export function errorMsg(e: unknown): string {
  if (e instanceof ApiError) return `${e.code}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}
