import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type Express } from 'express';

/**
 * In production Docker images the Vite-built frontend lives at
 * `services/<svc>/frontend/dist/`.  This helper mounts it as static files
 * and adds a catch-all that serves `index.html` for client-side routing.
 *
 * In dev (or when the directory doesn't exist) it's a no-op.
 *
 * Call **after** all API routes but **before** `errorMiddleware` so that
 * `/api/*` 404s still hit the error handler rather than serving the SPA.
 */
export function serveFrontend(app: Express, serviceDir: string): void {
  // serviceDir is import.meta.url of the service's index.ts — resolve
  // from there to the built frontend.
  const base = dirname(fileURLToPath(serviceDir));
  // In compiled output (dist/index.js) the frontend is at ../frontend/dist
  const frontendDist = join(base, '..', 'frontend', 'dist');
  if (!existsSync(frontendDist)) return;

  // Ensure .well-known/apple-app-site-association is served as JSON so iOS
  // Universal Links picks it up without a file extension.
  app.get('/.well-known/apple-app-site-association', (_req, res, next) => {
    res.type('application/json');
    next();
  });

  app.use(express.static(frontendDist, { index: 'index.html' }));

  // SPA catch-all: any non-API GET that didn't match a static file gets
  // index.html so react-router can handle the route client-side.
  app.get(/^\/(?!api\/).*/, (_req, res) => {
    res.sendFile(join(frontendDist, 'index.html'));
  });

  // eslint-disable-next-line no-console
  console.log(`  serving frontend from ${frontendDist}`);
}
