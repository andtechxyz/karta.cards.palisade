/**
 * batch-processor — polls EmbossingBatch rows in RECEIVED status, parses
 * each via the registered parser, and routes records to activation's
 * registerCard endpoint.
 *
 * Internal service, port 3008. Exposes /api/health for ALB.
 */

import 'dotenv/config';
import 'express-async-errors';
import express from 'express';

import { getBatchConfig } from './env.js';
import { pollOnce } from './processor.js';

const config = getBatchConfig();
const app = express();

app.set('trust proxy', 1);

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'batch-processor' });
});

app.listen(config.PORT, () => {
  console.log(`[batch-processor] listening on :${config.PORT}`);
});

// ---------------------------------------------------------------------------
// Polling loop
// ---------------------------------------------------------------------------

let running = false;
async function tick(): Promise<void> {
  if (running) return; // skip if previous tick still in progress
  running = true;
  try {
    await pollOnce();
  } catch (err) {
    console.error('[batch-processor] poll error:', err instanceof Error ? err.message : err);
  } finally {
    running = false;
  }
}

setInterval(tick, config.POLL_INTERVAL_MS);
// Kick off the first tick ~3 sec after startup so health check can stabilise.
setTimeout(tick, 3000);
