/**
 * SFTP service entrypoint — runs the ingester poll loop.
 *
 * sshd is supervised alongside this process by the container's entrypoint.sh,
 * not by this Node process.  If the ingester crashes, ECS restarts the
 * whole task (sshd is taken down with it), so there's no risk of partners
 * uploading into a silent black hole.
 */
import 'dotenv/config';

import { getSftpConfig } from './env.js';
import { scanOnce } from './ingester.js';

const config = getSftpConfig();

let running = false;
async function tick(): Promise<void> {
  if (running) return; // skip if previous scan still in flight
  running = true;
  try {
    await scanOnce();
  } catch (err) {
    console.error(
      '[sftp-ingester] scan error:',
      err instanceof Error ? err.message : err,
    );
  } finally {
    running = false;
  }
}

setInterval(tick, config.SFTP_POLL_INTERVAL_MS);
// First tick after a short delay so the SFTP daemon has started and user
// dirs are materialised before we scan.
setTimeout(tick, 3000);

console.log(
  `[sftp-ingester] polling every ${config.SFTP_POLL_INTERVAL_MS}ms from ${config.SFTP_HOME_BASE}`,
);
