import { describe, it, expect, vi, afterEach } from 'vitest';
import { NoopMetricsClient } from './noop-backend.js';

describe('NoopMetricsClient', () => {
  const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  const consoleInfoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
  const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

  afterEach(() => {
    consoleLogSpy.mockClear();
    consoleInfoSpy.mockClear();
    consoleWarnSpy.mockClear();
    consoleErrorSpy.mockClear();
  });

  it('counter() writes nothing to any console stream', () => {
    const client = new NoopMetricsClient();
    client.counter('hits', 5, { route: '/x' });
    expect(consoleLogSpy).not.toHaveBeenCalled();
    expect(consoleInfoSpy).not.toHaveBeenCalled();
    expect(consoleWarnSpy).not.toHaveBeenCalled();
    expect(consoleErrorSpy).not.toHaveBeenCalled();
  });

  it('gauge() writes nothing to any console stream', () => {
    const client = new NoopMetricsClient();
    client.gauge('depth', 42);
    expect(consoleLogSpy).not.toHaveBeenCalled();
    expect(consoleErrorSpy).not.toHaveBeenCalled();
  });

  it('timing() writes nothing to any console stream', () => {
    const client = new NoopMetricsClient();
    client.timing('lat', 15);
    expect(consoleLogSpy).not.toHaveBeenCalled();
    expect(consoleErrorSpy).not.toHaveBeenCalled();
  });

  it('flush() resolves without writing anything', async () => {
    const client = new NoopMetricsClient();
    client.counter('a');
    client.gauge('b', 1);
    client.timing('c', 1);
    await expect(client.flush()).resolves.toBeUndefined();
    expect(consoleLogSpy).not.toHaveBeenCalled();
  });
});
