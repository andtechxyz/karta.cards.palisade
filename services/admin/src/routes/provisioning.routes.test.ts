import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import 'express-async-errors';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    chipProfile: {
      findMany: vi.fn(),
      findUnique: vi.fn(),
      create: vi.fn(),
      delete: vi.fn(),
    },
    issuerProfile: {
      findMany: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
    },
    provisioningSession: {
      count: vi.fn(),
      findMany: vi.fn(),
    },
  },
}));

vi.mock('@palisade/service-auth', () => ({
  signRequest: vi.fn().mockReturnValue('VeraHmac keyId=admin,ts=0,sig=aa'),
}));

vi.mock('../env.js', () => ({
  getAdminConfig: vi.fn().mockReturnValue({
    ACTIVATION_SERVICE_URL: 'http://localhost:3002',
    SERVICE_AUTH_ADMIN_SECRET: '0'.repeat(64),
  }),
}));

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

import { prisma } from '@palisade/db';
import express from 'express';
import provisioningRouter from './provisioning.routes.js';
import { errorMiddleware } from '@palisade/core';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type Mocked<T> = ReturnType<typeof vi.fn> & T;

const chipFindMany = () => prisma.chipProfile.findMany as unknown as Mocked<typeof prisma.chipProfile.findMany>;
const chipFindUnique = () => prisma.chipProfile.findUnique as unknown as Mocked<typeof prisma.chipProfile.findUnique>;
const chipCreate = () => prisma.chipProfile.create as unknown as Mocked<typeof prisma.chipProfile.create>;
const chipDelete = () => prisma.chipProfile.delete as unknown as Mocked<typeof prisma.chipProfile.delete>;
const issuerFindMany = () => prisma.issuerProfile.findMany as unknown as Mocked<typeof prisma.issuerProfile.findMany>;
const issuerCreate = () => prisma.issuerProfile.create as unknown as Mocked<typeof prisma.issuerProfile.create>;
const issuerUpdate = () => prisma.issuerProfile.update as unknown as Mocked<typeof prisma.issuerProfile.update>;
const sessionCount = () => prisma.provisioningSession.count as unknown as Mocked<typeof prisma.provisioningSession.count>;
const sessionFindMany = () => prisma.provisioningSession.findMany as unknown as Mocked<typeof prisma.provisioningSession.findMany>;

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/admin', provisioningRouter);
  app.use(errorMiddleware);
  return app;
}

import http from 'node:http';

let activeServer: http.Server | null = null;

/** HTTP injection via a real ephemeral server — no supertest dependency. */
async function inject(
  app: express.Express,
  method: string,
  path: string,
  body?: Record<string, unknown>,
): Promise<{ status: number; body: any }> {
  return new Promise<{ status: number; body: any }>((resolve, reject) => {
    const server = http.createServer(app);
    activeServer = server;

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      const url = `http://127.0.0.1:${addr.port}${path}`;
      const bodyStr = body ? JSON.stringify(body) : undefined;

      const req = http.request(url, {
        method,
        headers: {
          'content-type': 'application/json',
          ...(bodyStr ? { 'content-length': String(Buffer.byteLength(bodyStr)) } : {}),
        },
      }, (res) => {
        let data = '';
        res.on('data', (chunk: string) => { data += chunk; });
        res.on('end', () => {
          server.close();
          activeServer = null;
          let parsed: any;
          try { parsed = JSON.parse(data); } catch { parsed = null; }
          resolve({ status: res.statusCode!, body: parsed });
        });
      });
      req.on('error', (err) => { server.close(); activeServer = null; reject(err); });
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  });
}

afterEach(() => {
  if (activeServer) { activeServer.close(); activeServer = null; }
});

beforeEach(() => {
  vi.mocked(chipFindMany()).mockReset();
  vi.mocked(chipFindUnique()).mockReset();
  vi.mocked(chipCreate()).mockReset();
  vi.mocked(chipDelete()).mockReset();
  vi.mocked(issuerFindMany()).mockReset();
  vi.mocked(issuerCreate()).mockReset();
  vi.mocked(issuerUpdate()).mockReset();
  vi.mocked(sessionCount()).mockReset();
  vi.mocked(sessionFindMany()).mockReset();
});

// ---------------------------------------------------------------------------
// Chip Profiles
// ---------------------------------------------------------------------------

describe('GET /api/admin/chip-profiles', () => {
  it('returns array of chip profiles (admin view, no filter)', async () => {
    const profiles = [
      { id: 'cp_1', name: 'JCOP4', scheme: 'visa', vendor: 'NXP', cvn: 18, programId: null, program: null },
      { id: 'cp_2', name: 'ST31', scheme: 'mastercard', vendor: 'ST', cvn: 10, programId: 'prog_1', program: { id: 'prog_1', name: 'Bank A' } },
    ];
    vi.mocked(chipFindMany()).mockResolvedValue(profiles as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/admin/chip-profiles');

    expect(status).toBe(200);
    expect(body).toHaveLength(2);
    expect(body[0].name).toBe('JCOP4');
    expect(chipFindMany()).toHaveBeenCalledWith(
      expect.objectContaining({
        where: undefined,
        include: { program: { select: { id: true, name: true } } },
      }),
    );
  });

  it('filters by programId — scoped + global union', async () => {
    vi.mocked(chipFindMany()).mockResolvedValue([] as never);

    const app = buildApp();
    await inject(app, 'GET', '/api/admin/chip-profiles?programId=prog_1');

    expect(chipFindMany()).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { OR: [{ programId: 'prog_1' }, { programId: null }] },
        include: { program: { select: { id: true, name: true } } },
      }),
    );
  });
});

describe('POST /api/admin/chip-profiles', () => {
  it('creates and returns a chip profile on valid data', async () => {
    const input = {
      name: 'JCOP5',
      scheme: 'visa',
      vendor: 'NXP',
      cvn: 18,
      dgiDefinitions: { tag9f27: '80' },
    };
    vi.mocked(chipCreate()).mockResolvedValue({ id: 'cp_new', ...input } as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/admin/chip-profiles', input);

    expect(status).toBe(201);
    expect(body.id).toBe('cp_new');
    expect(body.name).toBe('JCOP5');
  });

  it('400 validation_failed when required fields are missing', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/admin/chip-profiles', {
      name: 'Incomplete',
      // missing scheme, vendor, cvn
    });

    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });
});

describe('DELETE /api/admin/chip-profiles/:id', () => {
  it('deletes the chip profile and returns { deleted: true }', async () => {
    vi.mocked(chipDelete()).mockResolvedValue({} as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'DELETE', '/api/admin/chip-profiles/cp_1');

    expect(status).toBe(200);
    expect(body).toEqual({ deleted: true });
    expect(chipDelete()).toHaveBeenCalledWith({ where: { id: 'cp_1' } });
  });

  it('404 when chip profile does not exist', async () => {
    vi.mocked(chipDelete()).mockRejectedValue(new Error('Record not found'));

    const app = buildApp();
    const { status, body } = await inject(app, 'DELETE', '/api/admin/chip-profiles/cp_missing');

    expect(status).toBe(404);
    expect(body.error.code).toBe('chip_profile_not_found');
  });
});

// ---------------------------------------------------------------------------
// Issuer Profiles
// ---------------------------------------------------------------------------

describe('GET /api/admin/issuer-profiles', () => {
  it('returns array of issuer profiles with program and chipProfile includes', async () => {
    const profiles = [
      {
        id: 'ip_1',
        programId: 'prog_1',
        chipProfileId: 'cp_1',
        scheme: 'visa',
        cvn: 18,
        program: { id: 'prog_1', name: 'Program A' },
        chipProfile: { id: 'cp_1', name: 'JCOP4' },
      },
    ];
    vi.mocked(issuerFindMany()).mockResolvedValue(profiles as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/admin/issuer-profiles');

    expect(status).toBe(200);
    expect(body).toHaveLength(1);
    expect(body[0].program.name).toBe('Program A');
  });
});

describe('POST /api/admin/issuer-profiles', () => {
  it('creates an issuer profile', async () => {
    const input = {
      programId: 'prog_1',
      chipProfileId: 'cp_1',
      scheme: 'visa',
      cvn: 18,
    };
    vi.mocked(issuerCreate()).mockResolvedValue({ id: 'ip_new', ...input } as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/admin/issuer-profiles', input);

    expect(status).toBe(201);
    expect(body.id).toBe('ip_new');
  });
});

describe('PATCH /api/admin/issuer-profiles/:id', () => {
  it('updates an issuer profile', async () => {
    vi.mocked(issuerUpdate()).mockResolvedValue({
      id: 'ip_1',
      scheme: 'mastercard',
    } as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/admin/issuer-profiles/ip_1', {
      scheme: 'mastercard',
    });

    expect(status).toBe(200);
    expect(body.scheme).toBe('mastercard');
  });

  it('404 when issuer profile does not exist', async () => {
    vi.mocked(issuerUpdate()).mockRejectedValue(new Error('Record not found'));

    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/admin/issuer-profiles/ip_missing', {
      scheme: 'visa',
    });

    expect(status).toBe(404);
    expect(body.error.code).toBe('issuer_profile_not_found');
  });

  it('400 when no fields are supplied', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/admin/issuer-profiles/ip_1', {});

    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });
});

// ---------------------------------------------------------------------------
// Provisioning Monitor
// ---------------------------------------------------------------------------

describe('GET /api/admin/provisioning/stats', () => {
  it('returns aggregated stats', async () => {
    vi.mocked(sessionCount())
      .mockResolvedValueOnce(3 as never)   // activeSessions
      .mockResolvedValueOnce(12 as never)  // provisioned24h
      .mockResolvedValueOnce(100 as never) // totalProvisioned
      .mockResolvedValueOnce(2 as never);  // failedSessions24h

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/admin/provisioning/stats');

    expect(status).toBe(200);
    expect(body).toEqual({
      activeSessions: 3,
      provisioned24h: 12,
      totalProvisioned: 100,
      failedSessions24h: 2,
    });
    // All four counts should have been called
    expect(sessionCount()).toHaveBeenCalledTimes(4);
  });
});

describe('GET /api/admin/provisioning/sessions', () => {
  it('returns paginated sessions', async () => {
    const sessions = [
      { id: 'ps_1', phase: 'COMPLETE', card: { id: 'c1', cardRef: 'ref_1', status: 'PROVISIONED' }, sadRecord: null },
      { id: 'ps_2', phase: 'INIT', card: { id: 'c2', cardRef: 'ref_2', status: 'ACTIVATED' }, sadRecord: null },
    ];
    vi.mocked(sessionFindMany()).mockResolvedValue(sessions as never);

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/admin/provisioning/sessions');

    expect(status).toBe(200);
    expect(body).toHaveLength(2);
    expect(body[0].phase).toBe('COMPLETE');
  });

  it('respects limit and offset query params', async () => {
    vi.mocked(sessionFindMany()).mockResolvedValue([] as never);

    const app = buildApp();
    await inject(app, 'GET', '/api/admin/provisioning/sessions?limit=10&offset=5');

    expect(sessionFindMany()).toHaveBeenCalledWith(
      expect.objectContaining({
        take: 10,
        skip: 5,
      }),
    );
  });

  it('caps limit at 200', async () => {
    vi.mocked(sessionFindMany()).mockResolvedValue([] as never);

    const app = buildApp();
    await inject(app, 'GET', '/api/admin/provisioning/sessions?limit=999');

    expect(sessionFindMany()).toHaveBeenCalledWith(
      expect.objectContaining({
        take: 200,
      }),
    );
  });
});
