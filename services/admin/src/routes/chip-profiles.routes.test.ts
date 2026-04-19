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
      update: vi.fn(),
    },
  },
}));

vi.mock('@palisade/cognito-auth', () => ({
  createCognitoAuthMiddleware: vi.fn(() => {
    return (req: import('express').Request, res: import('express').Response, next: import('express').NextFunction) => {
      const role = req.headers['x-test-role'];
      if (role !== 'admin') {
        res.status(403).json({ error: { code: 'forbidden', message: 'admin group required' } });
        return;
      }
      next();
    };
  }),
}));

import { prisma } from '@palisade/db';
import express from 'express';
import http from 'node:http';
import chipProfilesRouter from './chip-profiles.routes.js';
import { createCognitoAuthMiddleware } from '@palisade/cognito-auth';
import { errorMiddleware } from '@palisade/core';

function buildApp(withAuth = false) {
  const app = express();
  app.use(express.json());
  if (withAuth) {
    const guard = createCognitoAuthMiddleware({
      userPoolId: 'pool',
      clientId: 'client',
      requiredGroup: 'admin',
    });
    app.use('/api/chip-profiles', guard, chipProfilesRouter);
  } else {
    app.use('/api/chip-profiles', chipProfilesRouter);
  }
  app.use(errorMiddleware);
  return app;
}

let activeServer: http.Server | null = null;

async function inject(
  app: express.Express,
  method: string,
  path: string,
  body?: Record<string, unknown> | string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    activeServer = server;
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      const url = `http://127.0.0.1:${addr.port}${path}`;
      const bodyStr =
        typeof body === 'string' ? body : body ? JSON.stringify(body) : undefined;
      const isRawString = typeof body === 'string';
      const req = http.request(
        url,
        {
          method,
          headers: {
            ...(isRawString ? {} : { 'content-type': 'application/json' }),
            ...(bodyStr ? { 'content-length': String(Buffer.byteLength(bodyStr)) } : {}),
            ...headers,
          },
        },
        (res) => {
          let data = '';
          res.on('data', (c: string) => { data += c; });
          res.on('end', () => {
            server.close();
            activeServer = null;
            let parsed: any = null;
            try { parsed = data ? JSON.parse(data) : null; } catch { parsed = data; }
            resolve({ status: res.statusCode!, body: parsed });
          });
        },
      );
      req.on('error', (e) => { server.close(); activeServer = null; reject(e); });
      if (bodyStr) req.write(bodyStr);
      req.end();
    });
  });
}

afterEach(() => {
  if (activeServer) { activeServer.close(); activeServer = null; }
});

beforeEach(() => {
  vi.resetAllMocks();
});

const findMany = () => prisma.chipProfile.findMany as unknown as ReturnType<typeof vi.fn>;
const findUnique = () => prisma.chipProfile.findUnique as unknown as ReturnType<typeof vi.fn>;
const create = () => prisma.chipProfile.create as unknown as ReturnType<typeof vi.fn>;
const update = () => prisma.chipProfile.update as unknown as ReturnType<typeof vi.fn>;

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

describe('auth', () => {
  it('returns 403 when the caller is not in the admin group', async () => {
    const app = buildApp(true);
    const { status, body } = await inject(app, 'GET', '/api/chip-profiles');
    expect(status).toBe(403);
    expect(body.error.code).toBe('forbidden');
  });
});

// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

describe('GET /api/chip-profiles', () => {
  it('returns full list with program include', async () => {
    findMany().mockResolvedValue([
      { id: 'cp_1', name: 'JCOP4', scheme: 'mchip_advance', vendor: 'nxp', cvn: 18, program: null },
    ]);
    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/chip-profiles');
    expect(status).toBe(200);
    expect(body).toHaveLength(1);
    expect(body[0].name).toBe('JCOP4');
    expect(findMany()).toHaveBeenCalledWith(
      expect.objectContaining({ where: undefined }),
    );
  });

  it('filters by programId (scoped + global union)', async () => {
    findMany().mockResolvedValue([]);
    const app = buildApp();
    await inject(app, 'GET', '/api/chip-profiles?programId=prog_1');
    expect(findMany()).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { OR: [{ programId: 'prog_1' }, { programId: null }] },
      }),
    );
  });
});

describe('GET /api/chip-profiles/:id', () => {
  it('returns profile when found', async () => {
    findUnique().mockResolvedValue({ id: 'cp_1', name: 'JCOP4', program: null });
    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/chip-profiles/cp_1');
    expect(status).toBe(200);
    expect(body.name).toBe('JCOP4');
  });

  it('404 when missing', async () => {
    findUnique().mockResolvedValue(null);
    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/chip-profiles/missing');
    expect(status).toBe(404);
    expect(body.error.code).toBe('chip_profile_not_found');
  });
});

// ---------------------------------------------------------------------------
// POST
// ---------------------------------------------------------------------------

describe('POST /api/chip-profiles (JSON body)', () => {
  it('creates a chip profile and canonicalises DGI entries', async () => {
    create().mockResolvedValue({ id: 'cp_new' });
    const app = buildApp();
    const input = {
      name: 'JCOP5',
      scheme: 'mchip_advance',
      vendor: 'nxp',
      cvn: 18,
      dgiDefinitions: [
        // camelCase (older upload) gets folded to snake_case
        { dgiNumber: 2048, name: 'MK-AC', tags: [], mandatory: true, source: 'per_card' },
      ],
    };
    const { status, body } = await inject(app, 'POST', '/api/chip-profiles', input);
    expect(status).toBe(201);
    expect(body.id).toBe('cp_new');
    const dataArg = create().mock.calls[0][0].data;
    expect(dataArg.dgiDefinitions[0]).toEqual({
      dgi_number: 2048,
      name: 'MK-AC',
      tags: [],
      mandatory: true,
      source: 'per_card',
    });
  });

  it('400 validation_failed when required fields are missing', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/chip-profiles', {
      name: 'no scheme',
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('400 when dgiDefinitions is empty', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/chip-profiles', {
      name: 'n',
      scheme: 'vsdc',
      vendor: 'nxp',
      cvn: 10,
      dgiDefinitions: [],
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('rejects unknown top-level fields (strict)', async () => {
    const app = buildApp();
    const { status } = await inject(app, 'POST', '/api/chip-profiles', {
      name: 'n',
      scheme: 'vsdc',
      vendor: 'nxp',
      cvn: 10,
      dgiDefinitions: [
        { dgi_number: 1, name: 'x', tags: [], mandatory: true, source: 'per_profile' },
      ],
      trojan: 'nope',
    });
    expect(status).toBe(400);
  });
});

describe('POST /api/chip-profiles (multipart upload)', () => {
  it('accepts a JSON file in a multipart request', async () => {
    create().mockResolvedValue({ id: 'cp_upload' });
    const boundary = 'TestBoundary123';
    const fileContent = JSON.stringify({
      name: 'UploadedProfile',
      scheme: 'mchip_advance',
      vendor: 'nxp',
      cvn: 18,
      dgiDefinitions: [
        { dgi_number: 32513, name: 'FCI', tags: [80], mandatory: true, source: 'per_profile' },
      ],
    });
    const raw = [
      `--${boundary}`,
      'Content-Disposition: form-data; name="file"; filename="profile.json"',
      'Content-Type: application/json',
      '',
      fileContent,
      `--${boundary}--`,
      '',
    ].join('\r\n');

    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/chip-profiles', raw, {
      'content-type': `multipart/form-data; boundary=${boundary}`,
    });
    expect(status).toBe(201);
    expect(body.id).toBe('cp_upload');
  });

  it('400 missing_file when the multipart body has no file part', async () => {
    const boundary = 'TestBoundary123';
    const raw = [
      `--${boundary}`,
      'Content-Disposition: form-data; name="other"',
      '',
      'unused',
      `--${boundary}--`,
      '',
    ].join('\r\n');
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/chip-profiles', raw, {
      'content-type': `multipart/form-data; boundary=${boundary}`,
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe('missing_file');
  });

  it('400 invalid_json when the multipart file is not JSON', async () => {
    const boundary = 'TestBoundary123';
    const raw = [
      `--${boundary}`,
      'Content-Disposition: form-data; name="file"; filename="profile.json"',
      '',
      'this is not json at all',
      `--${boundary}--`,
      '',
    ].join('\r\n');
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/chip-profiles', raw, {
      'content-type': `multipart/form-data; boundary=${boundary}`,
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe('invalid_json');
  });
});

// ---------------------------------------------------------------------------
// PATCH
// ---------------------------------------------------------------------------

describe('PATCH /api/chip-profiles/:id', () => {
  it('updates fields in place', async () => {
    update().mockResolvedValue({ id: 'cp_1', name: 'Renamed' });
    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/chip-profiles/cp_1', {
      name: 'Renamed',
    });
    expect(status).toBe(200);
    expect(body.name).toBe('Renamed');
  });

  it('400 when body is empty', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/chip-profiles/cp_1', {});
    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('404 when profile does not exist', async () => {
    update().mockRejectedValue({ code: 'P2025' });
    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/chip-profiles/missing', {
      name: 'x',
    });
    expect(status).toBe(404);
    expect(body.error.code).toBe('chip_profile_not_found');
  });
});
