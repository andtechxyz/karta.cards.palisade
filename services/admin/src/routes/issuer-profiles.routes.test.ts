import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import 'express-async-errors';

// ---------------------------------------------------------------------------
// Mocks — only the prisma surface this router touches.
// ---------------------------------------------------------------------------

vi.mock('@palisade/db', () => ({
  prisma: {
    issuerProfile: {
      findMany: vi.fn(),
      findUnique: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
    },
  },
}));

// Cognito auth middleware — test every 403 path without pulling a
// real JWT verifier in.  The middleware is replaced with a thin
// wrapper that inspects `x-test-role`: "admin" passes, anything
// else returns 403.
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
import issuerProfilesRouter from './issuer-profiles.routes.js';
import { createCognitoAuthMiddleware } from '@palisade/cognito-auth';
import { errorMiddleware } from '@palisade/core';

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

function buildApp(withAuth = false) {
  const app = express();
  app.use(express.json());
  if (withAuth) {
    const guard = createCognitoAuthMiddleware({
      userPoolId: 'pool',
      clientId: 'client',
      requiredGroup: 'admin',
    });
    app.use('/api/issuer-profiles', guard, issuerProfilesRouter);
  } else {
    app.use('/api/issuer-profiles', issuerProfilesRouter);
  }
  app.use(errorMiddleware);
  return app;
}

let activeServer: http.Server | null = null;

async function inject(
  app: express.Express,
  method: string,
  path: string,
  body?: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    activeServer = server;
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      const url = `http://127.0.0.1:${addr.port}${path}`;
      const bodyStr = body ? JSON.stringify(body) : undefined;
      const req = http.request(
        url,
        {
          method,
          headers: {
            'content-type': 'application/json',
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

// Compact mock accessors.
const findMany = () => prisma.issuerProfile.findMany as unknown as ReturnType<typeof vi.fn>;
const findUnique = () => prisma.issuerProfile.findUnique as unknown as ReturnType<typeof vi.fn>;
const create = () => prisma.issuerProfile.create as unknown as ReturnType<typeof vi.fn>;
const update = () => prisma.issuerProfile.update as unknown as ReturnType<typeof vi.fn>;

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

describe('auth', () => {
  it('returns 403 when the caller is not in the admin group', async () => {
    const app = buildApp(true);
    const { status, body } = await inject(app, 'GET', '/api/issuer-profiles');
    expect(status).toBe(403);
    expect(body.error.code).toBe('forbidden');
  });

  it('lets admin through the guard', async () => {
    findMany().mockResolvedValue([]);
    const app = buildApp(true);
    const { status } = await inject(app, 'GET', '/api/issuer-profiles', undefined, {
      'x-test-role': 'admin',
    });
    expect(status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// GET /api/issuer-profiles  (masked ARNs)
// ---------------------------------------------------------------------------

describe('GET /api/issuer-profiles', () => {
  it('returns list with ARNs masked down to last-4', async () => {
    findMany().mockResolvedValue([
      {
        id: 'ip_1',
        programId: 'prog_1',
        chipProfileId: 'cp_1',
        scheme: 'mchip_advance',
        cvn: 18,
        tmkKeyArn: 'arn:aws:pc::123:key/abcd1234',
        imkAcKeyArn: 'arn:aws:pc::123:key/5678efgh',
        imkSmiKeyArn: '',
        imkSmcKeyArn: 'abcd', // exactly 4 chars — full masking kicks in
        imkIdnKeyArn: '',
        issuerPkKeyArn: 'arn:aws:pc::123:key/99ZZ',
        program: { id: 'prog_1', name: 'Karta Platinum' },
        chipProfile: { id: 'cp_1', name: 'M/Chip Advance CVN 18', scheme: 'mchip_advance' },
      },
    ]);

    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/issuer-profiles');
    expect(status).toBe(200);
    expect(body).toHaveLength(1);
    const p = body[0];
    // Long ARNs masked to last 4
    expect(p.tmkKeyArn).toBe('***1234');
    expect(p.imkAcKeyArn).toBe('***efgh');
    expect(p.issuerPkKeyArn).toBe('***99ZZ');
    // Short ones get '***'
    expect(p.imkSmcKeyArn).toBe('***');
    // Empty stays empty
    expect(p.imkSmiKeyArn).toBe('');
    expect(p.imkIdnKeyArn).toBe('');
    // Non-ARN fields untouched
    expect(p.scheme).toBe('mchip_advance');
    expect(p.cvn).toBe(18);
  });
});

// ---------------------------------------------------------------------------
// GET /api/issuer-profiles/:id  (full ARNs)
// ---------------------------------------------------------------------------

describe('GET /api/issuer-profiles/:id', () => {
  it('returns the profile with ARNs unmasked', async () => {
    findUnique().mockResolvedValue({
      id: 'ip_1',
      programId: 'prog_1',
      chipProfileId: 'cp_1',
      tmkKeyArn: 'arn:aws:pc::123:key/abcd1234',
      program: { id: 'prog_1', name: 'P' },
      chipProfile: { id: 'cp_1', name: 'C', scheme: 'vsdc' },
    });
    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/issuer-profiles/ip_1');
    expect(status).toBe(200);
    expect(body.tmkKeyArn).toBe('arn:aws:pc::123:key/abcd1234');
  });

  it('404 when missing', async () => {
    findUnique().mockResolvedValue(null);
    const app = buildApp();
    const { status, body } = await inject(app, 'GET', '/api/issuer-profiles/ip_missing');
    expect(status).toBe(404);
    expect(body.error.code).toBe('issuer_profile_not_found');
  });
});

// ---------------------------------------------------------------------------
// POST /api/issuer-profiles
// ---------------------------------------------------------------------------

describe('POST /api/issuer-profiles', () => {
  it('creates an issuer profile with ARN paste-in', async () => {
    const input = {
      programId: 'prog_1',
      chipProfileId: 'cp_1',
      scheme: 'mchip_advance',
      cvn: 18,
      tmkKeyArn: 'arn:aws:pc::123:key/tmk0001',
      imkAcKeyArn: 'arn:aws:pc::123:key/ac0001',
      aid: 'A0000000041010',
      appLabel: 'KARTA PLATINUM',
      iacDefault: 'F040FC8000',
      caPkIndex: '05',
      currencyCode: '0036',
    };
    create().mockResolvedValue({ id: 'ip_new', ...input });
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/issuer-profiles', input);
    expect(status).toBe(201);
    expect(body.id).toBe('ip_new');
    expect(create()).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          programId: 'prog_1',
          scheme: 'mchip_advance',
          tmkKeyArn: 'arn:aws:pc::123:key/tmk0001',
        }),
      }),
    );
  });

  it('400 validation_failed on missing required fields', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/issuer-profiles', {
      programId: 'prog_1',
      // missing chipProfileId, scheme, cvn
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('400 validation_failed when a hex field contains non-hex', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/issuer-profiles', {
      programId: 'prog_1',
      chipProfileId: 'cp_1',
      scheme: 'mchip_advance',
      cvn: 18,
      aid: 'HELLO_WORLD', // not hex
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('400 when scheme is not in the enum', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/issuer-profiles', {
      programId: 'prog_1',
      chipProfileId: 'cp_1',
      scheme: 'amex',
      cvn: 18,
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('409 when the programId already has an IssuerProfile (P2002)', async () => {
    create().mockRejectedValue({ code: 'P2002' });
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/issuer-profiles', {
      programId: 'prog_1',
      chipProfileId: 'cp_1',
      scheme: 'mchip_advance',
      cvn: 18,
    });
    expect(status).toBe(409);
    expect(body.error.code).toBe('issuer_profile_program_conflict');
  });

  it('rejects unknown fields (strict())', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'POST', '/api/issuer-profiles', {
      programId: 'prog_1',
      chipProfileId: 'cp_1',
      scheme: 'mchip_advance',
      cvn: 18,
      rogueField: 'sneaky',
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });
});

// ---------------------------------------------------------------------------
// PATCH /api/issuer-profiles/:id
// ---------------------------------------------------------------------------

describe('PATCH /api/issuer-profiles/:id', () => {
  it('updates mutable fields and returns the full record', async () => {
    update().mockResolvedValue({ id: 'ip_1', aid: 'A0000000041010', appLabel: 'NEW LABEL' });
    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/issuer-profiles/ip_1', {
      aid: 'A0000000041010',
      appLabel: 'NEW LABEL',
    });
    expect(status).toBe(200);
    expect(body.appLabel).toBe('NEW LABEL');
  });

  it('404 when the profile does not exist', async () => {
    update().mockRejectedValue({ code: 'P2025' });
    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/issuer-profiles/ip_missing', {
      aid: 'A0000000041010',
    });
    expect(status).toBe(404);
    expect(body.error.code).toBe('issuer_profile_not_found');
  });

  it('400 when no fields are supplied', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/issuer-profiles/ip_1', {});
    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('rejects attempting to move programId', async () => {
    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/issuer-profiles/ip_1', {
      programId: 'prog_other',
    });
    expect(status).toBe(400);
    expect(body.error.code).toBe('validation_failed');
  });

  it('allows pasting a new key ARN', async () => {
    update().mockResolvedValue({ id: 'ip_1', tmkKeyArn: 'arn:aws:pc::999:key/new' });
    const app = buildApp();
    const { status, body } = await inject(app, 'PATCH', '/api/issuer-profiles/ip_1', {
      tmkKeyArn: 'arn:aws:pc::999:key/new',
    });
    expect(status).toBe(200);
    expect(body.tmkKeyArn).toBe('arn:aws:pc::999:key/new');
  });
});
