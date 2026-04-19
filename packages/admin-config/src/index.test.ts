import { describe, it, expect, afterEach } from 'vitest';
import { getAdminEmails, isAdminEmail } from './index.js';

const ORIGINAL = process.env.ADMIN_EMAIL_ALLOWLIST;

afterEach(() => {
  if (ORIGINAL === undefined) {
    delete process.env.ADMIN_EMAIL_ALLOWLIST;
  } else {
    process.env.ADMIN_EMAIL_ALLOWLIST = ORIGINAL;
  }
});

describe('getAdminEmails', () => {
  it('returns empty array when env var is unset', () => {
    delete process.env.ADMIN_EMAIL_ALLOWLIST;
    expect(getAdminEmails()).toEqual([]);
  });

  it('returns empty array when env var is the empty string', () => {
    process.env.ADMIN_EMAIL_ALLOWLIST = '';
    expect(getAdminEmails()).toEqual([]);
  });

  it('parses a single email', () => {
    process.env.ADMIN_EMAIL_ALLOWLIST = 'admin@karta.cards';
    expect(getAdminEmails()).toEqual(['admin@karta.cards']);
  });

  it('parses multiple emails, trims whitespace, lowercases', () => {
    process.env.ADMIN_EMAIL_ALLOWLIST = ' Alice@Karta.Cards , bob@karta.cards ';
    expect(getAdminEmails()).toEqual(['alice@karta.cards', 'bob@karta.cards']);
  });

  it('drops empty entries from trailing / doubled commas', () => {
    process.env.ADMIN_EMAIL_ALLOWLIST = 'a@x.y,,b@x.y,';
    expect(getAdminEmails()).toEqual(['a@x.y', 'b@x.y']);
  });
});

describe('isAdminEmail', () => {
  it('false when env is unset', () => {
    delete process.env.ADMIN_EMAIL_ALLOWLIST;
    expect(isAdminEmail('admin@karta.cards')).toBe(false);
  });

  it('false when email is undefined / null / empty', () => {
    process.env.ADMIN_EMAIL_ALLOWLIST = 'admin@karta.cards';
    expect(isAdminEmail(undefined)).toBe(false);
    expect(isAdminEmail(null)).toBe(false);
    expect(isAdminEmail('')).toBe(false);
  });

  it('case-insensitive match', () => {
    process.env.ADMIN_EMAIL_ALLOWLIST = 'admin@karta.cards';
    expect(isAdminEmail('ADMIN@karta.cards')).toBe(true);
    expect(isAdminEmail('Admin@Karta.Cards')).toBe(true);
  });

  it('rejects emails not on the list', () => {
    process.env.ADMIN_EMAIL_ALLOWLIST = 'admin@karta.cards';
    expect(isAdminEmail('other@karta.cards')).toBe(false);
  });
});
