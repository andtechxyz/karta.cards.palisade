import { prisma } from '@palisade/db';
import { decrypt, type KeyProvider } from '@palisade/core';
import type { SdmDeriver } from '@palisade/sdm-keys';
import { decryptPiccData } from './picc.js';

// Resolve a cardRef-less SUN URL (e.g. the mobile app's `/api/tap/verify/:urlCode`
// path) to a specific Card by trial-deriving its meta-read key from each
// candidate's stored UID and attempting PICC decrypt.  The "match" signal is
// the SDM tag byte (0xC7) at plaintext offset 0 — every other key produces
// effectively-random bytes there with probability 1/256.
//
// Complexity: O(N) derivations per tap, where N is the number of active cards
// in the program.  There is no way to lower this without exposing UID in the
// URL plaintext (a privacy requirement says no).  If the program fleet gets
// large, add an LRU cache keyed by UID fingerprint in the SdmDeriver or a
// pre-warmed in-process map — both are pure-function optimisations.
//
// Filters to ACTIVATED + PROVISIONED only — SHIPPED cards have no business
// hitting this endpoint (their NDEF URL points at the activation flow, not at
// /t/<urlCode>), and SUSPENDED/REVOKED cards must be rejected upstream of any
// signed-handoff mint.

export interface FindCardByPiccInput {
  /**
   * Program scope.  Iteration is over Cards in this program only, derived
   * from the `urlCode` in the chip's URL.
   */
  programId: string;
  piccHex: string;
  /** Decrypts the stored UID on each candidate. */
  keyProvider: KeyProvider;
  /** Derives meta/file read keys from a UID. */
  sdmDeriver: SdmDeriver;
}

export interface FindCardByPiccMatch {
  cardId: string;
  cardStatus: string;
  lastReadCounter: number;
  /** AES-128 key, plaintext.  Caller MUST scrub when done. */
  sdmMetaReadKey: Buffer;
  /** AES-128 key, plaintext.  Caller MUST scrub when done. */
  sdmFileReadKey: Buffer;
  /** PICC plaintext fields (UID, counter, etc) — already decrypted, save redoing. */
  uid: Buffer;
  counter: number;
}

/**
 * Returns the matching Card + already-decrypted PICC, or null if no card
 * in the program decrypted the PICC bytes to a valid (tag=0xC7) plaintext.
 */
export async function findCardByPicc(
  input: FindCardByPiccInput,
): Promise<FindCardByPiccMatch | null> {
  const candidates = await prisma.card.findMany({
    where: {
      programId: input.programId,
      status: { in: ['ACTIVATED', 'PROVISIONED'] },
    },
    select: {
      id: true,
      status: true,
      lastReadCounter: true,
      keyVersion: true,
      uidEncrypted: true,
    },
  });

  for (const c of candidates) {
    let uid: Buffer | null = null;
    let metaKey: Buffer | null = null;
    try {
      const uidHex = decrypt(
        { ciphertext: c.uidEncrypted, keyVersion: c.keyVersion },
        input.keyProvider,
      );
      uid = Buffer.from(uidHex, 'hex');
      metaKey = await input.sdmDeriver.deriveMetaReadKey(uid);

      const picc = decryptPiccData(metaKey, input.piccHex);
      if (!picc.valid) {
        // Tag mismatch — wrong UID (i.e. wrong card), try the next candidate.
        metaKey.fill(0);
        uid.fill(0);
        continue;
      }

      // Match.  Derive the file-read key too and return.  Caller scrubs both.
      const sdmFileReadKey = await input.sdmDeriver.deriveFileReadKey(uid);
      return {
        cardId: c.id,
        cardStatus: c.status,
        lastReadCounter: c.lastReadCounter,
        sdmMetaReadKey: metaKey,
        sdmFileReadKey,
        uid: picc.uid,
        counter: picc.counter,
      };
    } catch {
      // GCM auth fail on UID decrypt, or any other error = skip this card.
      metaKey?.fill(0);
      uid?.fill(0);
      continue;
    }
  }

  return null;
}
