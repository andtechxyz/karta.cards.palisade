import { Prisma, type Program } from '@prisma/client';
import { prisma } from '@palisade/db';
import { conflict, notFound } from '@palisade/core';
import { normaliseCurrency, tierRuleSetSchema } from '@palisade/card-programs';
import { renderNdefUrls, validateNdefUrlTemplate, type NdefUrlPair } from './ndef.js';

// -----------------------------------------------------------------------------
// Program CRUD — admin service.
// Full read/write access: create, update, list, get, NDEF URL resolution.
// -----------------------------------------------------------------------------

export interface UpsertProgramInput {
  id: string;
  name: string;
  currency: string;
  tierRules: unknown; // Zod-validated inside
  programType?: string; // Zod-validated by route; defaults to PREPAID_RELOADABLE in DB
  preActivationNdefUrlTemplate?: string | null;
  postActivationNdefUrlTemplate?: string | null;
  financialInstitutionId?: string | null;
  embossingTemplateId?: string | null;
}

export async function createProgram(input: UpsertProgramInput): Promise<Program> {
  const rules = tierRuleSetSchema.parse(input.tierRules);
  if (input.preActivationNdefUrlTemplate) {
    validateNdefUrlTemplate(input.preActivationNdefUrlTemplate);
  }
  if (input.postActivationNdefUrlTemplate) {
    validateNdefUrlTemplate(input.postActivationNdefUrlTemplate);
  }
  try {
    return await prisma.program.create({
      data: {
        id: input.id,
        name: input.name,
        currency: normaliseCurrency(input.currency),
        tierRules: rules,
        // Column has a DB default (PREPAID_RELOADABLE) — only pass when the
        // caller explicitly set one so creates without a programType still
        // hit the default path.
        ...(input.programType ? { programType: input.programType } : {}),
        preActivationNdefUrlTemplate: input.preActivationNdefUrlTemplate ?? null,
        postActivationNdefUrlTemplate: input.postActivationNdefUrlTemplate ?? null,
        financialInstitutionId: input.financialInstitutionId ?? null,
        embossingTemplateId: input.embossingTemplateId ?? null,
      },
    });
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
      throw conflict('program_exists', `Program ${input.id} already exists`);
    }
    throw err;
  }
}

export async function updateProgram(
  id: string,
  patch: Partial<Omit<UpsertProgramInput, 'id'>>,
): Promise<Program> {
  const data: Prisma.ProgramUpdateInput = {};
  if (patch.name !== undefined) data.name = patch.name;
  if (patch.currency !== undefined) data.currency = normaliseCurrency(patch.currency);
  if (patch.tierRules !== undefined) data.tierRules = tierRuleSetSchema.parse(patch.tierRules);
  if (patch.programType !== undefined) data.programType = patch.programType;
  if (patch.preActivationNdefUrlTemplate !== undefined) {
    if (patch.preActivationNdefUrlTemplate) {
      validateNdefUrlTemplate(patch.preActivationNdefUrlTemplate);
    }
    data.preActivationNdefUrlTemplate = patch.preActivationNdefUrlTemplate;
  }
  if (patch.postActivationNdefUrlTemplate !== undefined) {
    if (patch.postActivationNdefUrlTemplate) {
      validateNdefUrlTemplate(patch.postActivationNdefUrlTemplate);
    }
    data.postActivationNdefUrlTemplate = patch.postActivationNdefUrlTemplate;
  }
  if (patch.financialInstitutionId !== undefined) {
    data.financialInstitution = patch.financialInstitutionId
      ? { connect: { id: patch.financialInstitutionId } }
      : { disconnect: true };
  }
  if (patch.embossingTemplateId !== undefined) {
    data.embossingTemplate = patch.embossingTemplateId
      ? { connect: { id: patch.embossingTemplateId } }
      : { disconnect: true };
  }

  try {
    return await prisma.program.update({ where: { id }, data });
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2025') {
      throw notFound('program_not_found', `Program ${id} not found`);
    }
    throw err;
  }
}

export interface ListProgramsOptions {
  financialInstitutionId?: string;
}

export async function listPrograms(opts: ListProgramsOptions = {}): Promise<Program[]> {
  return prisma.program.findMany({
    where: opts.financialInstitutionId
      ? { financialInstitutionId: opts.financialInstitutionId }
      : undefined,
    orderBy: { id: 'asc' },
    include: {
      financialInstitution: { select: { id: true, name: true, slug: true } },
      embossingTemplate: { select: { id: true, name: true } },
    },
  });
}

export async function getProgram(id: string): Promise<Program> {
  const p = await prisma.program.findUnique({
    where: { id },
    include: {
      financialInstitution: { select: { id: true, name: true, slug: true } },
      embossingTemplate: { select: { id: true, name: true } },
    },
  });
  if (!p) throw notFound('program_not_found', `Program ${id} not found`);
  return p;
}

export async function resolveNdefUrlsForCard(cardId: string): Promise<NdefUrlPair> {
  return resolveNdefUrlsWhere({ id: cardId }, `Card ${cardId} not found`);
}

export async function resolveNdefUrlsByCardRef(cardRef: string): Promise<NdefUrlPair> {
  return resolveNdefUrlsWhere({ cardRef }, `Card ref ${cardRef} not found`);
}

async function resolveNdefUrlsWhere(
  where: Prisma.CardWhereUniqueInput,
  missingMessage: string,
): Promise<NdefUrlPair> {
  const card = await prisma.card.findUnique({
    where,
    select: {
      cardRef: true,
      program: {
        select: {
          preActivationNdefUrlTemplate: true,
          postActivationNdefUrlTemplate: true,
        },
      },
    },
  });
  if (!card) throw notFound('card_not_found', missingMessage);
  return renderNdefUrls({
    cardRef: card.cardRef,
    preActivationTemplate: card.program?.preActivationNdefUrlTemplate ?? null,
    postActivationTemplate: card.program?.postActivationNdefUrlTemplate ?? null,
  });
}
