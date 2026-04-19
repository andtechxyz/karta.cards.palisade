import { PrismaClient } from '@prisma/client';

// Single Prisma client for the process.
export const prisma = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
});
