// Single Prisma client for the process.  All services import from @palisade/db so
// there is exactly one connection pool per Node process and the generated
// types stay in lock-step with the schema this package owns.
export { prisma } from './prisma.js';
export * from '@prisma/client';
