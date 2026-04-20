-- Composite index on Card for the tap-service find-card hot path.
-- See packages/db/prisma/schema.prisma: @@index([programId, status])
CREATE INDEX "Card_programId_status_idx" ON "Card"("programId", "status");
