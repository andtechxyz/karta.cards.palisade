-- Adds Program.urlCode + backfills the three existing programs.
--
-- urlCode is the short opaque identifier that lives in the post-activation
-- chip URL (mobile.karta.cards/t/<urlCode>?e=&m=).  Public — same leak
-- surface as a PAN BIN.  Lets the mobile app + tap-verify endpoint resolve
-- which program's per-card SDM keys to try without {cardRef} leaking in the
-- URL.

ALTER TABLE "Program" ADD COLUMN IF NOT EXISTS "urlCode" VARCHAR(8);

-- Backfill the three current programs.  Codes chosen to be readable in logs
-- (kp / sg / tm) without being long enough to bloat the chip's NDEF buffer.
UPDATE "Program" SET "urlCode" = 'kp' WHERE id = 'karta_platinum'  AND "urlCode" IS NULL;
UPDATE "Program" SET "urlCode" = 'sg' WHERE id = 'securegift'      AND "urlCode" IS NULL;
UPDATE "Program" SET "urlCode" = 'tm' WHERE id = 'prog_mc_test_01' AND "urlCode" IS NULL;

-- Update Karta Platinum's post-activation NDEF template to use the new
-- {urlCode} placeholder + the /t/ prefix.  The chip will store
-- mobile.karta.cards/t/kp on activation and emit
-- https://mobile.karta.cards/t/kp?e=<picc>&m=<cmac> on every tap.
UPDATE "Program"
SET "postActivationNdefUrlTemplate" = 'https://mobile.karta.cards/t/{urlCode}?e={PICCData}&m={CMAC}'
WHERE id = 'karta_platinum';

-- Unique index — globally unique so the URL fully identifies the program.
CREATE UNIQUE INDEX IF NOT EXISTS "Program_urlCode_key" ON "Program" ("urlCode");
