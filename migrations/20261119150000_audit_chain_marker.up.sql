-- Distinguish a row that opted out of the chain from one whose hash was
-- removed.
--
-- Without this marker, an empty `row_hash` means either "written before the
-- chain existed" (or by a replica that has not been upgraded) or "someone
-- blanked it", and those need opposite verdicts: the first is a gap, the
-- second is tampering. Verification now trusts `chained`, never the hash's
-- absence.
ALTER TABLE audit_events
    ADD COLUMN chained BOOLEAN NOT NULL DEFAULT false;

-- Every row that already carries a hash was written by the chain.
UPDATE audit_events SET chained = true WHERE row_hash <> '';
