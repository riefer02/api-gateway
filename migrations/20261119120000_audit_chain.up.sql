-- Tamper-evident chain for the control-plane audit log.
--
-- Each row carries the hash of its predecessor and a hash of its own contents,
-- so an edit, an insertion or a reordering breaks the chain at a known row.
-- Writes are serialised by an advisory lock in the inserting transaction, which
-- is affordable here because control-plane mutations are low volume; the
-- high-volume data-plane audit stays batched and unchained on purpose.
--
-- Rows written before this migration have empty hashes and are reported as
-- unchained. The chain starts at the first row written afterwards; rehashing
-- history would prove nothing, because there is nothing to compare it to.
ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN row_hash TEXT NOT NULL DEFAULT '';
