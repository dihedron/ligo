-- A binding's description and annotations (.specs/ligo-binding-annotations.md):
-- `purpose` and `labels` become `description` and `annotations`, and both are
-- served to workloads.

ALTER TABLE bindings RENAME COLUMN purpose TO description;
ALTER TABLE bindings RENAME COLUMN labels TO annotations;

ALTER TABLE bindings DROP CONSTRAINT IF EXISTS bindings_purpose_check;
ALTER TABLE bindings ADD CONSTRAINT bindings_description_check CHECK (length(description) <= 4096);

-- Columns are only added at the end of the view, which CREATE OR REPLACE allows.
CREATE OR REPLACE VIEW v_active_bindings AS
SELECT b.id, b.name, b.platform_type, b.platform, t.name AS target_name, s.name AS source_name,
       b.access_level, b.source_trust_domain, b.active_revision, b.active_source_svid_regex,
       s.svid_regex AS current_source_svid_regex,
       b.active_auth_config, b.active_spec, b.secret_store_instance, b.expires_at, b.updated_at,
       b.description, b.annotations
FROM bindings b
JOIN targets t ON t.id = b.target_id
JOIN sources s ON s.id = b.source_id
WHERE b.active_revision IS NOT NULL
  AND b.phase NOT IN ('DELETING','DELETE_FAILED')
  AND s.state <> 'RETIRED'
  AND (b.expires_at IS NULL OR b.expires_at > now());

-- A change of either reaches the caches: the text is served to workloads.
DROP TRIGGER trg_bindings_notify_update ON bindings;
CREATE TRIGGER trg_bindings_notify_update
    AFTER UPDATE OF active_revision, active_source_svid_regex,
          active_auth_config, active_spec, phase, expires_at, description, annotations
    ON bindings FOR EACH ROW
    WHEN (
        OLD.active_revision IS DISTINCT FROM NEW.active_revision
        OR OLD.active_source_svid_regex IS DISTINCT FROM NEW.active_source_svid_regex
        OR OLD.active_auth_config IS DISTINCT FROM NEW.active_auth_config
        OR OLD.active_spec IS DISTINCT FROM NEW.active_spec
        OR OLD.description IS DISTINCT FROM NEW.description
        OR OLD.annotations IS DISTINCT FROM NEW.annotations
        OR OLD.expires_at IS DISTINCT FROM NEW.expires_at
        OR (OLD.phase IN ('DELETING', 'DELETE_FAILED')) IS DISTINCT FROM (NEW.phase IN ('DELETING', 'DELETE_FAILED'))
    )
    EXECUTE FUNCTION bindings_notify();
