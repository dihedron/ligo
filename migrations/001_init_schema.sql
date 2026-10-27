-- ligo schema 4.0 (specification §4.2, copied verbatim; do not edit here).
CREATE TYPE binding_phase      AS ENUM ('PROVISIONING','ACTIVE','FAILED','DELETING','DELETE_FAILED');
CREATE TYPE binding_operation  AS ENUM ('APPLY','REAPPLY','DELETE');
CREATE TYPE binding_stage      AS ENUM ('IDENTITY','TARGET','SECRET_STORE');
CREATE TYPE stage_status       AS ENUM ('STARTED','ENSURED');
CREATE TYPE lifecycle_state    AS ENUM ('ACTIVE','DEPRECATED','RETIRED');
CREATE TYPE visibility         AS ENUM ('PRIVATE','LISTED','PUBLIC');
CREATE TYPE flow_purpose       AS ENUM ('DATA','CREDENTIALS','DISCOVERY');
CREATE TYPE flow_protocol      AS ENUM ('TCP','UDP');
CREATE TYPE resource_type      AS ENUM ('SOURCE','TARGET','BINDING');
CREATE TYPE change_request_op  AS ENUM ('CREATE','UPDATE','DELETE');
CREATE TYPE change_request_kind AS ENUM ('STANDARD','BREAK_GLASS','SYSTEM_REVERT','SYSTEM_EXPIRY');
CREATE TYPE consent_rule       AS ENUM ('ALL','ANY');
CREATE TYPE approval_basis     AS ENUM ('AUTO','HUMAN','DELEGATED','BREAK_GLASS','SYSTEM_REVERT','SYSTEM_EXPIRY');
CREATE TYPE side_decision      AS ENUM ('APPROVED','DECLINED');
CREATE TYPE change_request_status AS ENUM
    ('PENDING','APPLIED','REJECTED','WITHDRAWN','EXPIRED','FAILED_TO_APPLY');

-- Scope paths (§3.9) are checked with this pattern wherever they are stored.
CREATE DOMAIN scope_path AS VARCHAR(128)
    CHECK (VALUE ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(/[a-z0-9]([a-z0-9-]*[a-z0-9])?){0,7}$');
-- Names of sources, targets and bindings (§3.8).
CREATE DOMAIN resource_name AS VARCHAR(63)
    CHECK (VALUE ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$');

-- ---------------------------------------------------------------------------
-- Sources (ADR-15): who may use bindings. The identity specification (trust
-- domain, regex, sample IDs) plus descriptive metadata. Never hard-deleted:
-- retiring a source sets state = 'RETIRED' and releases its name.
-- ---------------------------------------------------------------------------
CREATE TABLE sources (
    id                 UUID PRIMARY KEY,                    -- UUIDv7
    name               resource_name NOT NULL,
    scope              scope_path NOT NULL,                 -- derived from the regex (§3.9); immutable
    trust_domain       VARCHAR(255) NOT NULL,               -- immutable
    svid_regex         TEXT NOT NULL CHECK (length(svid_regex) <= 512),   -- may only be narrowed (§3.10)
    sample_spiffe_ids  JSONB NOT NULL DEFAULT '[]'::jsonb,  -- array of SPIFFE IDs the regex must match
    display_name       VARCHAR(128),
    description        TEXT CHECK (length(description) <= 4096),
    labels             JSONB NOT NULL DEFAULT '{}'::jsonb,
    external_refs      JSONB NOT NULL DEFAULT '{}'::jsonb,  -- e.g. {"cmdb": "APP-0042", "environment": "prod"}
    contacts           JSONB NOT NULL DEFAULT '[]'::jsonb,
    visibility         visibility NOT NULL DEFAULT 'PRIVATE',
    visible_to         JSONB NOT NULL DEFAULT '[]'::jsonb,  -- scope patterns, for LISTED
    state              lifecycle_state NOT NULL DEFAULT 'ACTIVE',
    revision           BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by         VARCHAR(255) NOT NULL,
    updated_by         VARCHAR(255) NOT NULL,
    -- Coarse defense in depth only; authoritative validation is Appendix A (ADR-06).
    CONSTRAINT chk_source_regex_shape CHECK (
        svid_regex LIKE '^spiffe://%' AND svid_regex LIKE '%$'
        AND right(svid_regex, 2) <> '\$'                      -- an escaped \$ is a literal, not an anchor
    ),
    CONSTRAINT chk_source_samples CHECK (jsonb_typeof(sample_spiffe_ids) = 'array' AND jsonb_array_length(sample_spiffe_ids) <= 20),
    CONSTRAINT chk_source_visible_to CHECK (
        jsonb_typeof(visible_to) = 'array' AND (visibility <> 'LISTED' OR jsonb_array_length(visible_to) > 0)
    )
);
CREATE UNIQUE INDEX uq_sources_name ON sources (name) WHERE state <> 'RETIRED';
CREATE INDEX idx_sources_scope ON sources (scope, name);

-- ---------------------------------------------------------------------------
-- Targets (ADR-15): one specific resource on a platform, with its access
-- levels and network flows. Register-only in 4.0: publishing a target does
-- not create the resource. Never hard-deleted (retired instead).
-- ---------------------------------------------------------------------------
CREATE TABLE targets (
    id                 UUID PRIMARY KEY,                    -- UUIDv7
    name               resource_name NOT NULL,
    platform           VARCHAR(128) NOT NULL,               -- configured platform (§8.1); immutable
    platform_type      VARCHAR(128) NOT NULL,               -- plugin type of the platform; immutable
    zone               VARCHAR(63)  NOT NULL,               -- the platform's zone; immutable
    scope              scope_path NOT NULL,                 -- owner scope; immutable (re-scoping only)
    platform_scope     scope_path NOT NULL,                 -- the platform's owner scope; immutable (re-scoping only)
    definition         JSONB NOT NULL,                      -- normalized by TargetProvider.ValidateTarget
    display_name       VARCHAR(128),
    description        TEXT CHECK (length(description) <= 4096),
    labels             JSONB NOT NULL DEFAULT '{}'::jsonb,
    documentation_url  VARCHAR(512),
    contacts           JSONB NOT NULL DEFAULT '[]'::jsonb,
    visibility         visibility NOT NULL DEFAULT 'PRIVATE',
    visible_to         JSONB NOT NULL DEFAULT '[]'::jsonb,  -- scope patterns, for LISTED
    state              lifecycle_state NOT NULL DEFAULT 'ACTIVE',
    revision           BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by         VARCHAR(255) NOT NULL,
    updated_by         VARCHAR(255) NOT NULL,
    CONSTRAINT chk_target_visible_to CHECK (
        jsonb_typeof(visible_to) = 'array' AND (visibility <> 'LISTED' OR jsonb_array_length(visible_to) > 0)
    )
);
CREATE UNIQUE INDEX uq_targets_name ON targets (name) WHERE state <> 'RETIRED';
CREATE INDEX idx_targets_scope ON targets (scope, name);
CREATE INDEX idx_targets_platform ON targets (platform, name);

-- Access levels offered by a target. Grants may be narrowed in place; adding
-- privilege means adding a new level (§3.10). A level in use cannot be removed.
CREATE TABLE target_access_levels (
    target_id          UUID NOT NULL REFERENCES targets(id),
    name               VARCHAR(32) NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,31}$'),
    description        TEXT CHECK (length(description) <= 1024),
    grants             JSONB NOT NULL,                      -- normalized by ValidateTarget; within the platform's grantable privileges
    privileges         JSONB NOT NULL,                      -- canonical sorted privilege list from the plugin, used to compare levels
    state              lifecycle_state NOT NULL DEFAULT 'ACTIVE',  -- DEPRECATED: no new bindings
    PRIMARY KEY (target_id, name)
);

-- Network flows needed to reach a target (ADR-16). Platform, secret-store and
-- ligo flows are configuration (§8.1); a binding's effective flows are computed.
CREATE TABLE target_network_flows (
    target_id          UUID NOT NULL REFERENCES targets(id),
    name               VARCHAR(63) NOT NULL CHECK (name ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'),
    purpose            flow_purpose NOT NULL DEFAULT 'DATA',
    protocol           flow_protocol NOT NULL,
    destination        VARCHAR(253) NOT NULL,               -- DNS name, IP address or CIDR; within the platform's allowed endpoints
    ports              INT4MULTIRANGE NOT NULL,
    tls                BOOLEAN NOT NULL,
    server_name        VARCHAR(253),                        -- expected TLS server name, if tls
    description        TEXT CHECK (length(description) <= 1024),
    PRIMARY KEY (target_id, name),
    CONSTRAINT chk_flow_ports CHECK (NOT isempty(ports) AND lower(ports) >= 1 AND upper(ports) <= 65536),
    CONSTRAINT chk_flow_tls CHECK (tls OR server_name IS NULL)
);

-- Sources and targets: immutable identity and ownership columns (INV-08, INV-21).
CREATE FUNCTION sources_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.scope <> OLD.scope AND coalesce(current_setting('ligo.rescope', true), '') <> 'on' THEN
    RAISE EXCEPTION 'source scope modified outside the re-scoping procedure';
  END IF;
  IF NEW.id <> OLD.id OR NEW.trust_domain <> OLD.trust_domain OR NEW.name <> OLD.name
     OR (OLD.state = 'RETIRED' AND NEW.state <> 'RETIRED') THEN
    RAISE EXCEPTION 'immutable source column modified';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_sources_immutable BEFORE UPDATE ON sources
    FOR EACH ROW EXECUTE FUNCTION sources_immutable_guard();

CREATE FUNCTION targets_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.scope <> OLD.scope OR NEW.platform_scope <> OLD.platform_scope)
     AND coalesce(current_setting('ligo.rescope', true), '') <> 'on' THEN
    RAISE EXCEPTION 'target scope modified outside the re-scoping procedure';
  END IF;
  IF NEW.id <> OLD.id OR NEW.name <> OLD.name OR NEW.platform <> OLD.platform
     OR NEW.platform_type <> OLD.platform_type OR NEW.zone <> OLD.zone
     OR (OLD.state = 'RETIRED' AND NEW.state <> 'RETIRED') THEN
    RAISE EXCEPTION 'immutable target column modified';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_targets_immutable BEFORE UPDATE ON targets
    FOR EACH ROW EXECUTE FUNCTION targets_immutable_guard();

-- ---------------------------------------------------------------------------
-- Bindings: the link between one source and one target at one access level.
-- The requested state of each revision is a copy composed from the source,
-- the target and the access level (§3.5), so that every revision is a
-- consistent, reviewable snapshot (INV-02).
-- ---------------------------------------------------------------------------
CREATE TABLE bindings (
    id                          UUID PRIMARY KEY,               -- UUIDv7, generated by application
    name                        resource_name NOT NULL UNIQUE,
    source_id                   UUID NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,   -- immutable
    target_id                   UUID NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,   -- immutable
    access_level                VARCHAR(32) NOT NULL,
    zone                        VARCHAR(63)  NOT NULL,
    platform_type               VARCHAR(128) NOT NULL,
    platform                    VARCHAR(128) NOT NULL,
    identity_provider_type      VARCHAR(128) NOT NULL,
    identity_provider_instance  VARCHAR(128) NOT NULL,
    secret_store_type           VARCHAR(128) NOT NULL,
    secret_store_instance       VARCHAR(128) NOT NULL,
    secret_storage_strategy       VARCHAR(64)  NOT NULL,          -- §5.6; from the platform's wiring at creation; immutable
    derived_principal_name      VARCHAR(20) NOT NULL UNIQUE,    -- Appendix B, with the platform's principal_prefix at creation; immutable
    source_scope                scope_path NOT NULL,            -- copied from the source; immutable (re-scoping only)
    target_scope                scope_path NOT NULL,            -- copied from the target
    platform_scope              scope_path NOT NULL,            -- copied from the target's platform
    parameters                  JSONB NOT NULL DEFAULT '{}'::jsonb,   -- per-binding parameters, validated by ValidateBinding
    purpose                     TEXT CHECK (length(purpose) <= 1024),
    labels                      JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at                  TIMESTAMPTZ,                    -- optional; revoked by the sweeper (§6.3)
    expiry_warned_at            TIMESTAMPTZ,                    -- BINDING_EXPIRING already emitted

    revision                    BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    attempt                     BIGINT NOT NULL DEFAULT 1 CHECK (attempt >= 1),
    phase                       binding_phase     NOT NULL DEFAULT 'PROVISIONING',
    operation                   binding_operation NOT NULL DEFAULT 'APPLY',
    workflow_id                 VARCHAR(255) NOT NULL UNIQUE,
    current_step                VARCHAR(64)  NOT NULL DEFAULT 'INIT',
    status_message              TEXT NOT NULL DEFAULT '' CHECK (length(status_message) <= 2048),
    last_transition_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotate_static_secrets       BOOLEAN NOT NULL DEFAULT TRUE,

    -- Requested state for `revision`, composed from the source, target and access level
    source_revision             BIGINT NOT NULL,
    target_revision             BIGINT NOT NULL,
    source_trust_domain         VARCHAR(255) NOT NULL,
    source_svid_regex           TEXT NOT NULL CHECK (length(source_svid_regex) <= 512),
    requested_spec              JSONB NOT NULL,                 -- normalized by ValidateBinding

    -- Active (served) snapshot
    active_revision             BIGINT,
    active_source_svid_regex    TEXT,
    active_auth_config          JSONB,
    active_spec                 JSONB,
    active_since                TIMESTAMPTZ,
    last_rotated_at             TIMESTAMPTZ,                    -- NULL for identity modes without static secrets (§6.4)
    break_glass_cr_id           UUID,                           -- open (unratified) break-glass change, ADR-12
    break_glass_expires_at      TIMESTAMPTZ,
    break_glass_warned_at       TIMESTAMPTZ,                    -- BREAK_GLASS_EXPIRING already emitted for the open change

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by                  VARCHAR(255) NOT NULL,
    updated_by                  VARCHAR(255) NOT NULL,

    CONSTRAINT uq_binding_source_target UNIQUE (source_id, target_id),          -- one binding per pair (ADR-15)
    CONSTRAINT fk_binding_access_level FOREIGN KEY (target_id, access_level)
        REFERENCES target_access_levels (target_id, name) ON DELETE RESTRICT,
    -- Coarse defense in depth only; authoritative validation is Appendix A (ADR-06).
    CONSTRAINT chk_regex_shape CHECK (
        source_svid_regex LIKE '^spiffe://%' AND source_svid_regex LIKE '%$'
        AND right(source_svid_regex, 2) <> '\$'                    -- an escaped \$ is a literal, not an anchor
    ),
    CONSTRAINT chk_break_glass_open CHECK ((break_glass_cr_id IS NULL) = (break_glass_expires_at IS NULL)),
    CONSTRAINT chk_active_consistent CHECK (
        (active_revision IS NULL AND active_source_svid_regex IS NULL
            AND active_auth_config IS NULL AND active_spec IS NULL)
     OR (active_revision IS NOT NULL AND active_source_svid_regex IS NOT NULL
            AND active_auth_config IS NOT NULL AND active_spec IS NOT NULL
            AND active_revision <= revision)
    )
);

CREATE INDEX idx_bindings_active_td ON bindings (source_trust_domain)
    WHERE active_revision IS NOT NULL AND phase NOT IN ('DELETING','DELETE_FAILED');
CREATE INDEX idx_bindings_phase           ON bindings (phase, last_transition_at);
CREATE INDEX idx_bindings_platform        ON bindings (platform_type, platform);
CREATE INDEX idx_bindings_target          ON bindings (target_id, access_level);
CREATE INDEX idx_bindings_zone            ON bindings (zone);
CREATE INDEX idx_bindings_source_scope    ON bindings (source_scope, name);
CREATE INDEX idx_bindings_target_scope    ON bindings (target_scope, name);
CREATE INDEX idx_bindings_break_glass     ON bindings (break_glass_expires_at) WHERE break_glass_cr_id IS NOT NULL;
CREATE INDEX idx_bindings_expiry          ON bindings (expires_at) WHERE expires_at IS NOT NULL;

-- Immutability of identity/wiring/scope columns (INV-08). Scopes change only through the
-- startup re-scoping procedure (§8.2 rule 17), which sets ligo.rescope = 'on' for its transaction.
CREATE FUNCTION bindings_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.source_scope <> OLD.source_scope OR NEW.target_scope <> OLD.target_scope
      OR NEW.platform_scope <> OLD.platform_scope)
     AND coalesce(current_setting('ligo.rescope', true), '') <> 'on' THEN
    RAISE EXCEPTION 'binding scope modified outside the re-scoping procedure';
  END IF;
  IF NEW.id <> OLD.id OR NEW.name <> OLD.name OR NEW.zone <> OLD.zone
     OR NEW.source_id <> OLD.source_id OR NEW.target_id <> OLD.target_id
     OR NEW.platform_type <> OLD.platform_type OR NEW.platform <> OLD.platform
     OR NEW.identity_provider_type <> OLD.identity_provider_type
     OR NEW.identity_provider_instance <> OLD.identity_provider_instance
     OR NEW.secret_store_type <> OLD.secret_store_type
     OR NEW.secret_store_instance <> OLD.secret_store_instance
     OR NEW.secret_storage_strategy <> OLD.secret_storage_strategy
     OR NEW.derived_principal_name <> OLD.derived_principal_name
     OR NEW.source_trust_domain <> OLD.source_trust_domain THEN
    RAISE EXCEPTION 'immutable binding column modified';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_bindings_immutable BEFORE UPDATE ON bindings
    FOR EACH ROW EXECUTE FUNCTION bindings_immutable_guard();

-- Change notification for workload resolution caches (fires ONLY when workload-visible state changes)
CREATE FUNCTION bindings_notify() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('ligo_bindings_changed', COALESCE(NEW.id, OLD.id)::text);
  RETURN NULL;
END $$;

CREATE TRIGGER trg_bindings_notify_delete
    AFTER DELETE ON bindings
    FOR EACH ROW EXECUTE FUNCTION bindings_notify();

CREATE TRIGGER trg_bindings_notify_update
    AFTER UPDATE OF active_revision, active_source_svid_regex,
          active_auth_config, active_spec, phase, expires_at
    ON bindings FOR EACH ROW
    WHEN (
        OLD.active_revision IS DISTINCT FROM NEW.active_revision
        OR OLD.active_source_svid_regex IS DISTINCT FROM NEW.active_source_svid_regex
        OR OLD.active_auth_config IS DISTINCT FROM NEW.active_auth_config
        OR OLD.active_spec IS DISTINCT FROM NEW.active_spec
        OR OLD.expires_at IS DISTINCT FROM NEW.expires_at
        OR (OLD.phase IN ('DELETING', 'DELETE_FAILED')) IS DISTINCT FROM (NEW.phase IN ('DELETING', 'DELETE_FAILED'))
    )
    EXECUTE FUNCTION bindings_notify();

-- A source's regex and state are part of resolution (INV-01): notify the caches,
-- which reload every binding of the source.
CREATE FUNCTION sources_notify() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('ligo_bindings_changed', 'source:' || NEW.id::text);
  RETURN NULL;
END $$;

CREATE TRIGGER trg_sources_notify
    AFTER UPDATE OF svid_regex, state ON sources FOR EACH ROW
    WHEN (OLD.svid_regex IS DISTINCT FROM NEW.svid_regex OR OLD.state IS DISTINCT FROM NEW.state)
    EXECUTE FUNCTION sources_notify();

-- ---------------------------------------------------------------------------
-- Per-stage provisioning state (drives cleanup; ADR-02, INV-05)
-- `artifact` holds NON-SECRET data only:
--   IDENTITY     -> IdentityArtifact without static_secret (JSON)
--   TARGET       -> {"finalizedClientSpec": {...}, "declaredEndpoints": [...]}
--   SECRET_STORE -> {"finalizedClientAuth": {...}, "declaredEndpoints": [...]}
-- ---------------------------------------------------------------------------
CREATE TABLE binding_stage_state (
    binding_id         UUID NOT NULL REFERENCES bindings(id) ON DELETE CASCADE,
    stage              binding_stage NOT NULL,
    provider_type      VARCHAR(128) NOT NULL,
    provider_instance  VARCHAR(128) NOT NULL,
    status             stage_status NOT NULL,
    revision           BIGINT NOT NULL,
    workflow_id        VARCHAR(255) NOT NULL,
    artifact           JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (binding_id, stage)
);

-- ---------------------------------------------------------------------------
-- Propagation queue (§6.8): bindings whose source, target or access level
-- changed and that must be re-applied. One row per binding; a later cause
-- replaces an earlier one. Security-relevant narrowing has priority 0.
-- ---------------------------------------------------------------------------
CREATE TABLE binding_propagation_queue (
    binding_id         UUID PRIMARY KEY REFERENCES bindings(id) ON DELETE CASCADE,
    cause_change_request_id UUID NOT NULL,
    cause              resource_type NOT NULL,              -- SOURCE or TARGET
    priority           SMALLINT NOT NULL CHECK (priority IN (0, 1)),
    enqueued_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts           INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT chk_propagation_cause CHECK (cause IN ('SOURCE', 'TARGET'))
);
CREATE INDEX idx_propagation_due ON binding_propagation_queue (priority, enqueued_at);

-- ---------------------------------------------------------------------------
-- Change requests (ADR-09, ADR-13, ADR-15): every change to a source, target
-- or binding. Scope columns by resource type:
--   SOURCE  -> owner_scope (the source's scope)
--   TARGET  -> owner_scope (the target's scope), platform_scope
--   BINDING -> source_scope, target_scope, platform_scope
-- ---------------------------------------------------------------------------
CREATE TABLE change_requests (
    id                 UUID PRIMARY KEY,                    -- UUIDv7
    resource_type      resource_type NOT NULL,              -- immutable
    resource_name      resource_name NOT NULL,
    resource_id        UUID,                                -- NULL for CREATE until applied
    operation          change_request_op NOT NULL,
    kind               change_request_kind NOT NULL,        -- STANDARD, BREAK_GLASS (ADR-12), SYSTEM_REVERT, SYSTEM_EXPIRY; immutable
    consent            consent_rule NOT NULL,               -- ALL: every side must approve; ANY: one side suffices (ADR-13, ADR-15); immutable
    zone               VARCHAR(63),                         -- TARGET and BINDING: the platform's zone
    owner_scope        scope_path,                          -- SOURCE, TARGET
    source_scope       scope_path,                          -- BINDING
    target_scope       scope_path,                          -- BINDING
    platform_scope     scope_path,                          -- TARGET, BINDING
    interconnect_rule  VARCHAR(64),                         -- BINDING with consent ALL across scopes: matched rule, or 'default' (ADR-14)
    policy_sha256      CHAR(64) NOT NULL,                   -- governance policy in force at creation (§8.2)
    distinct_approvers_required BOOLEAN NOT NULL,           -- ADR-13 rule 7; immutable
    expected_revision  BIGINT,                              -- REQUIRED for UPDATE/DELETE
    payload            JSONB NOT NULL,                      -- normalized desired state (§7.2.3); '{}' for DELETE
    payload_sha256     CHAR(64) NOT NULL,                   -- SHA-256 of RFC 8785 (JCS) canonical payload
    status             change_request_status NOT NULL DEFAULT 'PENDING',
    decision_seq       INTEGER NOT NULL DEFAULT 0,          -- incremented by every side decision; serializes deciders (§4.3)
    external_approval_ref VARCHAR(128),                     -- upstream approval reference (DELEGATED sides) or incident reference (BREAK_GLASS)
    automation_context JSONB CHECK (automation_context IS NULL OR octet_length(automation_context::text) <= 4096), -- self-asserted, informative only
    break_glass_justification TEXT CHECK (length(break_glass_justification) <= 2048),   -- BREAK_GLASS only
    break_glass_ttl_seconds   INTEGER,                                                 -- BREAK_GLASS only
    revert_payload     JSONB,                               -- BREAK_GLASS UPDATE: normalized payload of the previous revision
    reverts_cr_id      UUID REFERENCES change_requests(id), -- SYSTEM_REVERT: the break-glass change being reverted
    depends_on_cr_id   UUID REFERENCES change_requests(id), -- BINDING CREATE filed with an inline source: the source's CREATE (§7.2.4)
    review_overdue_notified_at TIMESTAMPTZ,                 -- BREAK_GLASS_REVIEW_OVERDUE already emitted
    requested_by       VARCHAR(255) NOT NULL,
    requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by         VARCHAR(255),                        -- the principal whose action closed the request
    decided_at         TIMESTAMPTZ,
    decision_comment   TEXT CHECK (length(decision_comment) <= 2048),
    apply_error        TEXT CHECK (length(apply_error) <= 2048),
    expires_at         TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_cr_id_requester_kind UNIQUE (id, requested_by, kind),  -- target of the sides' composite foreign key
    CONSTRAINT chk_expected_revision CHECK (operation = 'CREATE' OR expected_revision IS NOT NULL),
    CONSTRAINT chk_cr_scope_columns CHECK (
        (resource_type = 'SOURCE'  AND owner_scope IS NOT NULL AND source_scope IS NULL AND target_scope IS NULL
                                   AND platform_scope IS NULL AND zone IS NULL)
     OR (resource_type = 'TARGET'  AND owner_scope IS NOT NULL AND platform_scope IS NOT NULL AND zone IS NOT NULL
                                   AND source_scope IS NULL AND target_scope IS NULL)
     OR (resource_type = 'BINDING' AND owner_scope IS NULL AND source_scope IS NOT NULL AND target_scope IS NOT NULL
                                   AND platform_scope IS NOT NULL AND zone IS NOT NULL)
    ),
    CONSTRAINT chk_interconnect_rule CHECK (
        interconnect_rule IS NULL
        OR (resource_type = 'BINDING' AND consent = 'ALL' AND source_scope <> target_scope)
    ),
    CONSTRAINT chk_system_kinds CHECK (
        (kind NOT IN ('SYSTEM_REVERT', 'SYSTEM_EXPIRY') OR consent = 'ANY')
        AND (kind <> 'SYSTEM_EXPIRY' OR (resource_type = 'BINDING' AND operation = 'DELETE'))
        AND (kind <> 'BREAK_GLASS' OR resource_type IN ('BINDING', 'SOURCE'))
    ),
    -- Reserved 'system:*' identities can never collide with people or services: usernames cannot
    -- contain ':' (§7.2.1) and SPIFFE principals start with 'spiffe://'.
    CONSTRAINT chk_break_glass CHECK (
        kind <> 'BREAK_GLASS'
        OR (requested_by NOT LIKE 'spiffe://%' AND requested_by NOT LIKE 'system:%'
            AND external_approval_ref IS NOT NULL                       -- incident reference
            AND break_glass_justification IS NOT NULL AND length(break_glass_justification) >= 20
            AND break_glass_ttl_seconds BETWEEN 300 AND 86400
            AND (operation <> 'UPDATE' OR revert_payload IS NOT NULL))
    ),
    CONSTRAINT chk_break_glass_fields CHECK (
        kind = 'BREAK_GLASS'
        OR (break_glass_justification IS NULL AND break_glass_ttl_seconds IS NULL AND revert_payload IS NULL)
    ),
    CONSTRAINT chk_revert CHECK ((kind = 'SYSTEM_REVERT') = (reverts_cr_id IS NOT NULL)),
    CONSTRAINT chk_depends_on CHECK (depends_on_cr_id IS NULL OR (resource_type = 'BINDING' AND operation = 'CREATE')),
    CONSTRAINT chk_cr_decided CHECK (
        status NOT IN ('APPLIED', 'REJECTED')
        OR (decided_by IS NOT NULL AND decided_at IS NOT NULL AND decided_by <> requested_by)
    )
);

-- ---------------------------------------------------------------------------
-- One row per side whose consent a change request needs (ADR-13, ADR-15):
--   SOURCE resources:  OWNER
--   TARGET resources:  OWNER, plus PLATFORM for material changes when the scopes differ
--   BINDING, consent ALL: TARGET, SOURCE (if its scope differs), PARTY:<name> (ADR-14)
--   BINDING, consent ANY: the sides the requester acts for among SOURCE, TARGET, PLATFORM
-- The four-eyes rules of ADR-09, ADR-11 and ADR-12 are enforced here per side.
-- ---------------------------------------------------------------------------
CREATE TABLE change_request_sides (
    change_request_id  UUID NOT NULL,
    side               VARCHAR(40) NOT NULL,                -- 'OWNER' | 'SOURCE' | 'TARGET' | 'PLATFORM' | 'PARTY:<name>'
    scope              scope_path NOT NULL,                 -- whose consent this side represents
    approval_required  BOOLEAN NOT NULL,                    -- a person (or a delegation, or break-glass) must decide it
    basis              approval_basis NOT NULL,             -- how the side is decided; fixed at creation
    requested_by       VARCHAR(255) NOT NULL,               -- copy of change_requests.requested_by (composite FK)
    cr_kind            change_request_kind NOT NULL,        -- copy of change_requests.kind (composite FK)
    decision           side_decision,
    decided_by         VARCHAR(255),
    decided_at         TIMESTAMPTZ,
    decision_comment   TEXT CHECK (length(decision_comment) <= 2048),
    ratified_by        VARCHAR(255),                        -- BREAK_GLASS sides: approver who ratified this side
    ratified_at        TIMESTAMPTZ,
    ratification_comment TEXT CHECK (length(ratification_comment) <= 2048),
    PRIMARY KEY (change_request_id, side),
    FOREIGN KEY (change_request_id, requested_by, cr_kind)
        REFERENCES change_requests (id, requested_by, kind) ON DELETE CASCADE,
    CONSTRAINT chk_side_name CHECK (
        side IN ('OWNER', 'SOURCE', 'TARGET', 'PLATFORM') OR side ~ '^PARTY:[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$'
    ),
    CONSTRAINT chk_side_party_required CHECK (side NOT LIKE 'PARTY:%' OR approval_required),
    -- A side that needs a decision can never be auto-approved (AC-24); each kind allows only its bases.
    CONSTRAINT chk_side_basis CHECK (
        (basis <> 'AUTO' OR NOT approval_required)
        AND (basis NOT IN ('HUMAN', 'DELEGATED', 'BREAK_GLASS') OR approval_required)
        AND (basis <> 'DELEGATED' OR requested_by LIKE 'spiffe://%')        -- ADR-11: machines only
        AND (cr_kind <> 'STANDARD' OR basis IN ('AUTO', 'HUMAN', 'DELEGATED'))
        AND (cr_kind <> 'BREAK_GLASS' OR basis IN ('AUTO', 'BREAK_GLASS'))
        AND ((cr_kind = 'SYSTEM_REVERT') = (basis = 'SYSTEM_REVERT'))
        AND ((cr_kind = 'SYSTEM_EXPIRY') = (basis = 'SYSTEM_EXPIRY'))
    ),
    -- Four-eyes per side (ADR-09): never the requester; the decider must fit the basis.
    CONSTRAINT chk_side_decision CHECK (
        (decision IS NULL AND decided_by IS NULL AND decided_at IS NULL)
        OR (decision IS NOT NULL AND decided_by IS NOT NULL AND decided_at IS NOT NULL
            AND decided_by <> requested_by
            AND (
                   (decision = 'DECLINED' AND basis = 'HUMAN' AND decided_by NOT LIKE 'system:%')
                OR (decision = 'APPROVED' AND (
                       (basis = 'AUTO'          AND decided_by = 'system:auto-approve')
                    OR (basis = 'DELEGATED'     AND decided_by = 'system:delegated-approval')
                    OR (basis = 'BREAK_GLASS'   AND decided_by = 'system:break-glass')
                    OR (basis = 'SYSTEM_REVERT' AND decided_by = 'system:break-glass-revert')
                    OR (basis = 'SYSTEM_EXPIRY' AND decided_by = 'system:expiry')
                    OR (basis = 'HUMAN'         AND decided_by NOT LIKE 'system:%')))
            ))
    ),
    CONSTRAINT chk_side_ratification CHECK (
        ratified_by IS NULL
        OR (basis = 'BREAK_GLASS' AND ratified_at IS NOT NULL AND ratified_by <> requested_by
            AND ratified_by NOT LIKE 'system:%' AND ratified_by NOT LIKE 'spiffe://%')
    )
);

-- Approval facts are fixed at creation (INV-14).
CREATE FUNCTION change_requests_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.resource_type <> OLD.resource_type OR NEW.resource_name <> OLD.resource_name
     OR NEW.kind <> OLD.kind OR NEW.consent <> OLD.consent OR NEW.operation <> OLD.operation
     OR NEW.zone IS DISTINCT FROM OLD.zone
     OR NEW.owner_scope IS DISTINCT FROM OLD.owner_scope
     OR NEW.source_scope IS DISTINCT FROM OLD.source_scope
     OR NEW.target_scope IS DISTINCT FROM OLD.target_scope
     OR NEW.platform_scope IS DISTINCT FROM OLD.platform_scope
     OR NEW.interconnect_rule IS DISTINCT FROM OLD.interconnect_rule
     OR NEW.policy_sha256 <> OLD.policy_sha256
     OR NEW.distinct_approvers_required <> OLD.distinct_approvers_required
     OR NEW.external_approval_ref IS DISTINCT FROM OLD.external_approval_ref
     OR NEW.break_glass_justification IS DISTINCT FROM OLD.break_glass_justification
     OR NEW.break_glass_ttl_seconds IS DISTINCT FROM OLD.break_glass_ttl_seconds
     OR NEW.revert_payload IS DISTINCT FROM OLD.revert_payload
     OR NEW.reverts_cr_id IS DISTINCT FROM OLD.reverts_cr_id
     OR NEW.depends_on_cr_id IS DISTINCT FROM OLD.depends_on_cr_id
     OR NEW.requested_by <> OLD.requested_by OR NEW.payload_sha256 <> OLD.payload_sha256
     OR (OLD.status <> 'PENDING' AND NEW.status <> OLD.status) THEN
    RAISE EXCEPTION 'immutable change_request column modified';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_change_requests_immutable BEFORE UPDATE ON change_requests
    FOR EACH ROW EXECUTE FUNCTION change_requests_immutable_guard();

CREATE FUNCTION change_request_sides_immutable_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.change_request_id <> OLD.change_request_id OR NEW.side <> OLD.side OR NEW.scope <> OLD.scope
     OR NEW.approval_required <> OLD.approval_required OR NEW.basis <> OLD.basis
     OR NEW.requested_by <> OLD.requested_by OR NEW.cr_kind <> OLD.cr_kind
     OR (OLD.decision IS NOT NULL AND (NEW.decision IS DISTINCT FROM OLD.decision
         OR NEW.decided_by IS DISTINCT FROM OLD.decided_by OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
         OR NEW.decision_comment IS DISTINCT FROM OLD.decision_comment))
     OR (OLD.ratified_by IS NOT NULL AND (NEW.ratified_by IS DISTINCT FROM OLD.ratified_by
         OR NEW.ratified_at IS DISTINCT FROM OLD.ratified_at)) THEN
    RAISE EXCEPTION 'immutable change_request_sides column modified';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER trg_change_request_sides_immutable BEFORE UPDATE ON change_request_sides
    FOR EACH ROW EXECUTE FUNCTION change_request_sides_immutable_guard();

-- Cross-row rules (INV-14, INV-18, INV-20), checked at COMMIT by deferred constraint triggers,
-- so a change request and its sides can be written in any order within one transaction.
CREATE FUNCTION change_request_check(p_id UUID) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  cr change_requests%ROWTYPE;
  n_all int; n_approved int; n_declined int; n_scopes int;
  n_owner int; n_target int; n_source int; n_platform int; n_party int; n_bad int;
  n_human int; n_human_distinct int; n_ratified int; n_ratified_distinct int; n_delegated int;
BEGIN
  SELECT * INTO cr FROM change_requests WHERE id = p_id;
  IF NOT FOUND THEN RETURN; END IF;
  SELECT count(*),
         count(*) FILTER (WHERE decision = 'APPROVED'),
         count(*) FILTER (WHERE decision = 'DECLINED'),
         count(DISTINCT scope),
         count(*) FILTER (WHERE side = 'OWNER'),
         count(*) FILTER (WHERE side = 'TARGET'),
         count(*) FILTER (WHERE side = 'SOURCE'),
         count(*) FILTER (WHERE side = 'PLATFORM'),
         count(*) FILTER (WHERE side LIKE 'PARTY:%'),
         count(*) FILTER (WHERE (side = 'OWNER'    AND scope IS DISTINCT FROM cr.owner_scope)
                             OR (side = 'SOURCE'   AND scope IS DISTINCT FROM cr.source_scope)
                             OR (side = 'TARGET'   AND scope IS DISTINCT FROM cr.target_scope)
                             OR (side = 'PLATFORM' AND scope IS DISTINCT FROM cr.platform_scope)),
         count(decided_by) FILTER (WHERE basis = 'HUMAN' AND decision = 'APPROVED'),
         count(DISTINCT decided_by) FILTER (WHERE basis = 'HUMAN' AND decision = 'APPROVED'),
         count(ratified_by),
         count(DISTINCT ratified_by),
         count(*) FILTER (WHERE basis = 'DELEGATED')
    INTO n_all, n_approved, n_declined, n_scopes, n_owner, n_target, n_source, n_platform, n_party, n_bad,
         n_human, n_human_distinct, n_ratified, n_ratified_distinct, n_delegated
    FROM change_request_sides WHERE change_request_id = p_id;

  -- Structure (ADR-13, ADR-15)
  IF n_all = 0 OR n_bad > 0 OR n_scopes <> n_all THEN
    RAISE EXCEPTION 'change request %: missing sides, side scope mismatch, or two sides with one scope', p_id;
  END IF;
  IF cr.resource_type = 'SOURCE' AND (n_owner <> 1 OR n_all <> 1) THEN
    RAISE EXCEPTION 'change request %: a source change has exactly one OWNER side', p_id;
  END IF;
  IF cr.resource_type = 'TARGET'
     AND (n_owner <> 1 OR n_target + n_source + n_party > 0 OR cr.consent <> 'ALL'
          OR (n_platform = 1 AND cr.platform_scope = cr.owner_scope)) THEN
    RAISE EXCEPTION 'change request %: a target change has OWNER and optionally PLATFORM (different scope), consent ALL', p_id;
  END IF;
  IF cr.resource_type = 'BINDING' AND n_owner > 0 THEN
    RAISE EXCEPTION 'change request %: a binding change has no OWNER side', p_id;
  END IF;
  IF cr.resource_type = 'BINDING' AND cr.consent = 'ALL' AND cr.kind IN ('STANDARD', 'BREAK_GLASS')
     AND (n_target <> 1 OR n_platform > 0
          OR n_source <> (CASE WHEN cr.source_scope <> cr.target_scope THEN 1 ELSE 0 END)
          OR (n_party > 0 AND cr.source_scope = cr.target_scope)) THEN
    RAISE EXCEPTION 'change request %: a granting binding change needs TARGET, and SOURCE exactly when the scopes differ', p_id;
  END IF;
  IF cr.resource_type = 'BINDING' AND cr.consent = 'ANY' AND n_party > 0 THEN
    RAISE EXCEPTION 'change request %: a revoking binding change has no additional parties', p_id;
  END IF;
  IF n_delegated > 0 AND cr.external_approval_ref IS NULL THEN
    RAISE EXCEPTION 'change request %: a delegated side needs an approval reference', p_id;
  END IF;
  -- Distinct people per side (INV-18)
  IF cr.distinct_approvers_required AND (n_human <> n_human_distinct OR n_ratified <> n_ratified_distinct) THEN
    RAISE EXCEPTION 'change request %: one person decided more than one side', p_id;
  END IF;
  -- Completeness (INV-14, INV-20)
  IF cr.status = 'APPLIED' THEN
    IF cr.consent = 'ANY' THEN
      IF n_approved < 1 THEN
        RAISE EXCEPTION 'change request %: applied without any approved side', p_id;
      END IF;
    ELSIF n_approved <> n_all THEN
      RAISE EXCEPTION 'change request %: applied without approval of every side', p_id;
    END IF;
  ELSIF cr.status = 'REJECTED' THEN
    IF cr.kind <> 'STANDARD'
       OR (cr.consent = 'ANY' AND n_declined <> n_all)
       OR (cr.consent = 'ALL' AND n_declined < 1) THEN
      RAISE EXCEPTION 'change request %: rejected without the required declines', p_id;
    END IF;
  END IF;
END $$;

CREATE FUNCTION change_requests_check_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM change_request_check(NEW.id); RETURN NULL; END $$;
CREATE CONSTRAINT TRIGGER trg_change_requests_check AFTER INSERT OR UPDATE ON change_requests
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION change_requests_check_trigger();

CREATE FUNCTION change_request_sides_check_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM change_request_check(NEW.change_request_id); RETURN NULL; END $$;
CREATE CONSTRAINT TRIGGER trg_change_request_sides_check AFTER INSERT OR UPDATE ON change_request_sides
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION change_request_sides_check_trigger();

CREATE UNIQUE INDEX uq_cr_one_pending_per_resource ON change_requests (resource_type, resource_name) WHERE status = 'PENDING';

ALTER TABLE bindings ADD CONSTRAINT fk_bindings_break_glass_cr
    FOREIGN KEY (break_glass_cr_id) REFERENCES change_requests(id);
CREATE INDEX idx_cr_status_zone ON change_requests (status, zone, id DESC);
CREATE INDEX idx_cr_resource ON change_requests (resource_type, resource_name, id DESC);
CREATE INDEX idx_cr_sides_pending ON change_request_sides (scope) WHERE decision IS NULL;

-- ---------------------------------------------------------------------------
-- Admin UI sessions (server-side; cookie carries an opaque random token)
-- ---------------------------------------------------------------------------
CREATE TABLE admin_sessions (
    token_sha256       CHAR(64) PRIMARY KEY,
    username           VARCHAR(255) NOT NULL,
    roles              JSONB NOT NULL,          -- [{"role":"operator","scopes":["dc/corp-prod"]}, ...]
    csrf_token         CHAR(64) NOT NULL,       -- 32 random bytes, hex
    client_ip          INET,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    authz_checked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ
);
CREATE INDEX idx_sessions_user ON admin_sessions (username);

-- ---------------------------------------------------------------------------
-- Hash-chained, append-only audit log (T-13), for every resource type
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    id                 BIGSERIAL PRIMARY KEY,
    resource_type      resource_type,
    resource_id        UUID,
    resource_name      VARCHAR(63),             -- NULL only for SESSION_*, CONFIG_* and SYSTEM_* actions
    change_request_id  UUID,
    action             VARCHAR(48) NOT NULL,
    actor              VARCHAR(255) NOT NULL,
    actor_groups       TEXT[] NOT NULL DEFAULT '{}',
    approver           VARCHAR(255),
    revision           BIGINT,
    attempt            BIGINT,
    workflow_id        VARCHAR(255),
    request_id         VARCHAR(64),
    snapshot           JSONB,                   -- NON-SECRET
    occurred_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    prev_hash          CHAR(64) NOT NULL,
    entry_hash         CHAR(64) NOT NULL UNIQUE,
    CONSTRAINT chk_audit_resource CHECK (
        action LIKE 'SESSION\_%' OR action LIKE 'CONFIG\_%' OR action LIKE 'SYSTEM\_%'
        OR (resource_type IS NOT NULL AND resource_name IS NOT NULL)
    )
);
CREATE INDEX idx_audit_resource ON audit_log (resource_type, resource_name, id DESC);

CREATE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$;
CREATE TRIGGER trg_audit_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();

-- ---------------------------------------------------------------------------
-- Read models for workload resolution (§4.5) and network flows (ADR-16)
-- ---------------------------------------------------------------------------
-- A binding is served only to callers matching BOTH its active regex and its
-- source's current regex (INV-01), so narrowing a source takes effect at once,
-- before the propagation re-apply has updated the provisioned access (§6.8).
-- An expired binding stops being served at its expiry, before the sweeper
-- revokes it (INV-25).
CREATE VIEW v_active_bindings AS
SELECT b.id, b.name, b.platform_type, b.platform, t.name AS target_name, s.name AS source_name,
       b.access_level, b.source_trust_domain, b.active_revision, b.active_source_svid_regex,
       s.svid_regex AS current_source_svid_regex,
       b.active_auth_config, b.active_spec, b.secret_store_instance, b.expires_at, b.updated_at
FROM bindings b
JOIN targets t ON t.id = b.target_id
JOIN sources s ON s.id = b.source_id
WHERE b.active_revision IS NOT NULL
  AND b.phase NOT IN ('DELETING','DELETE_FAILED')
  AND s.state <> 'RETIRED'
  AND (b.expires_at IS NULL OR b.expires_at > now());

-- Target-declared flows of served bindings. Platform, secret-store and ligo
-- flows come from the configuration and are added by the application (ADR-16).
CREATE VIEW v_active_binding_flows AS
SELECT b.id AS binding_id, f.name, f.purpose, f.protocol, f.destination, f.ports, f.tls, f.server_name
FROM bindings b
JOIN target_network_flows f ON f.target_id = b.target_id
JOIN sources s ON s.id = b.source_id
WHERE b.active_revision IS NOT NULL
  AND b.phase NOT IN ('DELETING','DELETE_FAILED')
  AND s.state <> 'RETIRED'
  AND (b.expires_at IS NULL OR b.expires_at > now());

-- ---------------------------------------------------------------------------
-- System-wide settings (exactly one row). Maintenance mode lives here so that
-- every replica sees the same value and the §6.2 transaction can check it (§10.3).
-- ---------------------------------------------------------------------------
CREATE TABLE system_settings (
    id                  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),   -- forces a single row
    maintenance_mode    BOOLEAN NOT NULL DEFAULT FALSE,
    maintenance_reason  TEXT CHECK (length(maintenance_reason) <= 512),
    changed_by          VARCHAR(255),
    changed_at          TIMESTAMPTZ
);
INSERT INTO system_settings (id) VALUES (TRUE);

-- ---------------------------------------------------------------------------
-- Transactional outbox for webhook notifications (§7.5). Rows are written in the
-- same transaction as the event they announce, and delivered by a dispatcher.
-- ---------------------------------------------------------------------------
CREATE TABLE notification_outbox (
    id               BIGSERIAL PRIMARY KEY,
    event_id         UUID NOT NULL UNIQUE,           -- UUIDv7 generated by the application; sent as eventId
    webhook          VARCHAR(64) NOT NULL,
    event            VARCHAR(64) NOT NULL,
    payload          JSONB NOT NULL,                 -- NON-SECRET
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at     TIMESTAMPTZ,
    abandoned_at     TIMESTAMPTZ,
    last_error       TEXT CHECK (length(last_error) <= 1024)
);
CREATE INDEX idx_outbox_due ON notification_outbox (next_attempt_at)
    WHERE delivered_at IS NULL AND abandoned_at IS NULL;

-- Grants (role names fixed; executed by ligo_migrator)
GRANT SELECT, INSERT, UPDATE ON sources, targets, target_access_levels TO ligo_app;   -- never hard-deleted
GRANT SELECT, INSERT, UPDATE, DELETE ON target_network_flows TO ligo_app;           -- flows are replaced on target change
GRANT SELECT, INSERT, UPDATE, DELETE ON bindings, binding_stage_state, binding_propagation_queue,
      change_requests, admin_sessions TO ligo_app;
GRANT SELECT, INSERT, UPDATE ON change_request_sides TO ligo_app;   -- no DELETE: decisions are never removed
GRANT SELECT, INSERT ON audit_log TO ligo_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO ligo_app;
GRANT SELECT, UPDATE ON system_settings TO ligo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_outbox TO ligo_app;
GRANT USAGE ON SEQUENCE notification_outbox_id_seq TO ligo_app;
GRANT SELECT ON v_active_bindings, v_active_binding_flows TO ligo_reader;
