-- A source's and a target's `labels` become `annotations`, the name of a
-- binding's map since migration 002 (.specs/ligo-resource-annotations.md).
-- No view, function or trigger names the columns.

ALTER TABLE sources RENAME COLUMN labels TO annotations;
ALTER TABLE targets RENAME COLUMN labels TO annotations;
