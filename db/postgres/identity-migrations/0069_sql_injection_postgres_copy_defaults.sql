-- Upgrade only the two exact PostgreSQL workshop defaults that retained SQLite error wording.
-- Whole-document and provenance guards preserve instructor-owned content.
CREATE TEMP TABLE sql_copy_defaults(
  objective_id text PRIMARY KEY, old_value jsonb NOT NULL, new_value jsonb NOT NULL,
  old_hash text NOT NULL, new_hash text NOT NULL
) ON COMMIT DROP;

INSERT INTO sql_copy_defaults VALUES
  ('sqli_1',$old_sqli_1${"title":"Trigger SQL Syntax Error","difficulty":"Beginner","hints":["Try sending a character that SQL uses as a string delimiter","Single quotes ( ' ) are used to wrap string values in SQL queries","In the ARIA chat, search for a product with a name containing just a single quote: search for products named '"],"examples":["search for products named '","find '"],"approach":"In vulnerable mode, the ARIA agent's product search concatenates your input directly into a SQL LIKE query without sanitization:\n  SELECT ... FROM products WHERE name LIKE '%YOUR_INPUT%'\n\nA single quote (') breaks the string delimiter, resulting in malformed SQL:\n  WHERE name LIKE '%'%'\nThis causes SQLITE_ERROR and reveals the injection point. This is the classic first test for SQL injection — if the application returns an error on a single quote, the field is injectable.","tips":["Error messages like 'SQLITE_ERROR: unrecognized token' confirm the injection point","In a real app this error would be hidden, but the behavior change (error vs. empty result) is still detectable","This is Step 1 of any SQL injection assessment: the single-quote test"]}$old_sqli_1$::jsonb,$new_sqli_1${"title":"Trigger SQL Syntax Error","difficulty":"Beginner","hints":["Try sending a character that SQL uses as a string delimiter","Single quotes ( ' ) are used to wrap string values in SQL queries","In the ARIA chat, search for a product with a name containing just a single quote: search for products named '"],"examples":["search for products named '","find '"],"approach":"In vulnerable mode, the ARIA agent's product search concatenates your input directly into a PostgreSQL LIKE query without sanitization:\n  SELECT ... FROM products WHERE name LIKE '%YOUR_INPUT%'\n\nA single quote (') breaks the string delimiter and PostgreSQL reports a syntax or unterminated-quoted-string error. That real database error reveals the injection point. In fixed mode the same character is bound as data and cannot change the query structure.","tips":["A PostgreSQL syntax or unterminated-quoted-string error confirms that the vulnerable query structure was changed.","In a real application this error may be hidden, but the behavior change (error versus an empty result) can still reveal the injection point.","This is Step 1 of a SQL injection assessment: compare the single-quote probe with a bound literal search."]}$new_sqli_1$::jsonb,'6d6820608d436c3c4e474aee0b6bf2cbf2ac035aaddf6784fa3ad3135feffe48','301f5d94938aee04e339ba3fc9d5a86ffeda3cef6cb3bd6413a19f45761846d5'),
  ('sqli_3',$old_sqli_3${"title":"Determine Column Count via ORDER BY","difficulty":"Beginner","hints":["Before performing UNION injection you need to know how many columns the original query returns","ORDER BY can reference columns by position number — ORDER BY 1 sorts by column 1, ORDER BY 8 by column 8","Try increasing the ORDER BY number until you get an error — the last successful number is the column count"],"examples":["search for %' ORDER BY 1--","search for %' ORDER BY 5--","search for %' ORDER BY 8--","search for %' ORDER BY 9--  (this should error — 9 exceeds column count)"],"approach":"The products table SELECT returns 8 columns: id, product_id, name, category, price, description, stock, available.\n\n  Injected: WHERE name LIKE '%' ORDER BY 8-- (succeeds — 8 columns exist)\n  Injected: WHERE name LIKE '%' ORDER BY 9-- (errors — column 9 doesn't exist)\n\nThis technique from PortSwigger's UNION attack guide is used to determine the column count before crafting a UNION SELECT. The number where ORDER BY starts failing (N+1) tells you the exact column count (N).","tips":["Binary search works: if ORDER BY 4 succeeds and ORDER BY 8 errors, try ORDER BY 6...","ORDER BY errors are different from syntax errors — ORDER BY 9 says 'no such column: 9', not a parse error","You can also use ORDER BY with column names if you already know the schema"]}$old_sqli_3$::jsonb,$new_sqli_3${"title":"Determine Column Count via ORDER BY","difficulty":"Beginner","hints":["Before performing UNION injection you need to know how many columns the original query returns","ORDER BY can reference columns by position number — ORDER BY 1 sorts by column 1, ORDER BY 8 by column 8","Try increasing the ORDER BY number until you get an error — the last successful number is the column count"],"examples":["search for %' ORDER BY 1--","search for %' ORDER BY 5--","search for %' ORDER BY 8--","search for %' ORDER BY 9--  (this should error — 9 exceeds column count)"],"approach":"The products SELECT returns 8 columns: id, product_id, name, category, price, description, stock, available.\n\n  Injected: WHERE name LIKE '%' ORDER BY 8-- (succeeds — position 8 is in the select list)\n  Injected: WHERE name LIKE '%' ORDER BY 9-- (PostgreSQL rejects position 9 because it is outside the select list)\n\nUse separate ordered probes and retain both results. The highest successful position followed by the next-position boundary error establishes the column count before a UNION SELECT.","tips":["Keep the successful ORDER BY 8 receipt and the failing ORDER BY 9 receipt; either probe alone is incomplete evidence.","PostgreSQL reports that ORDER BY position 9 is not in the select list; it does not emit SQLite's 'no such column' error.","You can also use ORDER BY with column names if you already know the schema."]}$new_sqli_3$::jsonb,'035bbd1ff43ddd8ba244fe148e5fdb90ab35a04020e13488587b795f4cd8203f','0e619757c02031bbfd77b00fb1a0f02bf3a676921993d4070179f607bf0efe06');

CREATE TEMP TABLE sql_copy_changed(objective_id text PRIMARY KEY) ON COMMIT DROP;

WITH changed AS (
  UPDATE workshop_platform.objectives objective
  SET solution_content=defaults.new_value,updated_at=now()
  FROM sql_copy_defaults defaults
  WHERE objective.workshop_key='sql_injection_workshop'
    AND objective.objective_id=defaults.objective_id
    AND objective.updated_by IS NULL
    AND objective.solution_content=defaults.old_value
    AND EXISTS (
      SELECT 1 FROM workshop_platform.catalog_field_defaults provenance
      WHERE provenance.entity_kind='objective'
        AND provenance.workshop_key=objective.workshop_key
        AND provenance.objective_id=objective.objective_id
        AND provenance.field_name='solution_content'
        AND ((provenance.provenance_state='legacy_unknown'
              AND provenance.observed_document=jsonb_build_object('present',true,'value',defaults.old_value))
          OR (provenance.provenance_state='managed'
              AND provenance.applied_default_hash=defaults.old_hash
              AND provenance.applied_default_document=jsonb_build_object('present',true,'value',defaults.old_value)))
    )
  RETURNING objective.objective_id
)
INSERT INTO sql_copy_changed SELECT objective_id FROM changed;

UPDATE workshop_platform.catalog_field_defaults provenance
SET provenance_state='managed',
    source_version='workshop-defaults-2026-09-18-v5-postgres-sql-copy',
    source_hash=defaults.new_hash,
    source_document=jsonb_build_object('present',true,'value',defaults.new_value),
    applied_default_version='workshop-defaults-2026-09-18-v5-postgres-sql-copy',
    applied_default_hash=defaults.new_hash,
    applied_default_document=jsonb_build_object('present',true,'value',defaults.new_value),
    observed_document=jsonb_build_object('present',true,'value',defaults.new_value),
    updated_at=now()
FROM sql_copy_defaults defaults
JOIN sql_copy_changed changed USING(objective_id)
WHERE provenance.entity_kind='objective'
  AND provenance.workshop_key='sql_injection_workshop'
  AND provenance.objective_id=defaults.objective_id
  AND provenance.field_name='solution_content'
  AND provenance.provenance_state<>'custom'
  AND (provenance.provenance_state='legacy_unknown'
    OR (provenance.provenance_state='managed'
      AND provenance.applied_default_hash=defaults.old_hash
      AND provenance.applied_default_document=jsonb_build_object('present',true,'value',defaults.old_value)));

UPDATE workshop_platform.config_revision
SET revision=revision+1,updated_at=now()
WHERE id=1 AND EXISTS(SELECT 1 FROM sql_copy_changed);

DROP TABLE sql_copy_changed;
DROP TABLE sql_copy_defaults;
