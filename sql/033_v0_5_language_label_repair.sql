-- One-shot repair: an earlier bug in update_language called
-- str() on every top-level value of the labels payload, which
-- when the values were section sub-objects produced Python-repr
-- strings (e.g. "{'Cancel': 'Annuler'}") instead of JSON objects.
-- Walk every language row and re-parse any such top-level string
-- by replacing single quotes with double quotes.
--
-- Best-effort: translations containing apostrophes / unicode
-- escapes won't survive the simple quote-swap and will be left as
-- a string (next save will overwrite them). Re-enter those by
-- hand if needed.
--
-- Idempotent: a row whose top-level values are all proper objects
-- (already healthy) is a no-op.

DO $$
DECLARE
  r          RECORD;
  k          TEXT;
  v_text     TEXT;
  parsed_v   JSONB;
  new_labels JSONB;
BEGIN
  FOR r IN SELECT code, labels FROM language LOOP
    new_labels := r.labels;
    FOR k IN SELECT key FROM jsonb_each(r.labels) LOOP
      -- Top-level value is a JSON STRING that *looks* like a dict?
      IF jsonb_typeof(r.labels -> k) = 'string' THEN
        v_text := r.labels ->> k;
        IF v_text LIKE '{%}' THEN
          BEGIN
            parsed_v := replace(v_text, '''', '"')::jsonb;
            IF jsonb_typeof(parsed_v) = 'object' THEN
              new_labels := new_labels || jsonb_build_object(k, parsed_v);
            END IF;
          EXCEPTION WHEN OTHERS THEN
            -- leave the string as-is on parse failure
            NULL;
          END;
        END IF;
      END IF;
    END LOOP;
    IF new_labels IS DISTINCT FROM r.labels THEN
      UPDATE language SET labels = new_labels WHERE code = r.code;
    END IF;
  END LOOP;
END$$;
