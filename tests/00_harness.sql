-- test harness (superuser creates, roles use)
CREATE SCHEMA IF NOT EXISTS tt;
CREATE TABLE IF NOT EXISTS tt.res(label text, expect text, got text, ok boolean, detail text);
GRANT USAGE ON SCHEMA tt TO PUBLIC; GRANT ALL ON tt.res TO PUBLIC;
CREATE OR REPLACE FUNCTION tt.try(p_label text, p_expect text, p_sql text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE g text; d text := '';
BEGIN
  BEGIN
    EXECUTE p_sql; g := 'ok';
  EXCEPTION WHEN others THEN g := 'err'; d := SQLSTATE || ' ' || left(SQLERRM, 140);
  END;
  INSERT INTO tt.res VALUES (p_label, p_expect, g, g = p_expect, d);
END $$;
-- scalar check: expects query returning boolean true
CREATE OR REPLACE FUNCTION tt.chk(p_label text, p_sql text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE b boolean; d text := '';
BEGIN
  BEGIN EXECUTE p_sql INTO b; EXCEPTION WHEN others THEN b := false; d := SQLSTATE||' '||left(SQLERRM,140); END;
  INSERT INTO tt.res VALUES (p_label, 'true', coalesce(b::text,'null'), coalesce(b,false), d);
END $$;
GRANT EXECUTE ON FUNCTION tt.try(text,text,text), tt.chk(text,text) TO PUBLIC;
