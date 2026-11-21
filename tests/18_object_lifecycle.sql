-- AUDIT-007: database guards mirror Rust Object and ObjectVersion lifecycles
\set ON_ERROR_STOP on
SET client_min_messages=warning;

INSERT INTO objects(tenant_id,object_id,state)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001','18000000-0000-0000-0000-000000000001','draft');
SELECT tt.try('AUDIT-007 new object cannot start Validating','err',
 $q$INSERT INTO objects(tenant_id,object_id,state,published_version_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001','18000000-0000-0000-0000-000000000004','validating',NULL)$q$);
SELECT tt.try('AUDIT-007 new object version cannot start Published','err',
 $q$INSERT INTO object_versions(tenant_id,object_id,object_version_id,version_number,status)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000001','18000000-0000-0000-0000-000000000001','18000000-0000-0000-0000-000000000005',3,'published')$q$);

INSERT INTO object_versions(tenant_id,object_id,object_version_id,version_number,status)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001','18000000-0000-0000-0000-000000000001','18000000-0000-0000-0000-000000000002',1,'draft'),
       ('aaaaaaaa-0000-0000-0000-000000000001','18000000-0000-0000-0000-000000000001','18000000-0000-0000-0000-000000000003',2,'draft');

SELECT tt.try('AUDIT-007 Draft -> Superseded is rejected','err',
 $q$UPDATE object_versions SET status='superseded' WHERE object_version_id='18000000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('AUDIT-007 Draft version number is immutable','err',
 $q$UPDATE object_versions SET version_number=9 WHERE object_version_id='18000000-0000-0000-0000-000000000002'$q$);
UPDATE object_versions SET status='published' WHERE object_version_id='18000000-0000-0000-0000-000000000002';
SELECT tt.try('AUDIT-007 Published -> Draft is rejected','err',
 $q$UPDATE object_versions SET status='draft' WHERE object_version_id='18000000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('AUDIT-007 Published content is immutable','err',
 $q$UPDATE object_versions SET config='{"tampered":true}' WHERE object_version_id='18000000-0000-0000-0000-000000000002'$q$);
UPDATE object_versions SET status='superseded' WHERE object_version_id='18000000-0000-0000-0000-000000000002';
SELECT tt.try('AUDIT-007 Superseded is terminal','err',
 $q$UPDATE object_versions SET status='published' WHERE object_version_id='18000000-0000-0000-0000-000000000002'$q$);
SELECT tt.try('AUDIT-007 Superseded version cannot be deleted','err',
 $q$DELETE FROM object_versions WHERE object_version_id='18000000-0000-0000-0000-000000000002'$q$);

SELECT tt.try('AUDIT-007 Draft -> Active shortcut is rejected','err',
 $q$UPDATE objects SET state='active', published_version_id='18000000-0000-0000-0000-000000000002' WHERE object_id='18000000-0000-0000-0000-000000000001'$q$);
UPDATE objects SET state='validating' WHERE object_id='18000000-0000-0000-0000-000000000001';
SELECT tt.try('AUDIT-007 Validating -> Archived shortcut is rejected','err',
 $q$UPDATE objects SET state='archived' WHERE object_id='18000000-0000-0000-0000-000000000001'$q$);
-- Complete a valid first publication, then verify Archived is terminal.
UPDATE object_versions SET status='published'
 WHERE object_version_id='18000000-0000-0000-0000-000000000003';
UPDATE objects SET state='active', published_version_id='18000000-0000-0000-0000-000000000003'
 WHERE object_id='18000000-0000-0000-0000-000000000001';
UPDATE objects SET state='archived'
 WHERE object_id='18000000-0000-0000-0000-000000000001';
SELECT tt.try('AUDIT-007 Archived object cannot be revived','err',
 $q$UPDATE objects SET state='active' WHERE object_id='18000000-0000-0000-0000-000000000001'$q$);
SELECT tt.try('AUDIT-007 Archived published pointer cannot be replaced','err',
 $q$UPDATE objects SET published_version_id=NULL WHERE object_id='18000000-0000-0000-0000-000000000001'$q$);


-- R3-01 / QSA-014: replacing the currently published version is legal only
-- when the replacement is published and the Object pointer moves atomically.
INSERT INTO objects(tenant_id,object_id,state)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
        '18000000-0000-0000-0000-000000000010','draft');
INSERT INTO object_versions(tenant_id,object_id,object_version_id,version_number,status)
VALUES ('aaaaaaaa-0000-0000-0000-000000000001',
        '18000000-0000-0000-0000-000000000010',
        '18000000-0000-0000-0000-000000000011',1,'draft'),
       ('aaaaaaaa-0000-0000-0000-000000000001',
        '18000000-0000-0000-0000-000000000010',
        '18000000-0000-0000-0000-000000000012',2,'draft');
UPDATE objects SET state='validating'
 WHERE object_id='18000000-0000-0000-0000-000000000010';
UPDATE object_versions SET status='published'
 WHERE object_version_id='18000000-0000-0000-0000-000000000011';
UPDATE objects SET state='active', published_version_id='18000000-0000-0000-0000-000000000011'
 WHERE object_id='18000000-0000-0000-0000-000000000010';

SELECT tt.try('R3-01 cannot supersede the pointed-to version without moving the pointer','err',
 $q$UPDATE object_versions SET status='superseded'
      WHERE object_version_id='18000000-0000-0000-0000-000000000011';
    SET CONSTRAINTS trg_ov_superseded_pointer_check IMMEDIATE$q$);
SELECT tt.try('R3-01 replacement publication and pointer move commit atomically','ok',
 $q$UPDATE object_versions SET status='superseded'
      WHERE object_version_id='18000000-0000-0000-0000-000000000011';
    UPDATE object_versions SET status='published'
      WHERE object_version_id='18000000-0000-0000-0000-000000000012';
    UPDATE objects SET published_version_id='18000000-0000-0000-0000-000000000012'
      WHERE object_id='18000000-0000-0000-0000-000000000010'$q$);
SELECT tt.chk('R3-01 replacement is the active published pointer',
 $q$SELECT o.state='active' AND o.published_version_id='18000000-0000-0000-0000-000000000012'
       AND old.status='superseded' AND new.status='published'
     FROM objects o
     JOIN object_versions old ON old.object_id=o.object_id
     JOIN object_versions new ON new.object_id=o.object_id
    WHERE o.object_id='18000000-0000-0000-0000-000000000010'
      AND old.object_version_id='18000000-0000-0000-0000-000000000011'
      AND new.object_version_id='18000000-0000-0000-0000-000000000012'$q$);
