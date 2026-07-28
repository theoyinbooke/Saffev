-- Sanitized Cursor fixture: cursorDiskKV with a composerData session record
-- and its bubbles (headers order the conversation). composerData:comp-broken
-- holds an unparseable value to prove non-fatal degradation (skipped in list).
CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value TEXT);
INSERT INTO cursorDiskKV VALUES ('composerData:comp-0001', '{"composerId":"comp-0001","name":"Refactor auth flow","modelConfig":{"modelName":"claude-sonnet-4-6"},"workspaceIdentifier":{"uri":{"fsPath":"/home/dev/fixture-proj"}},"createdAt":1784900000000,"lastUpdatedAt":1784900600000,"fullConversationHeadersOnly":[{"bubbleId":"b1","type":1},{"bubbleId":"b2","type":2}]}');
INSERT INTO cursorDiskKV VALUES ('bubbleId:comp-0001:b1', '{"text":"please refactor the auth flow","timingInfo":{"clientEndTime":1784900010000}}');
INSERT INTO cursorDiskKV VALUES ('bubbleId:comp-0001:b2', '{"thinking":{"text":"plan: extract middleware"},"text":"Done - extracted auth middleware.","toolFormerData":{"name":"edit_file","params":"{\"file\":\"src/auth.ts\"}"},"timingInfo":{"clientEndTime":1784900020000}}');
INSERT INTO cursorDiskKV VALUES ('composerData:comp-broken', '{ not valid json at all');
