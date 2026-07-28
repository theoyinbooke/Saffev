-- Sanitized OpenCode fixture: schema mirrors the columns the adapter queries
-- (session / message / part with JSON `data` blobs). Session ses_good is a
-- complete two-message exchange with a tool part; ses_bad carries an
-- unparseable data blob to prove non-fatal degradation (json_extract -> NULL).
CREATE TABLE session (id TEXT PRIMARY KEY, title TEXT, directory TEXT, time_created INTEGER, time_updated INTEGER);
CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT, time_created INTEGER);
CREATE TABLE part (id TEXT PRIMARY KEY, session_id TEXT, message_id TEXT, data TEXT, time_created INTEGER);
INSERT INTO session VALUES ('ses_good', 'Add healthcheck endpoint', '/home/dev/fixture-proj', 1784900000000, 1784900600000);
INSERT INTO message VALUES ('msg_u1', 'ses_good', '{"role":"user"}', 1784900000000);
INSERT INTO message VALUES ('msg_a1', 'ses_good', '{"role":"assistant","providerID":"anthropic","modelID":"claude-opus-4-8","tokens":{"input":900,"output":150,"cache":{"read":100,"write":50}}}', 1784900010000);
INSERT INTO part VALUES ('prt_1', 'ses_good', 'msg_u1', '{"type":"text","text":"add a healthcheck endpoint"}', 1784900000000);
INSERT INTO part VALUES ('prt_2', 'ses_good', 'msg_a1', '{"type":"text","text":"Added /healthz."}', 1784900010000);
INSERT INTO part VALUES ('prt_3', 'ses_good', 'msg_a1', '{"type":"tool","tool":"bash","state":{"output":"cargo check: ok"}}', 1784900011000);
INSERT INTO session VALUES ('ses_bad', 'Corrupted blob session', '/home/dev/fixture-proj', 1784900100000, 1784900100000);
INSERT INTO message VALUES ('msg_x1', 'ses_bad', 'this is not json at all', 1784900100000);
