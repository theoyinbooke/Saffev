-- Sanitized Goose fixture: schema subset matching block/goose schema v15
-- (sessions + messages, the columns the adapter reads). Session 20260715_1
-- is a complete exchange with a tool round-trip; 20260715_2 carries an
-- unparseable content_json blob (non-fatal degradation); sub-1 is a
-- sub_agent side thread and arch-1 is archived - both must not list.
CREATE TABLE sessions (
  id TEXT PRIMARY KEY, name TEXT, description TEXT DEFAULT '', user_set_name BOOLEAN,
  session_type TEXT DEFAULT 'user', working_dir TEXT NOT NULL,
  created_at TIMESTAMP, updated_at TIMESTAMP, extension_data TEXT DEFAULT '{}',
  total_tokens INTEGER, input_tokens INTEGER, output_tokens INTEGER,
  cache_read_tokens INTEGER, cache_write_tokens INTEGER,
  accumulated_total_tokens INTEGER, accumulated_input_tokens INTEGER,
  accumulated_output_tokens INTEGER, accumulated_cache_read_tokens INTEGER,
  accumulated_cache_write_tokens INTEGER, accumulated_cost REAL,
  provider_name TEXT, model_config_json TEXT, goose_mode TEXT DEFAULT 'auto',
  archived_at TIMESTAMP, project_id TEXT, parent_session_id TEXT
);
CREATE TABLE messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT, session_id TEXT,
  role TEXT, content_json TEXT NOT NULL, created_timestamp INTEGER,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, tokens INTEGER, metadata_json TEXT
);
INSERT INTO sessions (id, name, user_set_name, session_type, working_dir, created_at, updated_at,
  input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
  accumulated_input_tokens, accumulated_output_tokens, accumulated_cache_read_tokens,
  accumulated_cache_write_tokens, accumulated_cost, provider_name, model_config_json)
VALUES ('20260715_1', 'Fix flaky test', 0, 'user', '/home/dev/fixture-proj',
  '2026-07-15 09:00:00', '2026-07-15 09:06:42',
  100, 10, 0, 0,
  8500, 212, 8000, 300, 0.0031, 'anthropic', '{"model_name":"claude-sonnet-4-5"}');
INSERT INTO messages (message_id, session_id, role, content_json, created_timestamp, metadata_json)
VALUES ('msg_1', '20260715_1', 'user', '[{"type":"text","text":"run the tests"}]', 1784710800, '{"userVisible":true}');
INSERT INTO messages (message_id, session_id, role, content_json, created_timestamp, metadata_json)
VALUES ('msg_2', '20260715_1', 'assistant',
  '[{"type":"thinking","thinking":"cargo test should do"},{"type":"text","text":"Running the suite."},{"type":"toolRequest","id":"toolu_9a2b","toolCall":{"status":"success","value":{"name":"developer__shell","arguments":{"command":"cargo test"}}}}]',
  1784710802, '{"inference":{"provider":"anthropic","requestedModel":"claude-sonnet-4-5"}}');
INSERT INTO messages (message_id, session_id, role, content_json, created_timestamp, metadata_json)
VALUES ('msg_3', '20260715_1', 'user',
  '[{"type":"toolResponse","id":"toolu_9a2b","toolResult":{"status":"success","value":{"content":[{"type":"text","text":"test result: ok. 42 passed"}],"isError":false}}}]',
  1784710805, '{}');
INSERT INTO sessions (id, name, session_type, working_dir, created_at, updated_at,
  accumulated_input_tokens, accumulated_output_tokens, provider_name, model_config_json)
VALUES ('20260715_2', 'Corrupted blob session', 'user', '/home/dev/fixture-proj',
  '2026-07-15 10:00:00', '2026-07-15 10:00:00', 50, 5, 'anthropic', '{"model_name":"claude-sonnet-4-5"}');
INSERT INTO messages (message_id, session_id, role, content_json, created_timestamp)
VALUES ('msg_x', '20260715_2', 'assistant', 'this is not json at all', 1784714400);
INSERT INTO sessions (id, name, session_type, working_dir, created_at, updated_at)
VALUES ('sub-1', 'Side thread', 'sub_agent', '/home/dev/fixture-proj', '2026-07-15 11:00:00', '2026-07-15 11:00:00');
INSERT INTO sessions (id, name, session_type, working_dir, created_at, updated_at, archived_at)
VALUES ('arch-1', 'Archived away', 'user', '/home/dev/fixture-proj', '2026-07-15 12:00:00', '2026-07-15 12:00:00', '2026-07-16 00:00:00');
