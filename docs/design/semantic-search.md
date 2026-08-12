# Design note — semantic search over the archive

> Status: **design only, not built.** This note exists so the feature can be
> judged before any code is written, per the repo's "don't build a reader (or
> here, an index) speculatively" rule. Nothing below ships until the open
> questions at the end are answered against a real archive.

## The problem

Full-text search (FTS5 over `archived_messages`, already shipped) answers
"which session contains the string `NullPointerException`". It cannot answer
"the session where I fixed the auth race" when those words never appear
literally. That is a semantic-similarity query, and it is the natural next step
for a product whose wedge is *keeping* the history: the value of a durable
archive rises sharply if you can actually find things in it by meaning.

## The hard constraints (these kill most obvious designs)

1. **VRAM contention is real and validated.** Running any model through the
   user's own engine thrashes a 16 GB Mac (this is why judges/guards are
   async-only, never inline). Embedding generation is a model call. Therefore
   embedding **must** be batch, idle-scheduled, and never on any interactive
   path — not on archive-write, not on query.
2. **Fully offline.** No hosted embedding API, ever. The only model available
   is the one the user already runs locally (Ollama / LM Studio / llama.cpp all
   expose an embeddings endpoint).
3. **Encrypted at rest.** Vectors derived from transcript text are as sensitive
   as the transcripts. They live in the SQLCipher store, not a sidecar file.
4. **Index size is accounted, not hidden.** The DB is already 336 MB on this
   maintainer's machine (task #5 surfaced it). A float32 index over hundreds of
   thousands of message chunks is not free; the design must state the cost and
   let the user opt in and see it.
5. **Fail-open and additive.** Semantic search is a second lens beside FTS, not
   a replacement. If the index is absent, stale, or the model is down, search
   silently falls back to FTS. It never blocks, never errors the archive.

## Proposed shape

### Embedding generation — a third scheduler tick

A new opt-in `[archive] embed` flag and an `embed_model` (must be an
embeddings-capable local model, e.g. `nomic-embed-text` on Ollama). A scheduler
loop like `spawn_archive_scheduler`, but:

- Runs on a **long** cadence (e.g. 30 min) and only when the machine looks
  idle (no proxied request in the last N minutes — we already track request
  timestamps). Contention avoidance is the whole game.
- Processes a **bounded batch** per tick (e.g. 200 chunks), so a cold start on
  a huge archive spreads over hours instead of pinning the GPU. Progress is a
  visible number, not a spinner.
- Chunks messages to a fixed token budget (≈256 tokens, overlap ≈32) — one
  embedding per chunk, not per message; long tool outputs otherwise dominate.
- Skips already-embedded chunks via a content hash, exactly like the archive's
  incremental snapshot skip.

### Storage — a vector table, no new engine

```
archived_embeddings(
  chunk_id      INTEGER PRIMARY KEY,
  message_id    INTEGER,        -- FK into archived_messages
  session_id    TEXT,
  model         TEXT,           -- which embed model produced this (re-embed on change)
  dim           INTEGER,
  vec           BLOB,           -- little-endian f32[dim]
  content_hash  TEXT
)
```

New schema migration (v11). No new dependency for storage — vectors are BLOBs.

### Query — brute-force cosine first, ANN only if measured to need it

For an archive of even 200k chunks, a brute-force cosine scan in Rust
(SIMD-friendly f32 dot products) is on the order of tens of milliseconds — very
likely fast enough, and it adds **zero** dependencies and **zero** index-build
cost. The honest engineering call is: **ship brute-force, measure, and only add
an ANN index (HNSW via `hnsw_rs`, or `sqlite-vec` if we accept the extension)
if the measured p95 on a real archive exceeds a threshold.** Do not import an
ANN library speculatively.

Query flow: embed the query string once (through the same local model, on the
query path — this is the one unavoidable interactive model call; it is a single
short embedding, ~10 ms, not a generation), cosine against the table, return
top-k message/session ids, hydrate through the existing session views. The
Studio search box gains a "by meaning" toggle beside the existing FTS search;
results say which lens produced them (the UI already states coverage honestly).

## What this is NOT

- Not a RAG/chat-over-history feature. This is retrieval only — find the
  session, then the user reads it. No generation, no summarization on this path
  (that stays the explicit, off-by-default Codex summary).
- Not a reranker. Cosine top-k is the whole ranking in v1.
- Not cross-device. The index is local, like everything else.

## Open questions (must be answered on a real archive before building)

1. **Is brute-force actually fast enough** at this maintainer's real archive
   size? Measure before importing any ANN crate. (Bench harness first, same as
   every other gauntlet.)
2. **Which local embedding model** is both good enough and light enough to run
   idle-batched without disrupting the user's foreground engine? Needs a small
   retrieval-quality eval (a labeled "these 5 sessions are about X" set).
3. **Index size in practice** — measure bytes/chunk × chunk count on the real
   archive; decide the default (probably off, opt-in, with the size shown).
4. **Re-embedding policy** on model change — the `model` column makes it
   possible; the cost (re-run the whole batch) must be surfaced like the
   redaction re-archive is.

Until (1) and (2) are answered with numbers, this stays a design note.
