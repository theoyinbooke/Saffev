//! Incremental ("tail") parsing of append-only JSONL transcripts.
//!
//! Claude Code and Codex append one JSON record per line to a session file for
//! as long as the session runs, and those files get big: 100MB+ transcripts and
//! gigabyte Codex rollouts exist on real machines. Every preservation snapshot
//! (every few minutes) and every list refresh used to re-read and re-parse the
//! whole file of each session that had changed, i.e. the ones being written
//! right now.
//!
//! [`parse`] remembers, per file, how far it has parsed and the reader's parse
//! state at that point. When the file has only grown, it resumes from there,
//! so one new message costs one new line. Anything else (the file shrank, was
//! replaced, or its bytes before the resume point changed) falls back to a full
//! parse. Either way the result is exactly what a full parse would produce:
//! lines are fed to the same state machine in the same order.
//!
//! ## A trailing partial line
//!
//! A writer may be mid-line when we read. Only newline-terminated lines advance
//! the remembered offset. A trailing unterminated fragment is fed to a *copy*
//! of the state for this call's answer (matching what a full parse sees), and is
//! re-read next time, once it is complete.
//!
//! ## Memory
//!
//! Cached states hold extracted messages (tool output is already capped by the
//! readers), so the cache is bounded two ways: a total byte budget with
//! least-recently-used eviction, and idle expiry. A session nobody re-parses for
//! [`IDLE_EXPIRY`] (it stopped growing; the archive's change check skips it)
//! is dropped, so in steady state only actively growing sessions stay cached.

use std::any::Any;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A reader's resumable parse state.
pub(crate) trait LineState: Clone + Send + 'static {
    /// Consume one line (without its line terminator; may be empty or invalid
    /// JSON, which the state must tolerate exactly as a full parse does).
    fn feed(&mut self, line: &str);
    /// Approximate heap bytes held, for the cache budget.
    fn weight(&self) -> usize;
}

/// Total weight of cached states.
const BUDGET_BYTES: usize = 64 * 1024 * 1024;
/// Drop a cached state nobody has used for this long.
const IDLE_EXPIRY: Duration = Duration::from_secs(15 * 60);
/// Bytes before the resume point that must be unchanged to resume.
const GUARD_BYTES: u64 = 256;

/// Identity of the file a cached state came from: a replaced file (new inode)
/// never resumes from the old one's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    #[cfg(unix)]
    fn of(m: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        FileId {
            dev: m.dev(),
            ino: m.ino(),
        }
    }

    #[cfg(not(unix))]
    fn of(m: &std::fs::Metadata) -> Self {
        // No inode: the creation time is the closest stable identity.
        let created = m
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        FileId {
            dev: 0,
            ino: created,
        }
    }
}

struct Entry {
    id: FileId,
    /// Bytes consumed so far (always at a line boundary).
    offset: u64,
    /// The last up-to-[`GUARD_BYTES`] bytes before `offset`.
    guard: Vec<u8>,
    state: Box<dyn Any + Send>,
    weight: usize,
    used: Instant,
}

/// Key: the file plus the state's flavour (e.g. metadata-only vs with
/// messages), so two parse modes of one file never share a state.
type Key = (PathBuf, &'static str);

#[derive(Default)]
struct Cache {
    entries: HashMap<Key, Entry>,
    total: usize,
}

impl Cache {
    fn take(&mut self, key: &Key) -> Option<Entry> {
        let e = self.entries.remove(key)?;
        self.total = self.total.saturating_sub(e.weight);
        Some(e)
    }

    fn put(&mut self, key: Key, entry: Entry) {
        let now = Instant::now();
        self.entries
            .retain(|_, e| now.duration_since(e.used) < IDLE_EXPIRY);
        self.total = self.entries.values().map(|e| e.weight).sum();
        if entry.weight > BUDGET_BYTES {
            return; // would evict everything else and still not fit
        }
        while self.total + entry.weight > BUDGET_BYTES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.used)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(e) = self.entries.remove(&oldest) {
                self.total = self.total.saturating_sub(e.weight);
            }
        }
        self.total += entry.weight;
        self.entries.insert(key, entry);
    }
}

fn cache() -> &'static Mutex<Cache> {
    static C: std::sync::OnceLock<Mutex<Cache>> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(Cache::default()))
}

/// Parse `path` line by line into a state, resuming a remembered state when
/// the file has only grown since. `flavour` separates parse modes of one file;
/// `init` builds a fresh state. `None` only when the file cannot be opened.
pub(crate) fn parse<S: LineState>(
    path: &Path,
    flavour: &'static str,
    init: impl FnOnce() -> S,
) -> Option<S> {
    let mut file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    let id = FileId::of(&meta);
    let len = meta.len();
    let key: Key = (path.to_path_buf(), flavour);

    let cached = cache().lock().ok().and_then(|mut c| c.take(&key));
    let resumed = cached.and_then(|e| {
        if e.id != id || e.offset > len || !guard_matches(&mut file, e.offset, &e.guard) {
            return None;
        }
        let state = e.state.downcast::<S>().ok()?;
        Some((e.offset, *state))
    });
    let (start, mut state) = resumed.unwrap_or_else(|| (0, init()));

    file.seek(SeekFrom::Start(start)).ok()?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut offset = start;
    let mut buf: Vec<u8> = Vec::new();
    let mut partial: Option<Vec<u8>> = None;
    loop {
        buf.clear();
        let n = match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            // An I/O error mid-file: stop here, remember nothing past it.
            Err(_) => break,
        };
        if buf.last() != Some(&b'\n') {
            partial = Some(std::mem::take(&mut buf));
            break;
        }
        offset += n as u64;
        feed_bytes(&mut state, &buf);
    }

    // Remember the state at the last complete line (only if a full line was
    // ever seen — an empty or all-partial file is cheap to re-read).
    let answer = match &partial {
        Some(frag) => {
            let mut out = state.clone();
            feed_bytes(&mut out, frag);
            out
        }
        None => state.clone(),
    };
    if offset > 0 {
        let guard = read_guard(path, offset);
        let weight = state.weight();
        if let (Some(guard), Ok(mut c)) = (guard, cache().lock()) {
            c.put(
                key,
                Entry {
                    id,
                    offset,
                    guard,
                    state: Box::new(state),
                    weight,
                    used: Instant::now(),
                },
            );
        }
    }
    Some(answer)
}

/// Feed one raw line, mirroring `BufRead::lines`: strip `\n` / `\r\n`, skip a
/// line that is not valid UTF-8.
fn feed_bytes<S: LineState>(state: &mut S, raw: &[u8]) {
    let mut line = raw;
    if let Some(rest) = line.strip_suffix(b"\n") {
        line = rest;
        if let Some(rest) = line.strip_suffix(b"\r") {
            line = rest;
        }
    }
    if let Ok(s) = std::str::from_utf8(line) {
        state.feed(s);
    }
}

fn read_guard(path: &Path, offset: u64) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(path).ok()?;
    let from = offset.saturating_sub(GUARD_BYTES);
    f.seek(SeekFrom::Start(from)).ok()?;
    let mut g = vec![0u8; (offset - from) as usize];
    f.read_exact(&mut g).ok()?;
    Some(g)
}

fn guard_matches(file: &mut std::fs::File, offset: u64, guard: &[u8]) -> bool {
    let from = offset.saturating_sub(guard.len() as u64);
    if file.seek(SeekFrom::Start(from)).is_err() {
        return false;
    }
    let mut now = vec![0u8; guard.len()];
    file.read_exact(&mut now).is_ok() && now == guard
}

/// Drop the cached states for one file.
pub(crate) fn forget(path: &Path) {
    if let Ok(mut c) = cache().lock() {
        c.entries.retain(|(p, _), _| p != path);
        c.total = c.entries.values().map(|e| e.weight).sum();
    }
}

/// Drop every cached state (tests, and a hook should memory ever need it).
pub(crate) fn clear() {
    if let Ok(mut c) = cache().lock() {
        c.entries.clear();
        c.total = 0;
    }
}

/// Heap weight of a message list, for [`LineState::weight`].
pub(crate) fn messages_weight(messages: &[super::AgentMessage]) -> usize {
    messages
        .iter()
        .map(|m| {
            std::mem::size_of::<super::AgentMessage>()
                + m.content.capacity()
                + m.tool_name.as_ref().map(|t| t.capacity()).unwrap_or(0)
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Records every line it was fed, so resumption can be compared exactly.
    #[derive(Clone, Default, Debug, PartialEq)]
    struct Lines(Vec<String>);

    impl LineState for Lines {
        fn feed(&mut self, line: &str) {
            self.0.push(line.to_string());
        }
        fn weight(&self) -> usize {
            self.0.iter().map(|l| l.len()).sum()
        }
    }

    /// A full parse exactly as the readers do it: `lines()`, skipping a line
    /// that fails (invalid UTF-8) and carrying on.
    fn full(path: &Path) -> Lines {
        let f = std::fs::File::open(path).unwrap();
        let mut out = Vec::new();
        for line in BufReader::new(f).lines() {
            let Ok(line) = line else { continue };
            out.push(line);
        }
        Lines(out)
    }

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("saffev-tail-{name}-{}.jsonl", uuid::Uuid::new_v4()))
    }

    fn append(path: &Path, bytes: &[u8]) {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    #[test]
    fn growing_file_matches_a_full_parse_at_every_step() {
        let p = tmp("grow");
        append(&p, b"one\ntwo\n");
        for chunk in [
            &b"three\r\nfo"[..],
            b"ur\n",
            b"",
            b"\xff\xfe bad utf8\n",
            b"last",
        ] {
            append(&p, chunk);
            let inc = parse(&p, "t", Lines::default).unwrap();
            assert_eq!(inc, full(&p), "after appending {chunk:?}");
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn resumes_instead_of_rereading() {
        let p = tmp("resume");
        append(&p, b"a\nb\n");
        parse(&p, "t", Lines::default).unwrap();
        append(&p, b"c\n");
        // A state that has seen nothing proves where parsing started: if it
        // resumed, the answer comes from the cached state, not from `init`.
        let inc = parse(&p, "t", || Lines(vec!["never used".into()])).unwrap();
        assert_eq!(inc.0, vec!["a", "b", "c"]);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rewritten_or_replaced_or_shrunk_files_are_parsed_from_scratch() {
        let p = tmp("rewrite");
        append(&p, b"alpha\nbeta\n");
        parse(&p, "t", Lines::default).unwrap();

        // Same length prefix rewritten in place, then grown.
        let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.write_all(b"ALPHA\nBETA\n").unwrap();
        drop(f);
        append(&p, b"gamma\n");
        assert_eq!(parse(&p, "t", Lines::default).unwrap(), full(&p));

        // Shrunk.
        std::fs::write(&p, b"x\n").unwrap();
        assert_eq!(parse(&p, "t", Lines::default).unwrap(), full(&p));

        // Replaced by a new file (new inode) that happens to be longer.
        let q = tmp("replacement");
        std::fs::write(&q, b"x\ncompletely\ndifferent\n").unwrap();
        std::fs::rename(&q, &p).unwrap();
        assert_eq!(parse(&p, "t", Lines::default).unwrap(), full(&p));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn flavours_do_not_share_state() {
        let p = tmp("flavour");
        append(&p, b"a\n");
        parse(&p, "meta", Lines::default).unwrap();
        append(&p, b"b\n");
        let other = parse(&p, "full", || Lines(vec!["fresh".into()])).unwrap();
        assert_eq!(
            other.0,
            vec!["fresh", "a", "b"],
            "a new flavour starts from init"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn cache_respects_its_budget() {
        let mut c = Cache::default();
        let entry = |w: usize| Entry {
            id: FileId { dev: 0, ino: 0 },
            offset: 1,
            guard: Vec::new(),
            state: Box::new(()),
            weight: w,
            used: Instant::now(),
        };
        let k = |n: &str| (PathBuf::from(n), "t");
        c.put(k("a"), entry(BUDGET_BYTES / 2));
        c.put(k("b"), entry(BUDGET_BYTES / 2));
        c.put(k("c"), entry(BUDGET_BYTES / 2));
        assert!(c.total <= BUDGET_BYTES);
        assert!(
            !c.entries.contains_key(&k("a")),
            "least recently used goes first"
        );
        c.put(k("huge"), entry(BUDGET_BYTES + 1));
        assert!(
            !c.entries.contains_key(&k("huge")),
            "an entry over budget is not cached"
        );
    }
}
