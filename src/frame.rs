//! Firehose frames as a server reads them back (they're built by
//! [`crate::events`]): an event's type and DID straight from its DAG-CBOR
//! without decoding it, and the `#info` frame.

use crate::cbor::*;

/// The DID of a frame's repo (`repo` of a #commit, `did` of the others),
/// read straight from its DAG-CBOR; None for a frame without one.
pub fn frame_did(f: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    cbor_skip(f, &mut i, 0)?; // header
    let (major, n) = cbor_head(f, &mut i)?;
    if major != 5 {
        return None;
    }
    for _ in 0..n {
        let key = cbor_text(f, &mut i)?;
        if key == b"repo" || key == b"did" {
            return cbor_text(f, &mut i);
        }
        cbor_skip(f, &mut i, 0)?;
    }
    None
}

/// A frame's event type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Commit,
    Sync,
    Identity,
    Account,
    /// `#info`, errors, anything else.
    Other,
}

/// What a frame filter sees of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameMeta<'a> {
    pub kind: FrameKind,
    /// `repo` of a #commit, `did` of a #sync, #identity or #account: the
    /// key each kind is checked and applied by, so a frame carrying both
    /// can't pass as the other DID. None for other kinds or a frame
    /// without it.
    pub did: Option<&'a [u8]>,
}

/// The type and DID of a frame, read straight from its DAG-CBOR without
/// decoding it.
pub fn frame_meta(f: &[u8]) -> FrameMeta<'_> {
    let mut meta = FrameMeta { kind: FrameKind::Other, did: None };
    let mut i = 0;
    let Some((5, n)) = cbor_head(f, &mut i) else { return meta };
    for _ in 0..n {
        let Some(key) = cbor_text(f, &mut i) else { return meta };
        if key == b"t" {
            meta.kind = match cbor_text(f, &mut i) {
                Some(b"#commit") => FrameKind::Commit,
                Some(b"#sync") => FrameKind::Sync,
                Some(b"#identity") => FrameKind::Identity,
                Some(b"#account") => FrameKind::Account,
                Some(_) => FrameKind::Other,
                None => return meta,
            };
        } else if cbor_skip(f, &mut i, 0).is_none() {
            return meta;
        }
    }
    let want: &[u8] = match meta.kind {
        FrameKind::Commit => b"repo",
        FrameKind::Sync | FrameKind::Identity | FrameKind::Account => b"did",
        FrameKind::Other => return meta,
    };
    let Some((5, n)) = cbor_head(f, &mut i) else { return meta };
    for _ in 0..n {
        let Some(key) = cbor_text(f, &mut i) else { return meta };
        if key == want {
            meta.did = cbor_text(f, &mut i);
            return meta;
        }
        if cbor_skip(f, &mut i, 0).is_none() {
            return meta;
        }
    }
    meta
}

/// An `#info` frame (`OutdatedCursor` and the like).
pub fn info_frame(name: &str, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    write_map_head(&mut out, 2);
    write_text(&mut out, "t");
    write_text(&mut out, "#info");
    write_text(&mut out, "op");
    write_uint(&mut out, 1);
    write_map_head(&mut out, 2);
    write_text(&mut out, "name");
    write_text(&mut out, name);
    write_text(&mut out, "message");
    write_text(&mut out, message);
    out
}

/// (major type, argument) of the item at `i`; definite lengths only (DAG-CBOR).
fn cbor_head(f: &[u8], i: &mut usize) -> Option<(u8, u64)> {
    let b = *f.get(*i)?;
    *i += 1;
    let n = match b & 0x1f {
        n @ 0..=23 => return Some((b >> 5, n as u64)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let bytes = f.get(*i..*i + n)?;
    *i += n;
    Some((b >> 5, bytes.iter().fold(0u64, |a, x| a << 8 | *x as u64)))
}

fn cbor_text<'a>(f: &'a [u8], i: &mut usize) -> Option<&'a [u8]> {
    let (major, n) = cbor_head(f, i)?;
    if major != 3 {
        return None;
    }
    let s = f.get(*i..i.checked_add(usize::try_from(n).ok()?)?)?;
    *i += s.len();
    Some(s)
}

fn cbor_skip(f: &[u8], i: &mut usize, depth: u32) -> Option<()> {
    if depth > 64 {
        return None;
    }
    let (major, n) = cbor_head(f, i)?;
    match major {
        2 | 3 => {
            let end = i.checked_add(usize::try_from(n).ok()?)?;
            if end > f.len() {
                return None;
            }
            *i = end;
        }
        4 => {
            for _ in 0..n {
                cbor_skip(f, i, depth + 1)?;
            }
        }
        5 => {
            for _ in 0..n.checked_mul(2)? {
                cbor_skip(f, i, depth + 1)?;
            }
        }
        6 => cbor_skip(f, i, depth + 1)?,
        _ => {}
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::Cid;
    use crate::events;

    /// A #commit, #sync, #identity or #account (by `kind % 4`) for `did`.
    fn kind_frame(kind: usize, did: &str, seq: i64) -> Vec<u8> {
        let cid = Cid::dag_cbor(b"x");
        let f = match kind % 4 {
            0 => {
                let ops = [
                    events::RepoOp { action: "create", path: "app.bsky.feed.post/3k", cid: Some(cid), prev: None },
                    events::RepoOp { action: "update", path: "app.bsky.feed.like/3j", cid: Some(cid), prev: Some(cid) },
                ];
                events::commit_frame(&events::CommitFrame {
                    repo: did,
                    rev: "3kabc",
                    since: Some("3kabb"),
                    commit: cid,
                    prev_data: Some(cid),
                    blocks: &[7u8; 300],
                    ops: &ops,
                    time: "2026-01-01T00:00:00Z",
                })
            }
            1 => events::sync_frame(did, "3kabc", &[1, 2, 3], "t"),
            2 => events::identity_frame(did, "a.test", "t"),
            _ => events::account_frame(did, false, Some("takendown"), "t"),
        };
        let mut out = Vec::new();
        f.finish(seq, &mut out);
        out
    }

    /// frame_did finds the repo of every event kind.
    #[test]
    fn frame_did_reads_every_kind() {
        let did = "did:plc:abcdefghijklmnopqrstuvwx";
        for k in 0..4 {
            assert_eq!(frame_did(&kind_frame(k, did, 7)), Some(did.as_bytes()), "kind {k}");
        }
        assert_eq!(frame_did(b"\xa0"), None);
        assert_eq!(frame_did(&kind_frame(0, did, 7)[..20]), None);
    }

    /// frame_meta reads each kind's own DID key, even with the other one
    /// in the frame, and never panics on garbage.
    #[test]
    fn frame_meta_reads_the_kind_and_its_did() {
        let did = "did:plc:abcdefghijklmnopqrstuvwx";
        for (k, kind) in
            [FrameKind::Commit, FrameKind::Sync, FrameKind::Identity, FrameKind::Account].into_iter().enumerate()
        {
            let f = kind_frame(k, did, 7);
            assert_eq!(frame_meta(&f), FrameMeta { kind, did: Some(did.as_bytes()) });
        }
        // a #commit carrying a `did` (sorted first) is still its `repo`'s
        let mut f = Vec::new();
        write_map_head(&mut f, 2);
        write_text(&mut f, "t");
        write_text(&mut f, "#commit");
        write_text(&mut f, "op");
        write_uint(&mut f, 1);
        write_map_head(&mut f, 2);
        write_text(&mut f, "did");
        write_text(&mut f, "did:plc:other");
        write_text(&mut f, "repo");
        write_text(&mut f, "did:plc:real");
        assert_eq!(frame_meta(&f), FrameMeta { kind: FrameKind::Commit, did: Some(b"did:plc:real".as_slice()) });
        let info = info_frame("OutdatedCursor", "x");
        assert_eq!(frame_meta(&info), FrameMeta { kind: FrameKind::Other, did: None });
        let full = kind_frame(0, did, 7);
        for n in 0..full.len() {
            let m = frame_meta(&full[..n]);
            assert!(m.did.is_none_or(|d| d == did.as_bytes()), "truncated at {n}");
        }
        assert_eq!(frame_meta(b"").kind, FrameKind::Other);
    }
}
