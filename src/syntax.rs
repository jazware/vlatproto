//! atproto identifier syntax, mirroring @atproto/syntax.

/// Dot-separated labels of 1-63 [A-Za-z0-9-], none starting or ending with
/// '-', at least `min` of them, `max_len` chars in all.
fn labels(s: &str, min: usize, max_len: usize) -> Option<Vec<&str>> {
    if s.len() > max_len || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        return None;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let ok = labels.len() >= min
        && labels.iter().all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'));
    ok.then_some(labels)
}

/// The authority may not start with a digit; the name is alphanumeric and
/// starts with a letter.
pub fn valid_nsid(s: &str) -> bool {
    let Some(parts) = labels(s, 3, 253 + 1 + 63) else {
        return false;
    };
    let name = parts[parts.len() - 1];
    !parts[0].as_bytes()[0].is_ascii_digit()
        && name.as_bytes()[0].is_ascii_alphabetic()
        && name.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub fn valid_rkey(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s != "."
        && s != ".."
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:~-".contains(&b))
}

pub fn valid_record_path(path: &str) -> bool {
    path.split_once('/').is_some_and(|(c, r)| valid_nsid(c) && valid_rkey(r))
}

/// Handles under these can't be resolved publicly (reference
/// DISALLOWED_TLDS).
pub fn disallowed_handle_tld(h: &str) -> bool {
    const DISALLOWED_TLDS: &[&str] =
        &[".local", ".arpa", ".invalid", ".localhost", ".internal", ".example", ".alt", ".onion"];
    DISALLOWED_TLDS.iter().any(|t| h.ends_with(t))
}

/// The TLD starts with a letter.
pub fn valid_handle(h: &str) -> bool {
    labels(h, 2, 253).is_some_and(|l| l[l.len() - 1].as_bytes()[0].is_ascii_alphabetic())
}

pub fn valid_tid(s: &str) -> bool {
    s.len() == 13
        && b"234567abcdefghij".contains(&s.as_bytes()[0])
        && s.bytes().all(|b| b"234567abcdefghijklmnopqrstuvwxyz".contains(&b))
}

pub fn valid_did(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("did:") else {
        return false;
    };
    let Some((method, id)) = rest.split_once(':') else {
        return false;
    };
    s.len() <= 2048
        && !method.is_empty()
        && method.bytes().all(|b| b.is_ascii_lowercase())
        && !id.is_empty()
        && !id.ends_with(':')
        && !id.ends_with('%')
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:%-".contains(&b))
}

/// The prefix of a space URI, in place of a public one's `at://`.
pub const SPACE_URI_PREFIX: &str = "at:space/";

/// A space URI without its fragment: `at:space/{space DID}/{space type
/// NSID}/{skey}`, plus `/{author DID}/{collection}/{rkey}` for a record in
/// it (@atproto/syntax `parseSpaceAtUriString`, strict). Both DIDs must be
/// DIDs, not handles, and the skey follows the record-key syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceUri<'a> {
    pub authority: &'a str,
    pub space_type: &'a str,
    pub skey: &'a str,
    /// (author, collection, rkey)
    pub record: Option<(&'a str, &'a str, &'a str)>,
}

impl std::fmt::Display for SpaceUri<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{SPACE_URI_PREFIX}{}/{}/{}", self.authority, self.space_type, self.skey)?;
        if let Some((a, c, r)) = self.record {
            write!(f, "/{a}/{c}/{r}")?;
        }
        Ok(())
    }
}

impl SpaceUri<'_> {
    /// The space's own URI, without a record's path.
    pub fn space(&self) -> String {
        format!("{SPACE_URI_PREFIX}{}/{}/{}", self.authority, self.space_type, self.skey)
    }
}

/// A space URI in the only form hosts accept: `at:space/...`.
pub fn parse_space_uri(s: &str) -> Option<SpaceUri<'_>> {
    let (authority, rest) = s.strip_prefix(SPACE_URI_PREFIX)?.split_once('/')?;
    space_parts(authority, rest)
}

/// A space URI in either form: `at:space/...`, or the alpha's
/// `at://{space DID}/space/...` that records written before the Nov 24
/// alpha may embed (@atproto/syntax with `strict: false`). Only for values
/// read back, never for params, tokens, MAC headers or archives.
// @TODO remove with the reference's fromLegacySpaceUri, before beta.
pub fn parse_space_uri_lenient(s: &str) -> Option<SpaceUri<'_>> {
    match s.strip_prefix("at://") {
        Some(rest) => {
            let (authority, rest) = rest.split_once('/')?;
            space_parts(authority, rest.strip_prefix("space/")?)
        }
        None => parse_space_uri(s),
    }
}

/// `{type}/{skey}[/{author}/{collection}/{rkey}]` under `authority`.
fn space_parts<'a>(authority: &'a str, rest: &'a str) -> Option<SpaceUri<'a>> {
    let mut parts = rest.split('/');
    let (space_type, skey) = (parts.next()?, parts.next()?);
    let record = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (None, ..) => None,
        (Some(a), Some(c), Some(r), None) => Some((a, c, r)),
        _ => return None,
    };
    let ok = valid_did(authority)
        && valid_nsid(space_type)
        && valid_rkey(skey)
        && record.is_none_or(|(a, c, r)| valid_did(a) && valid_nsid(c) && valid_rkey(r));
    ok.then_some(SpaceUri { authority, space_type, skey, record })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsids() {
        for ok in ["app.bsky.feed.post", "com.example.fooBar", "a-0.b-1.c", "com.example.f00"] {
            assert!(valid_nsid(ok), "{ok}");
        }
        for bad in [
            "app.bsky",
            "1com.example.foo",
            "com.example.foo-bar",
            "com..foo",
            "com.example.3foo",
            "com.exa_mple.foo",
            "-com.example.foo",
        ] {
            assert!(!valid_nsid(bad), "{bad}");
        }
    }

    #[test]
    fn rkeys() {
        for ok in ["3jui7kd54zh2y", "self", "a:b~c_d.e-f", "..."] {
            assert!(valid_rkey(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "a b", "#x", &"a".repeat(513)] {
            assert!(!valid_rkey(bad), "{bad}");
        }
    }

    #[test]
    fn handles() {
        assert!(valid_handle("alice.bsky.social"));
        assert!(valid_handle("x.test"));
        assert!(!valid_handle("alice"));
        assert!(!valid_handle("alice.-bsky.social"));
        assert!(!valid_handle("alice.bsky.1social"));
        assert!(!valid_handle("al_ice.bsky.social"));
    }

    #[test]
    fn space_uris() {
        let space = "at:space/did:plc:abc/com.example.group/self";
        let rec = "at:space/did:web:a.example/com.example.group/k/did:plc:alice/com.example.post/3jui7kd54zh2y";
        let u = parse_space_uri(space).unwrap();
        assert_eq!((u.authority, u.space_type, u.skey, u.record), ("did:plc:abc", "com.example.group", "self", None));
        assert_eq!(u.to_string(), space);
        let r = parse_space_uri(rec).unwrap();
        assert_eq!(r.record, Some(("did:plc:alice", "com.example.post", "3jui7kd54zh2y")));
        assert_eq!(
            (r.to_string().as_str(), r.space().as_str()),
            (rec, "at:space/did:web:a.example/com.example.group/k")
        );
        assert_eq!(
            parse_space_uri("at:space/did:web:a_b.example/com.example.group/k").unwrap().authority,
            "did:web:a_b.example"
        );
        for bad in [
            "at://did:plc:abc/space/com.example.group/self",
            "at:space/alice.test/com.example.group/self",
            "at:space/did:plc:abc/com.example.group",
            "at:space/did:plc:abc/com.example.group/self/",
            "at:space/did:plc:abc/com.example.group/self/did:plc:alice/com.example.post",
            "at:space/did:plc:abc/com.example.group/self/alice.test/com.example.post/x",
            "at:space/did:plc:abc/com.example.group/..",
            "at:space//com.example.group/self",
            "at:space/did:plc:abc/space/com.example.group/self",
        ] {
            assert!(parse_space_uri(bad).is_none(), "{bad}");
        }
        let old = "at://did:plc:abc/space/com.example.group/self";
        assert_eq!(parse_space_uri_lenient(old).unwrap().to_string(), space);
        assert_eq!(parse_space_uri_lenient(space), parse_space_uri(space));
        let old_rec = "at://did:web:a.example/space/com.example.group/k/did:plc:alice/com.example.post/3jui7kd54zh2y";
        assert_eq!(parse_space_uri_lenient(old_rec).unwrap().to_string(), rec);
        for bad in ["at://alice.test/space/com.example.group/self", "at://did:plc:abc/com.example.group/self"] {
            assert!(parse_space_uri_lenient(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn dids_tids() {
        assert!(valid_did("did:plc:abc123"));
        assert!(valid_did("did:web:example.com"));
        assert!(!valid_did("did:PLC:abc"));
        assert!(!valid_did("did:plc:"));
        assert!(valid_tid("3jui7kd54zh2y"));
        assert!(!valid_tid("3jui7kd54zh2"));
    }
}
