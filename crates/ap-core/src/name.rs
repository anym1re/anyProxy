use std::fmt;

use crate::Error;

const LABEL_MAX: usize = 32;
const TAG_NAME_MAX: usize = 24;
const NOTE_MAX: usize = 128;
const DOMAIN_MAX: usize = 253;
const DOMAIN_PART_MAX: usize = 63;

fn is_slug(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn is_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > DOMAIN_MAX || !value.contains('.') {
        return false;
    }
    value.split('.').all(|part| {
        !part.is_empty()
            && part.len() <= DOMAIN_PART_MAX
            && !part.starts_with('-')
            && !part.ends_with('-')
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

macro_rules! slug {
    ($name:ident, $max:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Borrows the validated value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = Error;

            fn try_from(value: &str) -> Result<Self, Error> {
                if is_slug(value, $max) {
                    Ok(Self(value.to_owned()))
                } else {
                    Err(Error::Name { max: $max })
                }
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(value: String) -> Result<Self, Error> {
                if is_slug(&value, $max) {
                    Ok(Self(value))
                } else {
                    Err(Error::Name { max: $max })
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

slug!(
    Label,
    LABEL_MAX,
    "Identifier of a client or a node, unique within its kind."
);
slug!(TagName, TAG_NAME_MAX, "Identifier of a tag.");
slug!(
    AdminLogin,
    LABEL_MAX,
    "Name an administrator signs in with."
);

/// Hostname a stealth node answers on, shared by its cover site and its clients.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(String);

impl Domain {
    /// Borrows the validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Domain {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Error> {
        if is_hostname(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(Error::Domain)
        }
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lowercase hex triplet used to mark a tag in the panel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Color(String);

impl Color {
    /// Borrows the validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Color {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Error> {
        let valid = value.len() == 7
            && value.starts_with('#')
            && value[1..]
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(Error::Color)
        }
    }
}

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Short free text an operator attaches to a tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Note(String);

impl Note {
    /// Borrows the validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Note {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Error> {
        if value.chars().count() <= NOTE_MAX {
            Ok(Self(value.to_owned()))
        } else {
            Err(Error::TextTooLong { max: NOTE_MAX })
        }
    }
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_accepts_one_character() {
        assert_eq!(Label::try_from("a").unwrap().as_str(), "a");
    }

    #[test]
    fn label_accepts_the_longest_allowed_value() {
        let longest = "a".repeat(LABEL_MAX);
        assert_eq!(Label::try_from(longest.as_str()).unwrap().as_str(), longest);
    }

    #[test]
    fn label_rejects_the_empty_string() {
        assert_eq!(Label::try_from(""), Err(Error::Name { max: LABEL_MAX }));
    }

    #[test]
    fn label_rejects_one_character_too_many() {
        let too_long = "a".repeat(LABEL_MAX + 1);
        assert_eq!(
            Label::try_from(too_long.as_str()),
            Err(Error::Name { max: LABEL_MAX })
        );
    }

    #[test]
    fn label_rejects_anything_outside_the_alphabet() {
        for value in ["Alice", "alice.bob", "alice bob", "алиса", "alice!"] {
            assert_eq!(
                Label::try_from(value),
                Err(Error::Name { max: LABEL_MAX }),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn tag_name_is_shorter_than_a_label() {
        assert!(TagName::try_from("a".repeat(TAG_NAME_MAX).as_str()).is_ok());
        assert!(TagName::try_from("a".repeat(TAG_NAME_MAX + 1).as_str()).is_err());
    }

    #[test]
    fn domain_accepts_a_hostname() {
        assert_eq!(
            Domain::try_from("cover.example.com").unwrap().as_str(),
            "cover.example.com"
        );
    }

    #[test]
    fn domain_rejects_malformed_values() {
        for value in [
            "",
            "example",
            "Example.com",
            "example..com",
            "-example.com",
            "example-.com",
            "приме́р.рф",
        ] {
            assert_eq!(
                Domain::try_from(value),
                Err(Error::Domain),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn color_accepts_a_lowercase_triplet() {
        assert_eq!(Color::try_from("#1a2b3c").unwrap().as_str(), "#1a2b3c");
    }

    #[test]
    fn color_rejects_uppercase_and_short_forms() {
        for value in ["#1A2B3C", "#1a2b3", "1a2b3c", "#1a2b3cd", ""] {
            assert_eq!(
                Color::try_from(value),
                Err(Error::Color),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn note_rejects_text_past_the_limit() {
        assert!(Note::try_from("a".repeat(NOTE_MAX).as_str()).is_ok());
        assert_eq!(
            Note::try_from("a".repeat(NOTE_MAX + 1).as_str()),
            Err(Error::TextTooLong { max: NOTE_MAX })
        );
    }
}

/// The tag Telegram issues to a proxy that carries a sponsored channel.
///
/// Sixteen bytes as thirty-two lowercase hex characters, handed out by
/// @MTProxybot once a proxy is registered with it. It is not a secret: it says
/// which proxy the traffic came through, so the sponsored channel is credited
/// to the right one, and it travels with every connection.
///
/// A node has one or none. Carrying one costs an extra hop, because a
/// sponsored channel is only counted when the traffic goes through Telegram's
/// middle proxies; a node without one goes to the data centres directly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdTag(String);

impl AdTag {
    /// Borrows the validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for AdTag {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Error> {
        // Upper case is accepted and folded down: the bot shows the tag in a
        // message a person copies by hand, and a tag that differs only in case
        // is the same tag.
        let folded = value.to_ascii_lowercase();
        let valid = folded.len() == 32 && folded.chars().all(|c| c.is_ascii_hexdigit());
        if valid {
            Ok(Self(folded))
        } else {
            Err(Error::AdTag)
        }
    }
}

impl fmt::Display for AdTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod ad_tag_tests {
    use super::*;

    #[test]
    fn a_tag_is_sixteen_bytes_in_hex() {
        let tag = AdTag::try_from("3c09c680b76ee91a4c25ad51f742ba1e").unwrap();
        assert_eq!(tag.as_str(), "3c09c680b76ee91a4c25ad51f742ba1e");
    }

    #[test]
    fn a_tag_copied_in_upper_case_is_the_same_tag() {
        assert_eq!(
            AdTag::try_from("3C09C680B76EE91A4C25AD51F742BA1E"),
            AdTag::try_from("3c09c680b76ee91a4c25ad51f742ba1e")
        );
    }

    #[test]
    fn anything_that_is_not_sixteen_bytes_of_hex_is_refused() {
        for bad in [
            "",
            "3c09c680b76ee91a4c25ad51f742ba",
            "3c09c680b76ee91a4c25ad51f742ba1e00",
            "3c09c680b76ee91a4c25ad51f742ba1z",
            "не тег",
        ] {
            assert_eq!(AdTag::try_from(bad), Err(Error::AdTag), "{bad:?} accepted");
        }
    }
}

/// The name an operator gives a link they hand out themselves.
///
/// Shown to the operator and nobody else: it says which public link is which
/// in a list where none of them belongs to a client. Written by a person, so
/// any script and ordinary punctuation are allowed and only what would break a
/// line of output is not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkName(String);

/// Longest name a link may carry.
const LINK_NAME_CEILING: usize = 64;

impl LinkName {
    /// Borrows the validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for LinkName {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Error> {
        // Trimmed before it is measured: a name that is only spaces is no
        // name, and trailing space is invisible in every place this is shown.
        let trimmed = value.trim();
        let valid = !trimmed.is_empty()
            && trimmed.chars().count() <= LINK_NAME_CEILING
            && !trimmed.chars().any(char::is_control);
        if valid {
            Ok(Self(trimmed.to_owned()))
        } else {
            Err(Error::LinkName)
        }
    }
}

impl fmt::Display for LinkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod link_name_tests {
    use super::*;

    #[test]
    fn a_name_a_person_would_write_is_taken() {
        for good in ["Канал новостей", "spring promo", "для друзей — 2026"]
        {
            assert!(LinkName::try_from(good).is_ok(), "{good:?} refused");
        }
    }

    #[test]
    fn surrounding_space_is_not_part_of_the_name() {
        assert_eq!(LinkName::try_from("  общая  ").unwrap().as_str(), "общая");
    }

    #[test]
    fn nothing_and_only_space_are_refused() {
        for bad in ["", "   ", "\t"] {
            assert_eq!(LinkName::try_from(bad), Err(Error::LinkName));
        }
    }

    #[test]
    fn a_name_that_would_break_a_line_is_refused() {
        assert_eq!(LinkName::try_from("две\nстроки"), Err(Error::LinkName));
    }

    #[test]
    fn a_name_longer_than_the_ceiling_is_refused() {
        let long: String = "и".repeat(LINK_NAME_CEILING + 1);
        assert_eq!(LinkName::try_from(long.as_str()), Err(Error::LinkName));
    }
}
