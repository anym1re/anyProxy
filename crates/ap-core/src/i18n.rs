//! Interface text, drawn from catalogues rather than written in the code.
//!
//! English and Russian are equal: both catalogues carry the same keys, and a
//! test refuses a build where they drift apart.
//!
//! Log lines stay English and are not routed through here: they are read by
//! an operator and searched by text.

use fluent::{FluentArgs, FluentBundle, FluentResource, FluentValue};
use unic_langid::{LanguageIdentifier, langid};

use crate::{Error, Reason};

const EN_SOURCE: &str = include_str!("../../../i18n/en/main.ftl");
const RU_SOURCE: &str = include_str!("../../../i18n/ru/main.ftl");

/// A language the interface speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Locale {
    /// English, the source catalogue.
    #[default]
    En,
    /// Russian.
    Ru,
}

impl Locale {
    /// Picks a locale from a code, falling back to English.
    ///
    /// The primary subtag is enough: `ru-RU` and `ru` both land on Russian.
    pub fn from_code(code: &str) -> Self {
        match code
            .split(['-', '_'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "ru" => Self::Ru,
            _ => Self::En,
        }
    }

    /// The code this locale is named by.
    pub fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
        }
    }

    fn source(self) -> &'static str {
        match self {
            Self::En => EN_SOURCE,
            Self::Ru => RU_SOURCE,
        }
    }

    fn langid(self) -> LanguageIdentifier {
        match self {
            Self::En => langid!("en"),
            Self::Ru => langid!("ru"),
        }
    }

    /// Every locale the interface speaks.
    pub fn all() -> [Self; 2] {
        [Self::En, Self::Ru]
    }
}

fn bundle(locale: Locale) -> Result<FluentBundle<FluentResource>, Error> {
    let resource =
        FluentResource::try_new(locale.source().to_owned()).map_err(|_| Error::Catalogue)?;
    let mut bundle = FluentBundle::new(vec![locale.langid()]);
    // Fluent wraps placeables in isolation marks for bidirectional text.
    // Neither catalogue is bidirectional and the marks would reach the
    // terminal, so they are turned off.
    bundle.set_use_isolating(false);
    bundle
        .add_resource(resource)
        .map_err(|_| Error::Catalogue)?;
    Ok(bundle)
}

/// Renders a message with no arguments.
pub fn message(locale: Locale, key: &str) -> Result<String, Error> {
    render(locale, key, FluentArgs::new())
}

/// Renders a message with named arguments.
///
/// Numbers and names are substituted by Fluent, not by joining strings:
/// Russian has three plural forms and joining cannot express them.
pub fn message_with(
    locale: Locale,
    key: &str,
    args: &[(&str, Argument<'_>)],
) -> Result<String, Error> {
    let mut fluent_args = FluentArgs::new();
    for (name, value) in args {
        fluent_args.set(
            *name,
            match value {
                Argument::Number(number) => FluentValue::from(*number),
                Argument::Text(text) => FluentValue::from(*text),
            },
        );
    }
    render(locale, key, fluent_args)
}

/// A value substituted into a message.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Argument<'a> {
    /// A number, which drives plural selection.
    Number(i64),
    /// A piece of text.
    Text(&'a str),
}

fn render(locale: Locale, key: &str, args: FluentArgs<'_>) -> Result<String, Error> {
    let bundle = bundle(locale)?;
    let message = bundle.get_message(key).ok_or(Error::MessageMissing)?;
    let pattern = message.value().ok_or(Error::MessageMissing)?;
    let mut errors = Vec::new();
    let rendered = bundle.format_pattern(pattern, Some(&args), &mut errors);
    if errors.is_empty() {
        Ok(rendered.into_owned())
    } else {
        Err(Error::MessageMissing)
    }
}

/// The keys a catalogue defines, in the order they appear.
pub fn keys(locale: Locale) -> Vec<String> {
    let mut found = Vec::new();
    for line in locale.source().lines() {
        if line.starts_with('#') || line.starts_with(' ') || line.trim().is_empty() {
            continue;
        }
        if let Some((key, _)) = line.split_once('=') {
            let key = key.trim();
            if !key.is_empty() {
                found.push(key.to_owned());
            }
        }
    }
    found
}

impl Reason {
    /// The catalogue key this reason is rendered from.
    pub fn message_key(self) -> &'static str {
        match self {
            Self::ClientSuspended => "reason-client-suspended",
            Self::ClientArchived => "reason-client-archived",
            Self::AccessDisabled => "reason-access-disabled",
            Self::AccessRevoked => "reason-access-revoked",
            Self::Expired => "reason-expired",
            Self::ClientQuotaExhausted => "reason-client-quota-exhausted",
            Self::AccessQuotaExhausted => "reason-access-quota-exhausted",
        }
    }

    /// Renders this reason in the given language.
    pub fn localised(self, locale: Locale) -> Result<String, Error> {
        message(locale, self.message_key())
    }
}

impl Error {
    /// The catalogue key this rejection is rendered from.
    ///
    /// `Display` stays English and goes to the log; this goes to a person.
    pub fn message_key(&self) -> &'static str {
        match self {
            Self::Name { .. } => "error-name",
            Self::Domain => "error-domain",
            Self::Color => "error-color",
            Self::TextTooLong { .. } => "error-text-too-long",
            Self::Quota => "error-quota",
            Self::Timestamp => "error-timestamp",
            Self::StealthWithoutDomain => "error-stealth-without-domain",
            Self::OpenWithDomain => "error-open-with-domain",
            Self::MaskingNotOffered => "error-masking-not-offered",
            Self::MaxDevices => "error-max-devices",
            Self::AccessRevoked => "error-access-revoked",
            Self::SurfaceMismatch { .. } => "error-surface-mismatch",
            Self::SecretForm => "error-secret-form",
            Self::CredentialForm => "error-credential-form",
            Self::SealedValue => "error-sealed-value",
            Self::KeyFileUnreadable => "error-key-file-unreadable",
            Self::KeyFilePermissions => "error-key-file-permissions",
            Self::KeyFileLength => "error-key-file-length",
            Self::LinkHost => "error-link-host",
            Self::StoredValue => "error-stored-value",
            Self::PasswordHash => "error-password-hash",
            Self::Catalogue | Self::MessageMissing => "error-sealed-value",
        }
    }

    /// Renders this rejection in the given language.
    pub fn localised(&self, locale: Locale) -> Result<String, Error> {
        match self {
            Self::Name { max } | Self::TextTooLong { max } => message_with(
                locale,
                self.message_key(),
                &[("max", Argument::Number(*max as i64))],
            ),
            Self::SurfaceMismatch { expected, actual } => message_with(
                locale,
                self.message_key(),
                &[
                    ("expected", Argument::Text(expected)),
                    ("actual", Argument::Text(actual)),
                ],
            ),
            _ => message(locale, self.message_key()),
        }
    }
}

/// Renders a count of connections, plural forms included.
pub fn access_count(locale: Locale, count: i64) -> Result<String, Error> {
    message_with(
        locale,
        "access-count",
        &[("count", Argument::Number(count))],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_catalogues_carry_the_same_keys() {
        let mut english = keys(Locale::En);
        let mut russian = keys(Locale::Ru);
        english.sort();
        russian.sort();
        assert_eq!(english, russian, "the catalogues have drifted apart");
        assert!(!english.is_empty());
    }

    #[test]
    fn russian_picks_the_right_plural_form() {
        for (count, expected) in [
            (1, "1 подключение"),
            (2, "2 подключения"),
            (5, "5 подключений"),
            (11, "11 подключений"),
            (21, "21 подключение"),
            (101, "101 подключение"),
        ] {
            assert_eq!(
                access_count(Locale::Ru, count).unwrap(),
                expected,
                "count {count}"
            );
        }
    }

    #[test]
    fn english_picks_the_right_plural_form() {
        assert_eq!(access_count(Locale::En, 1).unwrap(), "1 connection");
        assert_eq!(access_count(Locale::En, 2).unwrap(), "2 connections");
        assert_eq!(access_count(Locale::En, 0).unwrap(), "0 connections");
    }

    #[test]
    fn an_unknown_code_falls_back_to_english() {
        assert_eq!(Locale::from_code("ru"), Locale::Ru);
        assert_eq!(Locale::from_code("ru-RU"), Locale::Ru);
        assert_eq!(Locale::from_code("RU_ru"), Locale::Ru);
        assert_eq!(Locale::from_code("en-GB"), Locale::En);
        assert_eq!(Locale::from_code("fr"), Locale::En);
        assert_eq!(Locale::from_code(""), Locale::En);
        assert_eq!(Locale::default(), Locale::En);
    }

    #[test]
    fn a_missing_key_is_an_error_not_an_empty_string() {
        assert_eq!(
            message(Locale::En, "no-such-key"),
            Err(Error::MessageMissing)
        );
        assert_eq!(
            message(Locale::Ru, "no-such-key"),
            Err(Error::MessageMissing)
        );
    }

    #[test]
    fn every_reason_renders_in_both_languages() {
        for reason in [
            Reason::ClientSuspended,
            Reason::ClientArchived,
            Reason::AccessDisabled,
            Reason::AccessRevoked,
            Reason::Expired,
            Reason::ClientQuotaExhausted,
            Reason::AccessQuotaExhausted,
        ] {
            for locale in Locale::all() {
                let text = reason.localised(locale).unwrap();
                assert!(!text.is_empty(), "{reason:?} in {}", locale.code());
            }
        }
    }

    #[test]
    fn every_rejection_renders_in_both_languages() {
        let cases = [
            Error::Name { max: 32 },
            Error::Domain,
            Error::Color,
            Error::TextTooLong { max: 128 },
            Error::Quota,
            Error::Timestamp,
            Error::StealthWithoutDomain,
            Error::OpenWithDomain,
            Error::MaxDevices,
            Error::AccessRevoked,
            Error::SurfaceMismatch {
                expected: "stealth",
                actual: "open",
            },
            Error::SecretForm,
            Error::CredentialForm,
            Error::SealedValue,
            Error::KeyFileUnreadable,
            Error::KeyFilePermissions,
            Error::KeyFileLength,
            Error::LinkHost,
            Error::StoredValue,
            Error::PasswordHash,
        ];
        for error in cases {
            for locale in Locale::all() {
                let text = error.localised(locale).unwrap();
                assert!(!text.is_empty(), "{error:?} in {}", locale.code());
            }
        }
    }

    #[test]
    fn arguments_are_substituted_not_appended() {
        assert_eq!(
            Error::Name { max: 32 }.localised(Locale::En).unwrap(),
            "name must be 1 to 32 characters of a-z, 0-9, underscore or hyphen"
        );
        assert_eq!(
            Error::SurfaceMismatch {
                expected: "stealth",
                actual: "open"
            }
            .localised(Locale::En)
            .unwrap(),
            "expected a stealth access, found open"
        );
    }

    #[test]
    fn nothing_leaks_bidirectional_isolation_marks() {
        let text = access_count(Locale::Ru, 5).unwrap();
        assert!(!text.contains('\u{2068}'));
        assert!(!text.contains('\u{2069}'));
    }
}
