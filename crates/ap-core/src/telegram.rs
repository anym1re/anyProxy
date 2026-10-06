//! Who is behind a Telegram account tied to a client (0103).

use std::fmt;

use crate::{Error, Sealable};

/// Longest piece of text kept for one field, in bytes.
///
/// Telegram's own limits are far below it — a username is at most 32
/// characters, a name at most 64 — so this only stops an unexpected update from
/// growing the record without bound.
const FIELD_CEILING: usize = 256;

/// Version of the sealed form, so it can change without guessing.
const FORM: u8 = 1;

/// What the panel keeps about an account, sealed under its key.
///
/// Refreshed with every message the person sends the bot, since names and
/// usernames change; dropped when the account is untied (0102, 0103).
#[derive(Clone, PartialEq, Eq)]
pub struct TelegramAccount {
    id: i64,
    chat: i64,
    username: Option<String>,
    first_name: String,
    last_name: Option<String>,
    language: String,
}

impl TelegramAccount {
    /// An account as an update describes it. Text past the ceiling is cut
    /// at a character boundary; empty optional parts are kept as absent.
    pub fn new(
        id: i64,
        chat: i64,
        username: Option<&str>,
        first_name: &str,
        last_name: Option<&str>,
        language: &str,
    ) -> Self {
        let kept = |text: &str| -> Option<String> {
            let text = bounded(text.trim());
            (!text.is_empty()).then(|| text.to_owned())
        };
        Self {
            id,
            chat,
            username: username.and_then(|name| kept(name.trim_start_matches('@'))),
            first_name: bounded(first_name.trim()).to_owned(),
            last_name: last_name.and_then(kept),
            language: bounded(language.trim()).to_owned(),
        }
    }

    /// The account.
    pub fn id(&self) -> i64 {
        self.id
    }

    /// Where the bot writes to it first. In a private chat, the account again.
    pub fn chat(&self) -> i64 {
        self.chat
    }

    /// The username without the at-sign, when the account has one.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// The name as Telegram shows it: first and last together.
    pub fn name(&self) -> String {
        match &self.last_name {
            Some(last) if !self.first_name.is_empty() => format!("{} {last}", self.first_name),
            Some(last) => last.clone(),
            None => self.first_name.clone(),
        }
    }

    /// The language the account is set to, as Telegram reports it.
    pub fn language(&self) -> &str {
        &self.language
    }
}

/// Cuts text to the ceiling at the last character boundary before it.
fn bounded(text: &str) -> &str {
    if text.len() <= FIELD_CEILING {
        return text;
    }
    let mut end = FIELD_CEILING;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

// A person's name and handle are what this type exists to hold, so nothing
// that prints it for a developer may show them: not a log line, not a panic.
impl fmt::Debug for TelegramAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TelegramAccount([redacted])")
    }
}

impl Sealable for TelegramAccount {
    fn to_plaintext(&self) -> Vec<u8> {
        let mut out = vec![FORM];
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&self.chat.to_le_bytes());
        for text in [
            self.username.as_deref().unwrap_or_default(),
            self.first_name.as_str(),
            self.last_name.as_deref().unwrap_or_default(),
            self.language.as_str(),
        ] {
            // Every field was cut to the ceiling when the value was built, so
            // its length fits the two bytes it is written in.
            let bytes = bounded(text).as_bytes();
            out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }

    fn from_plaintext(bytes: &[u8]) -> Result<Self, Error> {
        let mut rest = match bytes.split_first() {
            Some((&FORM, rest)) => rest,
            _ => return Err(Error::SealedValue),
        };
        let mut number = || -> Result<i64, Error> {
            let (head, tail) = rest.split_at_checked(8).ok_or(Error::SealedValue)?;
            rest = tail;
            let head: [u8; 8] = head.try_into().map_err(|_| Error::SealedValue)?;
            Ok(i64::from_le_bytes(head))
        };
        let id = number()?;
        let chat = number()?;
        let mut texts = Vec::with_capacity(4);
        for _ in 0..4 {
            let (length, tail) = rest.split_at_checked(2).ok_or(Error::SealedValue)?;
            let length = u16::from_le_bytes([length[0], length[1]]) as usize;
            let (text, tail) = tail.split_at_checked(length).ok_or(Error::SealedValue)?;
            texts.push(String::from_utf8(text.to_vec()).map_err(|_| Error::SealedValue)?);
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(Error::SealedValue);
        }
        let absent = |text: String| (!text.is_empty()).then_some(text);
        let language = texts.pop().unwrap_or_default();
        let last_name = texts.pop().and_then(absent);
        let first_name = texts.pop().unwrap_or_default();
        let username = texts.pop().and_then(absent);
        Ok(Self {
            id,
            chat,
            username,
            first_name,
            last_name,
            language,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Encrypted, KeyStore};

    fn key() -> KeyStore {
        KeyStore::from_bytes([7u8; 32])
    }

    #[test]
    fn an_account_comes_back_from_under_the_seal_as_it_went_in() {
        let account =
            TelegramAccount::new(4242, 4242, Some("@ivan_p"), "Иван", Some("Петров"), "ru");
        let sealed = Encrypted::seal(&account, &key()).unwrap();
        let opened = sealed.open(&key()).unwrap();
        assert_eq!(opened, account);
        assert_eq!(opened.username(), Some("ivan_p"));
        assert_eq!(opened.name(), "Иван Петров");
        assert_eq!(opened.chat(), 4242);
    }

    #[test]
    fn missing_parts_stay_missing() {
        let account = TelegramAccount::new(1, 2, None, "Anna", Some("  "), "");
        let opened = TelegramAccount::from_plaintext(&account.to_plaintext()).unwrap();
        assert_eq!(opened.username(), None);
        assert_eq!(opened.name(), "Anna");
        assert_eq!(opened.language(), "");
    }

    #[test]
    fn an_overlong_name_is_cut_at_a_character_not_a_byte() {
        let long = "ж".repeat(FIELD_CEILING);
        let account = TelegramAccount::new(1, 1, None, &long, None, "ru");
        assert!(account.name().len() <= FIELD_CEILING);
        let opened = TelegramAccount::from_plaintext(&account.to_plaintext()).unwrap();
        assert_eq!(opened, account);
    }

    #[test]
    fn a_damaged_record_is_refused_rather_than_misread() {
        let good = TelegramAccount::new(1, 1, Some("a"), "b", None, "en").to_plaintext();
        assert!(TelegramAccount::from_plaintext(&good[..good.len() - 1]).is_err());
        let mut longer = good.clone();
        longer.push(0);
        assert!(TelegramAccount::from_plaintext(&longer).is_err());
        let mut other_form = good;
        other_form[0] = 9;
        assert!(TelegramAccount::from_plaintext(&other_form).is_err());
    }

    #[test]
    fn nothing_about_the_person_is_printed_for_a_developer() {
        let account = TelegramAccount::new(4242, 4242, Some("ivan_p"), "Иван", None, "ru");
        let printed = format!("{account:?}");
        assert!(
            !printed.contains("ivan_p") && !printed.contains("Иван") && !printed.contains("4242")
        );
    }
}
