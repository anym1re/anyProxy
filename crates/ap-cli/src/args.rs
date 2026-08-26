use ap_core::time::parse_rfc3339;
use time::OffsetDateTime;

/// Why an argument was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ArgError {
    /// A size without a unit, or with one that is not recognised.
    #[error("size must be a number with a unit, such as 50G, or 0 for none")]
    Size,

    /// A moment that is neither a date nor a full RFC 3339 timestamp.
    #[error("expiry must be YYYY-MM-DD, a full RFC 3339 timestamp, or never")]
    Until,
}

/// Reads a byte count written the way an operator writes it.
///
/// A unit is required so that `50` cannot silently mean fifty bytes. Zero is
/// the one value written without one, and it means no ceiling at all.
pub fn parse_size(text: &str) -> Result<Option<i64>, ArgError> {
    let trimmed = text.trim();
    if trimmed == "0" {
        return Ok(None);
    }

    let (digits, unit) = trimmed.split_at(trimmed.len().saturating_sub(1));
    let multiplier = match unit {
        "K" | "k" => 1024_i64,
        "M" | "m" => 1024_i64.pow(2),
        "G" | "g" => 1024_i64.pow(3),
        "T" | "t" => 1024_i64.pow(4),
        _ => return Err(ArgError::Size),
    };

    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ArgError::Size);
    }

    digits
        .parse::<i64>()
        .ok()
        .and_then(|value| value.checked_mul(multiplier))
        .filter(|value| *value > 0)
        .map(Some)
        .ok_or(ArgError::Size)
}

/// Reads the moment an access or a client stops being served.
///
/// A bare date means the end of that day, so `--until 2026-12-31` covers the
/// whole of the thirty-first rather than expiring at midnight before it.
pub fn parse_until(text: &str) -> Result<Option<OffsetDateTime>, ArgError> {
    let trimmed = text.trim();
    if trimmed.eq_ignore_ascii_case("never") || trimmed == "0" {
        return Ok(None);
    }

    let candidate = if trimmed.len() == 10 && trimmed.as_bytes().get(4) == Some(&b'-') {
        format!("{trimmed}T23:59:59Z")
    } else {
        trimmed.to_owned()
    };

    parse_rfc3339(&candidate)
        .map(Some)
        .map_err(|_| ArgError::Until)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_core::time::format_rfc3339;

    #[test]
    fn sizes_carry_their_unit() {
        assert_eq!(parse_size("50G"), Ok(Some(50 * 1024 * 1024 * 1024)));
        assert_eq!(parse_size("500M"), Ok(Some(500 * 1024 * 1024)));
        assert_eq!(parse_size("1T"), Ok(Some(1024_i64.pow(4))));
        assert_eq!(parse_size("1k"), Ok(Some(1024)));
    }

    #[test]
    fn zero_means_no_ceiling() {
        assert_eq!(parse_size("0"), Ok(None));
    }

    #[test]
    fn a_size_without_a_unit_is_refused() {
        for text in ["50", "-1", "50X", "", "G", "1.5G", "5 0G"] {
            assert_eq!(parse_size(text), Err(ArgError::Size), "accepted {text}");
        }
    }

    #[test]
    fn a_bare_date_covers_the_whole_day() {
        let parsed = parse_until("2026-12-31").unwrap().unwrap();
        assert_eq!(format_rfc3339(parsed).unwrap(), "2026-12-31T23:59:59Z");
    }

    #[test]
    fn a_full_timestamp_is_taken_as_given() {
        let parsed = parse_until("2026-12-31T12:00:00Z").unwrap().unwrap();
        assert_eq!(format_rfc3339(parsed).unwrap(), "2026-12-31T12:00:00Z");
    }

    #[test]
    fn never_means_no_expiry() {
        assert_eq!(parse_until("never"), Ok(None));
        assert_eq!(parse_until("NEVER"), Ok(None));
        assert_eq!(parse_until("0"), Ok(None));
    }

    #[test]
    fn other_date_forms_are_refused() {
        for text in ["31.12.2026", "2026/12/31", "tomorrow", "", "2026-13-01"] {
            assert_eq!(parse_until(text), Err(ArgError::Until), "accepted {text}");
        }
    }
}
