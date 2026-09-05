//! RFC 3339 timestamps, always UTC and always whole seconds.

use ::time::Date;
use ::time::OffsetDateTime;
use ::time::UtcOffset;
use ::time::format_description::well_known::Rfc3339;

use crate::Error;

/// Parses an RFC 3339 timestamp, converts it to UTC and drops any fraction.
pub fn parse_rfc3339(input: &str) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(input, &Rfc3339)
        .map_err(|_| Error::Timestamp)?
        .to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|_| Error::Timestamp)
}

/// Renders a timestamp as RFC 3339 in UTC with whole seconds.
pub fn format_rfc3339(value: OffsetDateTime) -> Result<String, Error> {
    value
        .to_offset(UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|_| Error::Timestamp)?
        .format(&Rfc3339)
        .map_err(|_| Error::Timestamp)
}

/// Renders a calendar day as `YYYY-MM-DD`.
pub fn format_date(value: Date) -> Result<String, Error> {
    let description = ::time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")
        .map_err(|_| Error::Timestamp)?;
    value.format(&description).map_err(|_| Error::Timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_day_is_rendered_with_its_zeroes() {
        let day = Date::from_calendar_date(2026, ::time::Month::September, 5).unwrap();
        assert_eq!(format_date(day).unwrap(), "2026-09-05");
    }

    // A stamp with no fractional part is the form this project writes. Parsing
    // it must survive a round trip: the equivalent code in MTProxyMax appended
    // a second 'Z' here and every expiry check silently read zero for months.
    #[test]
    fn stamp_without_a_fraction_survives_a_round_trip() {
        let text = "2026-12-31T23:59:59Z";
        let parsed = parse_rfc3339(text).unwrap();
        assert_eq!(format_rfc3339(parsed).unwrap(), text);
    }

    #[test]
    fn fraction_is_dropped() {
        let parsed = parse_rfc3339("2026-12-31T23:59:59.123456789Z").unwrap();
        assert_eq!(parsed.nanosecond(), 0);
        assert_eq!(format_rfc3339(parsed).unwrap(), "2026-12-31T23:59:59Z");
    }

    #[test]
    fn offset_is_normalised_to_utc() {
        let parsed = parse_rfc3339("2027-01-01T02:59:59+03:00").unwrap();
        assert_eq!(format_rfc3339(parsed).unwrap(), "2026-12-31T23:59:59Z");
    }

    #[test]
    fn malformed_input_is_rejected() {
        for text in [
            "",
            "2026-12-31T23:59:59ZZ",
            "2026-12-31T23:59:59",
            "2026-12-31",
            "31.12.2026",
            "not a timestamp",
        ] {
            assert_eq!(
                parse_rfc3339(text),
                Err(Error::Timestamp),
                "accepted {text}"
            );
        }
    }

    // RFC 3339 permits a leap second and the time crate clamps it to :59
    // rather than refusing it. Pinned here so a dependency change that starts
    // rejecting the value is caught instead of silently voiding an expiry.
    #[test]
    fn leap_second_is_clamped_to_the_previous_second() {
        let parsed = parse_rfc3339("2026-12-31T23:59:60Z").unwrap();
        assert_eq!(format_rfc3339(parsed).unwrap(), "2026-12-31T23:59:59Z");
    }
}
