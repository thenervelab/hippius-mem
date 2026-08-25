//! Proleptic-Gregorian calendar arithmetic, shared by the stderr log
//! timestamps and the `import` date filter.
//!
//! Both directions are Howard Hinnant's closed-form algorithms (exact for any
//! date, no month-length loops), and because they are exact inverses the test
//! below checks them against each other over the whole supported range rather
//! than trusting a handful of hand-picked dates.

/// Days from the Unix epoch (1970-01-01) to the given date.
///
/// Pure arithmetic: the caller validates `month` and `day` (see the `import`
/// module's month-length gate), this only converts.
#[cfg(any(feature = "import", test))]
pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // Shift so March is month 0: the leap day then falls at the year's end, which
    // is what makes the era arithmetic below closed-form.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // year of era, [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 }; // March-based month, [0, 11]
    let doy = (153 * mp + 2) / 5 + day - 1; // day of year, [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day of era, [0, 146096]
    era * 146_097 + doe - 719_468
}

/// `(year, month, day)` for a day count since 1970-01-01 — the unsigned
/// inverse of `days_from_civil`, for timestamps (never before the epoch).
pub(crate) fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{civil_from_days, days_from_civil};

    /// (seconds since the epoch, y-m-d) — checked against Python's datetime.
    const VECTORS: &[(u64, (u64, u64, u64))] = &[
        (0, (1970, 1, 1)),
        (86_399, (1970, 1, 1)),
        (951_782_400, (2000, 2, 29)),
        (1_700_000_000, (2023, 11, 14)),
        (1_709_164_800, (2024, 2, 29)),
        (4_102_444_800, (2100, 1, 1)),
        (253_402_300_799, (9999, 12, 31)),
    ];

    #[test]
    fn known_dates_in_both_directions() {
        for &(seconds, (y, m, d)) in VECTORS {
            assert_eq!(civil_from_days(seconds / 86_400), (y, m, d), "{seconds}");
            let days = days_from_civil(y.cast_signed(), m.cast_signed(), d.cast_signed());
            assert_eq!(days, (seconds / 86_400).cast_signed(), "{y}-{m}-{d}");
        }
        assert_eq!(civil_from_days(59), (1970, 3, 1));
        assert_eq!(
            days_from_civil(1969, 12, 31),
            -1,
            "the signed direction reaches before the epoch"
        );
    }

    proptest! {
        /// The two algorithms are exact inverses over every date a timestamp or
        /// an `import --since` can name.
        #[test]
        fn round_trips_over_the_supported_range(
            year in 1970i64..=9999,
            month in 1i64..=12,
            day in 1i64..=28,
        ) {
            let days = days_from_civil(year, month, day);
            prop_assert!(days >= 0);
            prop_assert_eq!(
                civil_from_days(days.cast_unsigned()),
                (year.cast_unsigned(), month.cast_unsigned(), day.cast_unsigned())
            );
        }

        /// Consecutive days never skip or repeat a date: each step advances by
        /// exactly one day in the inverse as well.
        #[test]
        fn consecutive_days_are_consecutive_dates(days in 0u64..3_000_000) {
            let (y, m, d) = civil_from_days(days);
            let next = days_from_civil(y.cast_signed(), m.cast_signed(), d.cast_signed()) + 1;
            prop_assert_eq!(next.cast_unsigned(), days + 1);
        }
    }
}
