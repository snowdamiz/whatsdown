use crate::MathError;

const SECONDS_PER_DAY: i64 = 86_400;
// Matches the upper year in chrono 0.4, used by Mesh's DateTime runtime.
const MAX_YEAR: i64 = 262_142;

pub(crate) struct Origin {
    year: i64,
    month: i64,
    day: i64,
    seconds_of_day: i64,
}

fn year_start_days(year: i64) -> i64 {
    let previous = year - 1;
    // There were 477 Gregorian leap days through 1969.
    365 * (year - 1970) + previous / 4 - previous / 100 + previous / 400 - 477
}

fn month_days(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl Origin {
    pub(crate) fn from_unix_seconds(seconds: i64) -> Result<Self, MathError> {
        let days = seconds / SECONDS_PER_DAY;
        if seconds < 0 || days >= year_start_days(MAX_YEAR + 1) {
            return Err(MathError::InvalidTime);
        }

        // Search only the bounded positive-year domain, using small scalars
        // rather than date libraries, allocations or large SBF stack values.
        let mut low = 1970;
        let mut high = MAX_YEAR + 1;
        while high - low > 1 {
            let middle = low + (high - low) / 2;
            if year_start_days(middle) <= days {
                low = middle;
            } else {
                high = middle;
            }
        }
        let mut day_in_year = days - year_start_days(low);
        let mut month = 1;
        while day_in_year >= month_days(low, month) {
            day_in_year -= month_days(low, month);
            month += 1;
        }
        Ok(Self {
            year: low,
            month,
            day: day_in_year + 1,
            seconds_of_day: seconds % SECONDS_PER_DAY,
        })
    }

    pub(crate) fn anniversary(&self, months: i64) -> Result<i64, MathError> {
        let index = self.month - 1 + months;
        let year = self.year + index / 12;
        let month = index % 12 + 1;
        if year > MAX_YEAR {
            return Err(MathError::InvalidTime);
        }
        let mut days = year_start_days(year) + self.day.min(month_days(year, month)) - 1;
        for preceding in 1..month {
            days += month_days(year, preceding);
        }
        Ok(days * SECONDS_PER_DAY + self.seconds_of_day)
    }
}
