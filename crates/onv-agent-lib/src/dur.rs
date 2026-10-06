//! A duration written with its unit: `500ms`, `90s`, `5m`, `24h`, `30d`.
//!
//! The one way this crate's two programs read a time out of a file (omnuv's
//! `docs/plans/runtime-configuration.md`: units in the value, never a bare
//! number whose unit lives in a key's name). Shared by the Provider Agent and
//! the Workload Agent through `#[path]`, because the crate has no library and
//! the writer of `workload.yaml` and its reader must read the same text the
//! same way.
//!
//! Milliseconds, where Core's own `Dur` counts seconds: one value here, the
//! Workload Agent's degraded threshold, has always been under a second's
//! resolution away from mattering (two seconds, measured on a trivial
//! handler), and a unit the type cannot hold is a value nobody can write.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dur(u64);

impl Dur {
    pub const fn millis(n: u64) -> Self {
        Dur(n)
    }
    pub const fn secs(n: u64) -> Self {
        Dur(n * 1000)
    }
    pub const fn mins(n: u64) -> Self {
        Dur(n * 60_000)
    }
    pub const fn hours(n: u64) -> Self {
        Dur(n * 3_600_000)
    }
    pub const fn as_millis(self) -> u64 {
        self.0
    }
    /// Whole seconds, rounded down.
    pub const fn as_secs(self) -> u64 {
        self.0 / 1000
    }
    pub const fn std(self) -> std::time::Duration {
        std::time::Duration::from_millis(self.0)
    }
}

const UNITS: [(&str, u64); 5] = [("d", 86_400_000), ("h", 3_600_000), ("m", 60_000), ("s", 1000), ("ms", 1)];

impl fmt::Display for Dur {
    /// The largest unit that states the value exactly: `300s` reads `5m`, so
    /// two spellings of one value print, and hash, as one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("0s");
        }
        // Milliseconds divide everything, so the search always ends.
        let (unit, per) = UNITS.iter().find(|(_, per)| self.0.is_multiple_of(*per)).copied().unwrap_or(("ms", 1));
        write!(f, "{}{unit}", self.0 / per)
    }
}

impl std::str::FromStr for Dur {
    type Err = String;
    fn from_str(v: &str) -> Result<Self, Self::Err> {
        let v = v.trim();
        let (n, unit) = v.split_at(v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len()));
        let n: u64 = n.parse().map_err(|_| {
            format!("`{v}` is not a duration: a whole number and a unit, like 500ms, 90s, 5m, 24h or 30d")
        })?;
        if unit.is_empty() {
            return Err(format!("`{v}` has no unit: write {n}s, or another of ms, s, m, h, d"));
        }
        let per = UNITS
            .iter()
            .find(|(u, _)| *u == unit)
            .map(|(_, per)| *per)
            .ok_or_else(|| format!("`{v}`: the unit must be ms, s, m, h or d"))?;
        n.checked_mul(per).map(Dur).ok_or_else(|| format!("`{v}` is too long"))
    }
}

impl Serialize for Dur {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Dur {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Text;
        impl serde::de::Visitor<'_> for Text {
            type Value = Dur;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a duration with its unit, like 90s or 5m")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Dur, E> {
                v.parse().map_err(E::custom)
            }
            // A bare number is the one mistake worth answering in words: it is
            // what `inventoryEverySecs: 300` looked like, and which unit it
            // meant is exactly what the key used to say and this one does not.
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Dur, E> {
                Err(E::custom(format!("`{v}` has no unit: write {v}s, or another of ms, s, m, h, d")))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Dur, E> {
                Err(E::custom(format!("`{v}` is not a duration: a whole number and a unit, like 90s")))
            }
        }
        d.deserialize_any(Text)
    }
}

#[cfg(test)]
mod tests {
    use super::Dur;

    #[test]
    fn a_duration_carries_its_unit_both_ways() {
        for (text, millis, back) in [
            ("500ms", 500, "500ms"),
            ("2000ms", 2000, "2s"),
            ("90s", 90_000, "90s"),
            ("300s", 300_000, "5m"),
            ("5m", 300_000, "5m"),
            ("24h", 86_400_000, "1d"),
            ("30d", 2_592_000_000, "30d"),
            ("0s", 0, "0s"),
        ] {
            let d: Dur = text.parse().unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!((d.as_millis(), d.to_string().as_str()), (millis, back), "{text}");
        }
        for bad in ["90", "5 minutes", "m", "-5s", "1.5h", "5w", "", "99999999999999999999d"] {
            assert!(bad.parse::<Dur>().is_err(), "{bad:?} was accepted");
        }
    }

    /// A bare number in a file is refused in words that say what to write.
    #[test]
    fn a_bare_number_is_refused_with_the_unit_it_needs() {
        let e = serde_yaml_ng::from_str::<Dur>("300").expect_err("a bare number was taken");
        assert!(e.to_string().contains("300s"), "{e}");
        let d: Dur = serde_yaml_ng::from_str("5m").expect("a duration");
        assert_eq!(d, Dur::mins(5));
    }
}
