//! Strict parser for Solana Pay transfer requests:
//! `solana:<recipient>?amount=&spl-token=&reference=&label=&message=&memo=`.

use crate::{tx::Pubkey, Error};

/// A decimal amount in user units: `mantissa / 10^scale` ("1.5" is 15 with scale 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Amount {
    pub mantissa: u64,
    pub scale: u8,
}

impl Amount {
    /// Canonical decimals only: no sign, exponent, leading zeros, bare or trailing point, or
    /// trailing fractional zeros.
    fn parse(s: &str) -> Result<Amount, Error> {
        let (whole, fraction) = s.split_once('.').unwrap_or((s, ""));
        let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
        let canonical = digits(whole)
            && (whole == "0" || !whole.starts_with('0'))
            && ((fraction.is_empty() && !s.ends_with('.'))
                || (digits(fraction) && !fraction.ends_with('0')));
        if !canonical {
            return Err(Error::Amount);
        }
        let mantissa = format!("{whole}{fraction}")
            .parse()
            .map_err(|_| Error::Amount)?;
        let scale = u8::try_from(fraction.len()).map_err(|_| Error::Amount)?;
        Ok(Amount { mantissa, scale })
    }

    /// Base units for an asset with `decimals` (9 for SOL, 6 for USDC).
    pub fn base_units(self, decimals: u8) -> Result<u64, Error> {
        let shift = decimals.checked_sub(self.scale).ok_or(Error::Decimals)?;
        10u64
            .checked_pow(shift.into())
            .and_then(|factor| self.mantissa.checked_mul(factor))
            .ok_or(Error::Amount)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PayRequest {
    pub recipient: Pubkey,
    pub amount: Option<Amount>,
    /// SPL mint; `None` means SOL.
    pub spl_token: Option<Pubkey>,
    /// In URL order; Solana Pay allows several.
    pub references: Vec<Pubkey>,
    pub label: Option<String>,
    pub message: Option<String>,
    pub memo: Option<String>,
}

/// Parses a transfer request. Everything outside the spec is refused: other schemes, unknown or
/// repeated parameters (only distinct `reference`s may repeat), empty values, malformed
/// percent-encoding, bad base58, non-canonical amounts, SOL amounts with more than 9 decimals,
/// and control or bidirectional-override characters in the text shown to the user.
pub fn parse_pay_url(url: &str) -> Result<PayRequest, Error> {
    if !url.bytes().all(|b| b.is_ascii_graphic() && b != b'#') {
        return Err(Error::Url);
    }
    let rest = url.strip_prefix("solana:").ok_or(Error::Url)?;
    let (recipient, query) = match rest.split_once('?') {
        Some((recipient, query)) => (recipient, Some(query)),
        None => (rest, None),
    };
    let mut request = PayRequest {
        recipient: pubkey(recipient)?,
        ..PayRequest::default()
    };
    for pair in query.into_iter().flat_map(|q| q.split('&')) {
        let (key, raw) = pair.split_once('=').ok_or(Error::Url)?;
        if !matches!(
            key,
            "amount" | "spl-token" | "reference" | "label" | "message" | "memo"
        ) {
            return Err(if key.is_empty() {
                Error::Url
            } else {
                Error::UnknownParam
            });
        }
        let value = percent_decode(raw)?;
        match key {
            "amount" => once(&mut request.amount, Amount::parse(&value)?)?,
            "spl-token" => once(&mut request.spl_token, pubkey(&value)?)?,
            "label" => once(&mut request.label, text(value)?)?,
            "message" => once(&mut request.message, text(value)?)?,
            "memo" => once(&mut request.memo, text(value)?)?,
            _ => {
                let reference = pubkey(&value)?;
                if request.references.contains(&reference) {
                    return Err(Error::DuplicateParam);
                }
                request.references.push(reference);
            }
        }
    }
    if let (None, Some(amount)) = (request.spl_token, request.amount) {
        amount.base_units(9)?;
    }
    Ok(request)
}

fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), Error> {
    match slot.replace(value) {
        Some(_) => Err(Error::DuplicateParam),
        None => Ok(()),
    }
}

fn pubkey(s: &str) -> Result<Pubkey, Error> {
    let bytes = bs58::decode(s).into_vec().map_err(|_| Error::Base58)?;
    bytes.try_into().map_err(|_| Error::Base58)
}

/// `%XX` escapes and `+` for space, as `URLSearchParams` (which Solana Pay's own parser uses)
/// decodes them. A raw `=` or an empty value is malformed.
fn percent_decode(raw: &str) -> Result<String, Error> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3).ok_or(Error::Url)?;
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return Err(Error::Url);
                }
                let hex = std::str::from_utf8(hex).map_err(|_| Error::Url)?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| Error::Url)?);
                i += 3;
                continue;
            }
            b'=' => return Err(Error::Url),
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    if out.is_empty() {
        return Err(Error::Url);
    }
    String::from_utf8(out).map_err(|_| Error::Text)
}

/// Text shown to the user: no control characters and no bidirectional overrides or isolates,
/// which could make a label read as something else.
fn text(value: String) -> Result<String, Error> {
    let spoofing =
        |c: char| c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
    if value.chars().any(spoofing) {
        return Err(Error::Text);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::USDC_MINT;

    const R: &str = "mvines9iiHiQTysrwkJjGf2gb9Ex9jXJX8ns3qwf2kN";
    const REF_A: &str = "H6wH6oXYdaBFf6FyRbiARKHyqfPiKDU666mSoXgHCst5";
    const REF_B: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";

    fn key(s: &str) -> Pubkey {
        bs58::decode(s).into_vec().unwrap().try_into().unwrap()
    }

    fn err(url: &str) -> Error {
        parse_pay_url(url).unwrap_err()
    }

    #[test]
    fn parses_the_spec_examples() {
        // Examples from the Solana Pay transfer request specification.
        let sol = parse_pay_url(&format!("solana:{R}?amount=1&label=Michael&message=Thanks%20for%20all%20the%20fish&memo=OrderId12345")).unwrap();
        assert_eq!(
            sol,
            PayRequest {
                recipient: key(R),
                amount: Some(Amount {
                    mantissa: 1,
                    scale: 0
                }),
                label: Some("Michael".into()),
                message: Some("Thanks for all the fish".into()),
                memo: Some("OrderId12345".into()),
                ..Default::default()
            }
        );
        assert_eq!(sol.amount.unwrap().base_units(9), Ok(1_000_000_000));

        let usdc = parse_pay_url(&format!(
            "solana:{R}?amount=0.01&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        ))
        .unwrap();
        assert_eq!(usdc.spl_token, Some(USDC_MINT));
        assert_eq!(usdc.amount.unwrap().base_units(6), Ok(10_000));

        assert_eq!(
            parse_pay_url(&format!("solana:{R}")).unwrap(),
            PayRequest {
                recipient: key(R),
                ..Default::default()
            }
        );
    }

    #[test]
    fn keeps_references_in_order_and_decodes_text() {
        let req = parse_pay_url(&format!(
            "solana:{R}?reference={REF_A}&label=Caf%C3%A9+Morse&reference={REF_B}"
        ))
        .unwrap();
        assert_eq!(req.references, vec![key(REF_A), key(REF_B)]);
        assert_eq!(req.label.as_deref(), Some("Café Morse"));
    }

    #[test]
    fn requires_the_lowercase_solana_scheme() {
        for url in [
            R.to_string(),
            format!("Solana:{R}"),
            format!("solana://{R}"),
            format!("web+solana:{R}"),
        ] {
            assert!(matches!(err(&url), Error::Url | Error::Base58), "{url}");
        }
    }

    #[test]
    fn rejects_bad_base58_and_wrong_lengths() {
        for url in [
            "solana:0OIl".to_string(),
            "solana:https%3A%2F%2Fexample.com".to_string(),
            format!("solana:{}", &R[..20]),
            format!("solana:{R}?spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8"),
            format!("solana:{R}?reference=abc"),
        ] {
            assert_eq!(err(&url), Error::Base58, "{url}");
        }
    }

    #[test]
    fn rejects_unknown_params() {
        for q in ["foo=1", "Amount=1", "amount%3D1=1", "request=https"] {
            assert_eq!(err(&format!("solana:{R}?{q}")), Error::UnknownParam, "{q}");
        }
    }

    #[test]
    fn rejects_duplicate_params_and_repeated_references() {
        for q in ["amount=1&amount=1", "label=a&label=b", "message=a&message=a", "memo=a&memo=b",
                  "spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"] {
            assert_eq!(err(&format!("solana:{R}?{q}")), Error::DuplicateParam, "{q}");
        }
        assert_eq!(
            err(&format!("solana:{R}?reference={REF_A}&reference={REF_A}")),
            Error::DuplicateParam
        );
    }

    #[test]
    fn rejects_malformed_query_syntax() {
        for q in [
            "",
            "amount",
            "amount=",
            "&amount=1",
            "amount=1&",
            "amount=1&&label=a",
            "=1",
            "label==",
            "label=%",
            "label=%4",
            "label=%G1",
            "label=%+1",
        ] {
            assert_eq!(err(&format!("solana:{R}?{q}")), Error::Url, "{q:?}");
        }
    }

    #[test]
    fn rejects_non_ascii_spaces_and_fragments() {
        for url in [
            format!("solana:{R}?label=a b"),
            format!("solana:{R}?label=café"),
            format!("solana:{R}#x"),
            format!(" solana:{R}"),
        ] {
            assert_eq!(err(&url), Error::Url, "{url:?}");
        }
    }

    #[test]
    fn rejects_non_canonical_amounts() {
        for a in [
            "01",
            "00",
            "1.",
            ".5",
            "1.50",
            "0.0",
            "1.0",
            "-1",
            "%2B1",
            "1e3",
            "1,5",
            "1.2.3",
            "0x10",
            "18446744073709551616",
        ] {
            assert_eq!(err(&format!("solana:{R}?amount={a}")), Error::Amount, "{a}");
        }
        for (a, mantissa, scale) in [
            ("0", 0, 0),
            ("0.5", 5, 1),
            ("12.25", 1225, 2),
            ("18446744073.709551615", u64::MAX, 9),
        ] {
            let req = parse_pay_url(&format!("solana:{R}?amount={a}")).unwrap();
            assert_eq!(req.amount, Some(Amount { mantissa, scale }), "{a}");
        }
    }

    #[test]
    fn sol_amounts_have_at_most_9_decimals() {
        assert!(parse_pay_url(&format!("solana:{R}?amount=0.000000001")).is_ok());
        assert_eq!(
            err(&format!("solana:{R}?amount=0.0000000001")),
            Error::Decimals
        );
    }

    #[test]
    fn base_units_refuse_extra_decimals_and_overflow() {
        let amount = Amount {
            mantissa: 1_234_567,
            scale: 7,
        };
        assert_eq!(amount.base_units(6), Err(Error::Decimals));
        assert_eq!(amount.base_units(9), Ok(123_456_700));
        assert_eq!(
            Amount {
                mantissa: u64::MAX,
                scale: 0
            }
            .base_units(1),
            Err(Error::Amount)
        );
    }

    #[test]
    fn rejects_invalid_utf8_and_control_characters_in_text() {
        for q in [
            "label=%FF",
            "message=a%0Ab",
            "memo=%7F",
            "label=%E2%80%AEevil",
            "label=%E2%81%A6x",
        ] {
            assert_eq!(err(&format!("solana:{R}?{q}")), Error::Text, "{q}");
        }
    }
}
