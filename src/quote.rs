use crate::error::{Result, ServiceError};

pub const TDX_TEE_TYPE: u32 = 0x0000_0081;
pub const TDX_V10_BODY_SIZE: usize = 584;
pub const TDX_V15_BODY_SIZE: usize = 648;

const QUOTE_HEADER_SIZE: usize = 48;
const TDX_RTMR_BASE_OFFSET: usize = 328;
const TDX_RTMR3_OFFSET: usize = TDX_RTMR_BASE_OFFSET + 3 * 48;
const TDX_REPORT_DATA_OFFSET: usize = 520;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteVersion {
    V4,
    V5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteBodyType {
    Tdx10,
    Tdx15,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTdxQuote {
    pub version: QuoteVersion,
    pub body_type: QuoteBodyType,
    pub rtmr3: [u8; 48],
    pub report_data: [u8; 64],
}

pub fn parse_tdx_quote(quote: &[u8]) -> Result<ParsedTdxQuote> {
    if quote.len() < QUOTE_HEADER_SIZE + 4 {
        return Err(ServiceError::Parse(format!(
            "quote too short: {} bytes",
            quote.len()
        )));
    }

    let version = read_u16_le(quote, 0)?;
    let tee_type = read_u32_le(quote, 4)?;
    if tee_type != TDX_TEE_TYPE {
        return Err(ServiceError::Parse(format!(
            "unexpected tee type: 0x{tee_type:08x}"
        )));
    }

    match version {
        4 => parse_v4_tdx_quote(quote),
        5 => parse_v5_tdx_quote(quote),
        _ => Err(ServiceError::Parse(format!(
            "unsupported quote version: {version}"
        ))),
    }
}

fn parse_v4_tdx_quote(quote: &[u8]) -> Result<ParsedTdxQuote> {
    let body_start = QUOTE_HEADER_SIZE;
    let body_end = body_start + TDX_V10_BODY_SIZE;
    let signature_len_offset = body_end;
    let signature_len = read_u32_le(quote, signature_len_offset)? as usize;
    let expected_total = signature_len_offset
        .checked_add(4)
        .and_then(|value| value.checked_add(signature_len))
        .ok_or_else(|| ServiceError::Parse("quote length overflow".to_owned()))?;

    if quote.len() != expected_total {
        return Err(ServiceError::Parse(format!(
            "quote length mismatch for v4: got {} expected {}",
            quote.len(),
            expected_total
        )));
    }

    let body = quote
        .get(body_start..body_end)
        .ok_or_else(|| ServiceError::Parse("missing v4 quote body".to_owned()))?;
    parse_tdx_body(body, QuoteVersion::V4, QuoteBodyType::Tdx10)
}

fn parse_v5_tdx_quote(quote: &[u8]) -> Result<ParsedTdxQuote> {
    let descriptor_start = QUOTE_HEADER_SIZE;
    let body_type_raw = read_u16_le(quote, descriptor_start)?;
    let body_size = read_u32_le(quote, descriptor_start + 2)? as usize;
    let body_start = descriptor_start + 6;
    let body_end = body_start
        .checked_add(body_size)
        .ok_or_else(|| ServiceError::Parse("v5 body size overflow".to_owned()))?;
    let signature_len_offset = body_end;
    let signature_len = read_u32_le(quote, signature_len_offset)? as usize;
    let expected_total = signature_len_offset
        .checked_add(4)
        .and_then(|value| value.checked_add(signature_len))
        .ok_or_else(|| ServiceError::Parse("quote length overflow".to_owned()))?;

    if quote.len() != expected_total {
        return Err(ServiceError::Parse(format!(
            "quote length mismatch for v5: got {} expected {}",
            quote.len(),
            expected_total
        )));
    }

    let body_type = match body_type_raw {
        2 => QuoteBodyType::Tdx10,
        3 => QuoteBodyType::Tdx15,
        _ => {
            return Err(ServiceError::Parse(format!(
                "unsupported v5 body type: {body_type_raw}"
            )));
        }
    };

    let min_size = match body_type {
        QuoteBodyType::Tdx10 => TDX_V10_BODY_SIZE,
        QuoteBodyType::Tdx15 => TDX_V15_BODY_SIZE,
    };
    if body_size < min_size {
        return Err(ServiceError::Parse(format!(
            "v5 body too short for {:?}: {body_size} < {min_size}",
            body_type
        )));
    }

    let body = quote
        .get(body_start..body_end)
        .ok_or_else(|| ServiceError::Parse("missing v5 quote body".to_owned()))?;
    parse_tdx_body(body, QuoteVersion::V5, body_type)
}

fn parse_tdx_body(
    body: &[u8],
    version: QuoteVersion,
    body_type: QuoteBodyType,
) -> Result<ParsedTdxQuote> {
    if body.len() < TDX_V10_BODY_SIZE {
        return Err(ServiceError::Parse(format!(
            "tdx body too short: {} < {}",
            body.len(),
            TDX_V10_BODY_SIZE
        )));
    }

    let mut rtmr3 = [0_u8; 48];
    rtmr3.copy_from_slice(
        body.get(TDX_RTMR3_OFFSET..TDX_RTMR3_OFFSET + 48)
            .ok_or_else(|| ServiceError::Parse("missing RTMR3 in quote body".to_owned()))?,
    );

    let mut report_data = [0_u8; 64];
    report_data.copy_from_slice(
        body.get(TDX_REPORT_DATA_OFFSET..TDX_REPORT_DATA_OFFSET + 64)
            .ok_or_else(|| ServiceError::Parse("missing reportdata in quote body".to_owned()))?,
    );

    Ok(ParsedTdxQuote {
        version,
        body_type,
        rtmr3,
        report_data,
    })
}

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data.get(offset..offset + 2).ok_or_else(|| {
        ServiceError::Parse(format!("quote missing u16 field at offset {offset}"))
    })?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data.get(offset..offset + 4).ok_or_else(|| {
        ServiceError::Parse(format!("quote missing u32 field at offset {offset}"))
    })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::{QuoteBodyType, QuoteVersion, TDX_TEE_TYPE, parse_tdx_quote};

    #[test]
    fn parse_v4_extracts_rtmr3_and_report_data() {
        let mut quote = vec![0_u8; 48 + 584 + 4 + 16];
        quote[0..2].copy_from_slice(&4_u16.to_le_bytes());
        quote[4..8].copy_from_slice(&TDX_TEE_TYPE.to_le_bytes());
        quote[48 + 472..48 + 520].fill(0x11);
        quote[48 + 520..48 + 584].fill(0x22);
        quote[48 + 584..48 + 588].copy_from_slice(&16_u32.to_le_bytes());

        let parsed = parse_tdx_quote(quote.as_slice()).expect("quote should parse");
        assert_eq!(parsed.version, QuoteVersion::V4);
        assert_eq!(parsed.body_type, QuoteBodyType::Tdx10);
        assert_eq!(parsed.rtmr3, [0x11_u8; 48]);
        assert_eq!(parsed.report_data, [0x22_u8; 64]);
    }

    #[test]
    fn parse_v5_extracts_rtmr3_and_report_data() {
        let mut quote = vec![0_u8; 48 + 6 + 648 + 4 + 8];
        quote[0..2].copy_from_slice(&5_u16.to_le_bytes());
        quote[4..8].copy_from_slice(&TDX_TEE_TYPE.to_le_bytes());
        quote[48..50].copy_from_slice(&3_u16.to_le_bytes());
        quote[50..54].copy_from_slice(&648_u32.to_le_bytes());
        let body_start = 54;
        quote[body_start + 472..body_start + 520].fill(0x33);
        quote[body_start + 520..body_start + 584].fill(0x44);
        quote[body_start + 648..body_start + 652].copy_from_slice(&8_u32.to_le_bytes());

        let parsed = parse_tdx_quote(quote.as_slice()).expect("quote should parse");
        assert_eq!(parsed.version, QuoteVersion::V5);
        assert_eq!(parsed.body_type, QuoteBodyType::Tdx15);
        assert_eq!(parsed.rtmr3, [0x33_u8; 48]);
        assert_eq!(parsed.report_data, [0x44_u8; 64]);
    }
}
