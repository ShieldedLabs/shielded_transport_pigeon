//! Canonical URL-safe unpadded Base64 used by STP addresses.
//! Kept private: the public address format is unchanged.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(crate) fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().saturating_add(2) / 3 * 4);
    for chunk in input.chunks(3) {
        let a = chunk[0];
        out.push(ALPHABET[(a >> 2) as usize] as char);
        let b = chunk.get(1).copied().unwrap_or(0);
        out.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            let c = chunk.get(2).copied().unwrap_or(0);
            out.push(ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char);
            if chunk.len() > 2 { out.push(ALPHABET[(c & 63) as usize] as char); }
        }
    }
    out
}

fn digit(byte: u8) -> Option<u8> {
    Some(match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    })
}

pub(crate) fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 == 1 { return None; }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let a = digit(chunk[0])?;
        let b = digit(chunk[1])?;
        out.push((a << 2) | (b >> 4));
        if chunk.len() == 2 {
            if b & 15 != 0 { return None; }
            continue;
        }
        let c = digit(chunk[2])?;
        out.push((b << 4) | (c >> 2));
        if chunk.len() == 3 {
            if c & 3 != 0 { return None; }
            continue;
        }
        out.push((c << 6) | digit(chunk[3])?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_vectors_and_url_alphabet() {
        for (plain, coded) in [("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"),
            ("foob", "Zm9vYg"), ("fooba", "Zm9vYmE"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(decode(coded).unwrap(), plain.as_bytes());
        }
        assert_eq!(encode(&[251, 255, 255]), "-___");
        assert_eq!(decode("-___"), Some(vec![251, 255, 255]));
    }

    #[test]
    fn rejects_noncanonical_and_padded_strings() {
        for bad in ["A", "AAAAA", "Zg=", "Zg==", "Zg\n", "Zg ", "+w", "/w", "Zh", "Zm9", "éé", "Zg\0"] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
        for a in 0..64u8 {
            for b in 0..64u8 {
                let coded = String::from_utf8(vec![ALPHABET[a as usize], ALPHABET[b as usize]]).unwrap();
                assert_eq!(decode(&coded).is_some(), b & 15 == 0);
            }
        }
    }

    #[test]
    fn varied_lengths_round_trip() {
        let data: Vec<u8> = (0..8193).map(|i| ((i * 73 + i / 256) & 255) as u8).collect();
        for len in 0..=data.len() {
            let coded = encode(&data[..len]);
            assert_eq!(coded.len(), (len * 8 + 5) / 6);
            assert_eq!(decode(&coded).as_deref(), Some(&data[..len]));
        }
    }
}
