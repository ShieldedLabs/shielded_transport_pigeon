const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
pub(crate) fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().saturating_add(2) / 3 * 4);
    for chunk in input.chunks(3) {
        let a = chunk[0]; out.push(ALPHABET[(a >> 2) as usize] as char); let b = chunk.get(1).copied().unwrap_or(0);
        out.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            let c = chunk.get(2).copied().unwrap_or(0);
            out.push(ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char);
            if chunk.len() > 2 { out.push(ALPHABET[(c & 63) as usize] as char); } } }
    out }
fn digit(byte: u8) -> Option<u8> {
    Some(match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None, }) }
pub(crate) fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 == 1 { return None; }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let a = digit(chunk[0])?; let b = digit(chunk[1])?; out.push((a << 2) | (b >> 4));
        if chunk.len() == 2 { if b & 15 != 0 { return None; } continue; }
        let c = digit(chunk[2])?; out.push((b << 4) | (c >> 2));
        if chunk.len() == 3 { if c & 3 != 0 { return None; } continue; }
        out.push((c << 6) | digit(chunk[3])?); }
    Some(out) }
