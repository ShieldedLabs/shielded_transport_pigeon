//! Optional bounded-memory sender trace. CSV is an event stream, not a final packet table:
//! S=sent, F=fragment association, L=declared lost, A=ACK (including late ACK).
//! Join by (connection,seq); a late A after L cancels that loss. Pending sends are censored.
use std::io::{BufWriter, Write};

pub(crate) struct LossTrace(BufWriter<std::fs::File>);
impl LossTrace {
    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        let mut w = BufWriter::with_capacity(256 * 1024, std::fs::File::create(path)?);
        writeln!(w, "event,connection,seq,time_ns,payload_bytes,lost,message_id,fragment,fec,app_id,app_size")?;
        Ok(Self(w))
    }
    pub fn outcome(&mut self, event: char, connection: u16, seq: u64, time: u64) {
        writeln!(self.0, "{event},{connection},{seq},{time},0,{},-1,-1,0,-1,-1", (event == 'L') as u8).expect("write loss trace");
    }
    pub fn sent(&mut self, connection: u16, seq: u64, time: u64, payload: &[u8]) {
        writeln!(self.0, "S,{connection},{seq},{time},{},0,-1,-1,0,-1,-1", payload.len()).expect("write loss trace");
        let mut cursor = 0;
        while cursor + 8 <= payload.len() {
            let word = u64::from_le_bytes(payload[cursor..cursor+8].try_into().unwrap());
            if word == u64::MAX { break; }
            let fec = word & 1 != 0;
            let len = ((word >> 18) & 0x3fff) as usize;
            let header = if fec { 16 } else { 8 };
            if cursor + header + len > payload.len() { break; }
            // Fragment zero is systematic source data, including for FEC. An
            // application may interpret these first eight bytes as a tracing tag.
            let (app_id, app_size) = if word >> 32 == 0 && len >= 8 {
                let p = &payload[cursor + header..];
                (u32::from_le_bytes(p[..4].try_into().unwrap()) as i64,
                 u32::from_le_bytes(p[4..8].try_into().unwrap()) as i64)
            } else { (-1, -1) };
            writeln!(self.0, "F,{connection},{seq},{time},{len},0,{},{},{},{app_id},{app_size}", (word >> 2) & 0xffff, word >> 32, fec as u8).expect("write loss trace");
            cursor += header + len;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_csv_records_fragments_and_late_ack() {
        let p = std::env::temp_dir().join(format!("stp-trace-test-{}", std::process::id()));
        {
            let mut t = LossTrace::open(&p).unwrap();
            let mut b = Vec::from((2u64 | (7 << 2) | (3 << 18) | (4 << 32)).to_le_bytes());
            b.extend_from_slice(&[1, 2, 3]);
            t.sent(8, 9, 10, &b);
            let mut fec = Vec::from((1u64 | (9 << 2) | (8 << 18)).to_le_bytes());
            fec.extend_from_slice(&[0; 8]);
            fec.extend_from_slice(&7u32.to_le_bytes());
            fec.extend_from_slice(&1000u32.to_le_bytes());
            t.sent(8, 10, 11, &fec);
            t.outcome('L', 8, 9, 20);
            t.outcome('A', 8, 9, 30);
        }
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains("F,8,9,10,3,0,7,4,0,-1,-1"));
        assert!(s.contains("F,8,10,11,8,0,9,0,1,7,1000"));
        assert!(s.contains("L,8,9,20,0,1,-1,-1,0"));
        assert!(s.contains("A,8,9,30,0,0,-1,-1,0"));
        std::fs::remove_file(p).unwrap();
    }
}
