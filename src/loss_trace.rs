//! Optional bounded-memory sender trace. CSV is an event stream, not a final packet table:
//! S=sent, F=fragment association, L=declared lost, A=ACK (including late ACK).
//! Join by (connection,seq); a late A after L cancels that loss. Pending sends are censored.
use std::io::{BufWriter, Write};

pub(crate) struct LossTrace(BufWriter<std::fs::File>);
impl LossTrace {
    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        let mut w = BufWriter::with_capacity(256 * 1024, std::fs::File::create(path)?);
        writeln!(w, "event,connection,seq,time_ns,payload_bytes,lost,message_id,fragment,fec")?;
        Ok(Self(w))
    }
    pub fn outcome(&mut self, event: char, connection: u16, seq: u64, time: u64) {
        writeln!(self.0, "{event},{connection},{seq},{time},0,{},-1,-1,0", (event == 'L') as u8).expect("write loss trace");
    }
    pub fn sent(&mut self, connection: u16, seq: u64, time: u64, payload: &[u8]) {
        writeln!(self.0, "S,{connection},{seq},{time},{},0,-1,-1,0", payload.len()).expect("write loss trace");
        let mut cursor = 0;
        while let Some((word, plain_header)) = crate::stp::read_fragment_header(&payload[cursor..]) {
            let fec = word & 1 != 0;
            let len = ((word >> 18) & 0x3fff) as usize;
            let header = if fec {
                let Some(size) = crate::stp::fec_fragment_header_size(&payload[cursor..]) else { break; };
                size
            } else { plain_header };
            if cursor + header + len > payload.len() { break; }
            writeln!(self.0, "F,{connection},{seq},{time},{len},0,{},{},{}", (word >> 2) & 0xffff, word >> 32, fec as u8).expect("write loss trace");
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
            t.outcome('L', 8, 9, 20);
            t.outcome('A', 8, 9, 30);
        }
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains("F,8,9,10,3,0,7,4,0"));
        assert!(s.contains("L,8,9,20,0,1,-1,-1,0"));
        assert!(s.contains("A,8,9,30,0,0,-1,-1,0"));
        std::fs::remove_file(p).unwrap();
    }
}
