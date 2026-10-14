//! Optional bounded-memory sender trace. CSV is an event stream, not a final packet table:
//! S=data sent, P=control/probe sent, F=fragment association, L=declared lost, A=ACK (including late ACK).
//! C=the exact controller context used to pace the following send, X=congestion cut.
//! Join by (connection,seq); a late A after L cancels that loss. Pending sends are censored.
use std::io::{BufWriter, Write};

#[derive(Clone, Copy, Debug)]
pub(crate) struct CcContext {
    pub pps: f64,
    pub slope_ppsps: f64,
    pub rtt_ns: u64,
    pub feedback_ns: u64,
    pub mode: char,
}

pub(crate) struct LossTrace(BufWriter<std::fs::File>, std::collections::HashMap<u16, CcContext>);
impl LossTrace {
    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        let mut w = BufWriter::with_capacity(256 * 1024, std::fs::File::create(path)?);
        writeln!(w, "event,connection,seq,time_ns,payload_bytes,lost,message_id,fragment,fec,cc_pps,slope_ppsps,rtt_ns,feedback_ns,cc_mode,cut_kind,cause_send_ns,dscp")?;
        Ok(Self(w, std::collections::HashMap::new()))
    }
    pub fn set_cc(&mut self, connection: u16, context: CcContext) {
        self.1.insert(connection, context);
    }
    pub fn cut(&mut self, connection: u16, seq: u64, time: u64, sent: u64, kind: &str, context: CcContext) {
        self.cc_row('X', connection, seq, time, sent, kind, context);
    }
    fn cc_row(&mut self, event: char, connection: u16, seq: u64, time: u64, sent: u64, kind: &str, c: CcContext) {
        writeln!(self.0, "{event},{connection},{seq},{time},0,0,-1,-1,0,{},{},{},{},{},{kind},{sent},",
            c.pps, c.slope_ppsps, c.rtt_ns, c.feedback_ns, c.mode).expect("write CC trace");
    }
    pub fn outcome(&mut self, event: char, connection: u16, seq: u64, time: u64) {
        writeln!(self.0, "{event},{connection},{seq},{time},0,{},-1,-1,0,,,,,,,,", (event == 'L') as u8).expect("write loss trace");
    }
    pub fn control_sent(&mut self, connection: u16, seq: u64, time: u64, len: usize, dscp: u8) {
        writeln!(self.0, "P,{connection},{seq},{time},{len},0,-1,-1,0,,,,,,,,{dscp}").expect("write control trace");
    }
    pub fn sent(&mut self, connection: u16, seq: u64, time: u64, payload: &[u8], dscp: u8) {
        if let Some(context) = self.1.get(&connection).copied() {
            self.cc_row('C', connection, seq, time, 0, "", context);
        }
        writeln!(self.0, "S,{connection},{seq},{time},{},0,-1,-1,0,,,,,,,,{dscp}", payload.len()).expect("write loss trace");
        let mut cursor = 0;
        while let Some((word, plain_header)) = crate::stp::read_fragment_header(&payload[cursor..]) {
            let fec = word & 1 != 0;
            let len = ((word >> 18) & 0x3fff) as usize;
            let header = if fec {
                let Some(size) = crate::stp::fec_fragment_header_size(&payload[cursor..]) else { break; };
                size
            } else { plain_header };
            if cursor + header + len > payload.len() { break; }
            writeln!(self.0, "F,{connection},{seq},{time},{len},0,{},{},{},,,,,,,,", (word >> 2) & 0xffff, word >> 32, fec as u8).expect("write loss trace");
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
            let c = CcContext { pps: 1000.0, slope_ppsps: 25.0, rtt_ns: 200_000_000, feedback_ns: 222_500_000, mode: 'P' };
            t.set_cc(8, c);
            t.sent(8, 9, 10, &b, 0);
            t.control_sent(8, 10, 12, 1162, 18);
            t.cut(8, 9, 11, 10, "early", c);
            t.outcome('L', 8, 9, 20);
            t.outcome('A', 8, 9, 30);
        }
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains("F,8,9,10,3,0,7,4,0"));
        assert!(s.contains("P,8,10,12,1162,0,-1,-1,0,,,,,,,,18"));
        assert!(s.contains("L,8,9,20,0,1,-1,-1,0"));
        assert!(s.contains("A,8,9,30,0,0,-1,-1,0"));
        assert!(s.contains("C,8,9,10,0,0,-1,-1,0,1000,25,200000000,222500000,P,,0"));
        assert!(s.contains("X,8,9,11,0,0,-1,-1,0,1000,25,200000000,222500000,P,early,10"));
        assert!(s.lines().all(|line| line.split(',').count() == 17));
        std::fs::remove_file(p).unwrap();
    }
}
