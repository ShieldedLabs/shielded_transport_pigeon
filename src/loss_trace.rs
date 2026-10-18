//! Optional bounded-memory sender trace. CSV is an event stream, not a final packet table:
//! S=sent, F=fragment association, L=declared lost, A=ACK (including late ACK).
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

pub(crate) type SlipstreamWriter = std::sync::Arc<std::sync::Mutex<BufWriter<std::fs::File>>>;
pub(crate) struct LossTrace(BufWriter<std::fs::File>, std::collections::HashMap<u16, CcContext>, SlipstreamWriter);
impl LossTrace {
    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        let mut w = BufWriter::with_capacity(256 * 1024, std::fs::File::create(path)?);
        writeln!(w, "event,connection,seq,time_ns,payload_bytes,lost,message_id,fragment,fec,cc_pps,slope_ppsps,rtt_ns,feedback_ns,cc_mode,cut_kind,cause_send_ns")?;
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(".slip.csv");
        let mut slip = BufWriter::with_capacity(32 * 1024, std::fs::File::create(sidecar)?);
        writeln!(slip, "time_ns,queue,event,head_root_id,head_tag,head_len,planned_tu_packets,rtt_ns,fair_pps,est_train_ms,decision,follower_kind,follower_root_id,follower_tag")?;
        Ok(Self(w, std::collections::HashMap::new(), std::sync::Arc::new(std::sync::Mutex::new(slip))))
    }
    pub fn slipstream_writer(&self) -> SlipstreamWriter { self.2.clone() }
    pub fn set_cc(&mut self, connection: u16, context: CcContext) {
        self.1.insert(connection, context);
    }
    pub fn cut(&mut self, connection: u16, seq: u64, time: u64, sent: u64, kind: &str, context: CcContext) {
        self.cc_row('X', connection, seq, time, sent, kind, context);
    }
    fn cc_row(&mut self, event: char, connection: u16, seq: u64, time: u64, sent: u64, kind: &str, c: CcContext) {
        writeln!(self.0, "{event},{connection},{seq},{time},0,0,-1,-1,0,{},{},{},{},{},{kind},{sent}",
            c.pps, c.slope_ppsps, c.rtt_ns, c.feedback_ns, c.mode).expect("write CC trace");
    }
    pub fn outcome(&mut self, event: char, connection: u16, seq: u64, time: u64) {
        writeln!(self.0, "{event},{connection},{seq},{time},0,{},-1,-1,0,,,,,,,", (event == 'L') as u8).expect("write loss trace");
    }
    pub fn sent(&mut self, connection: u16, seq: u64, time: u64, payload: &[u8]) {
        if let Some(context) = self.1.get(&connection).copied() {
            self.cc_row('C', connection, seq, time, 0, "", context);
        }
        writeln!(self.0, "S,{connection},{seq},{time},{},0,-1,-1,0,,,,,,,", payload.len()).expect("write loss trace");
        let mut cursor = 0;
        while let Some((frame, consumed)) = crate::stp::read_frame(&payload[cursor..]) {
            use crate::stp::WireFrame;
            match frame {
                WireFrame::Whole(data) => writeln!(self.0, "F,{connection},{seq},{time},{},0,-1,{cursor},0,,,,,,,", data.len()).expect("write loss trace"),
                WireFrame::Plain { id, offset, data, .. } => writeln!(self.0, "F,{connection},{seq},{time},{},0,{id},{offset},0,,,,,,,", data.len()).expect("write loss trace"),
                WireFrame::Fec { id, block_id, data, .. } => writeln!(self.0, "F,{connection},{seq},{time},{},0,{id},{block_id},1,,,,,,,", data.len()).expect("write loss trace"),
                WireFrame::Unknown => (),
            }
            cursor += consumed;
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
            let mut b = vec![3, 15, 0];
            b.extend_from_slice(&7u64.to_le_bytes());
            b.extend_from_slice(&4u32.to_le_bytes());
            b.extend_from_slice(&[1, 2, 3]);
            let c = CcContext { pps: 1000.0, slope_ppsps: 25.0, rtt_ns: 200_000_000, feedback_ns: 222_500_000, mode: 'P' };
            t.set_cc(8, c);
            t.sent(8, 9, 10, &b);
            t.cut(8, 9, 11, 10, "early", c);
            t.outcome('L', 8, 9, 20);
            t.outcome('A', 8, 9, 30);
        }
        let s = std::fs::read_to_string(&p).unwrap();
        assert!(s.contains("F,8,9,10,3,0,7,4,0"));
        assert!(s.contains("L,8,9,20,0,1,-1,-1,0"));
        assert!(s.contains("A,8,9,30,0,0,-1,-1,0"));
        assert!(s.contains("C,8,9,10,0,0,-1,-1,0,1000,25,200000000,222500000,P,,0"));
        assert!(s.contains("X,8,9,11,0,0,-1,-1,0,1000,25,200000000,222500000,P,early,10"));
        assert!(s.lines().all(|line| line.split(',').count() == 16));
        std::fs::remove_file(p).unwrap();
    }
}
