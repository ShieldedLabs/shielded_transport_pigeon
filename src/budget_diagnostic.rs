use std::cell::RefCell; use std::io::{self, Write}; pub const PACKET_LIMIT: usize = 65536;
pub const FEEDBACK_LIMIT: usize = 131072; pub const LAYOUT_LIMIT: usize = 8192; pub const CONNECTION_LIMIT: usize = 8;
pub const SCHEMA: &str = "stp-budget-diagnostic-evidence/1"; pub const BUDGET25_SCHEMA: &str = "stp-budget25-evidence/1";
pub const EMPIRICAL_SCHEMA: &str = "stp-empirical-calibration-evidence/1"; pub const DEMAND_LIMIT: usize = 4096;
pub const DEMAND_ITERATION_LIMIT: usize = 64; pub const ADAPTIVE_GENERATION_LIMIT:usize=64;
#[derive(Debug,Clone,Copy,Default)]
pub struct AdaptiveGeneration {pub generation:u64,pub conn:u32,pub created_ns:u64,pub first_observed_ns:u64}
#[derive(Debug,Clone,Copy,Default)]
pub struct DemandIteration { pub r:u64,pub e:u64,pub n:u64,pub samples:u64,pub empirical:u64,pub iid:u64,pub selected:u64,pub next_r:u32,pub scale:u16,pub flags:u16 }
#[derive(Debug,Clone,Copy,Default)] pub struct DemandHeader {
    pub index:u64,pub query_batch:u64,pub owner_generation:u64,pub query_now_ns:u64,pub ns:u64,pub generation:u64,pub package:u64,pub root:u64,pub adaptive_generation:u64,
    pub adaptive_created_ns:u64,pub anchor_generation:u64,pub anchor_a:u64,pub s:u64,pub f:u64,pub ug:u64,pub uc:u64,
    pub iid_p:f64,pub eps_e:f64,pub eps_i:f64,
    pub conn:u32,pub codec_index:u32,pub codec_count:u32,pub group_count:u32,pub k:u32,pub original_k:u32,
    pub cap_percent:u32,pub limit:u32,pub sources_committed:u32,pub repairs_committed:u32,
    pub old_planned:u32,pub reserved:u32,pub emitted:u32,pub d:u32,pub own_finalized:u32,pub assembled:u32,
    pub rs:u32,pub start:u32,pub result_r:u32,pub requested:u32,pub plan_after:u32,pub segment_offset:u32,
    pub flags:u32,pub reason:u8,pub iterations_count:u8, }
#[derive(Debug,Clone,Copy)] pub struct Demand { pub header:DemandHeader,pub iterations:[DemandIteration;DEMAND_ITERATION_LIMIT] }
impl Default for Demand { fn default()->Self { Self{header:DemandHeader::default(),iterations:[DemandIteration::default();DEMAND_ITERATION_LIMIT]} } }
impl Demand {
    fn write(&self,w:&mut impl Write)->io::Result<()> {
        let h=&self.header; write!(w,"{{")?;
        macro_rules! fields { ($($n:ident),*) => { $(write!(w,concat!("\"",stringify!($n),"\":{},"),h.$n)?;)* }; }
        fields!(index,query_batch,query_now_ns,conn,generation,package,root,adaptive_generation,adaptive_created_ns,ns,codec_index,codec_count,group_count,k,original_k,cap_percent,limit,old_planned,reserved,d,own_finalized,assembled,rs,s,f,ug,uc,start,result_r,requested,plan_after,segment_offset,reason,eps_e,eps_i,iid_p);
        let opt=|value:u64,valid:bool|if valid {value.to_string()}else{"null".into()};
        let anchor=h.flags&1!=0;let owner=h.owner_generation!=u64::MAX;let sources=h.flags&32==0;let repairs=h.flags&64==0;
        let validity=u32::from(anchor)|if owner{2}else{0}|if sources{4}else{0}|if repairs{8}else{0};
        write!(w,"\"owner_generation\":{},\"sources_committed\":{},\"repairs_committed\":{},\"emitted\":{},\"anchor_generation\":{},\"anchor_a\":{},\"span_seen\":{},\"eps_e_bits\":{},\"eps_i_bits\":{},\"invalid_anchor\":{},\"want_exceeded_k\":{},\"model_cap_bound\":{},\"terminated\":\"{}\",\"incomplete\":{},\"clipped\":{},\"iterations_count\":{},\"validity\":{},\"own_direct_positive\":null,\"allowed_micro_pps\":null,\"loss_timeout_ns\":null,\"h\":null,\"rtt_ns\":null,\"srtt_ns\":null,\"rttvar_ns\":null,\"iterations\":[",
            opt(h.owner_generation,owner),opt(h.sources_committed as u64,sources),opt(h.repairs_committed as u64,repairs),opt(h.emitted as u64,repairs),opt(h.anchor_generation,anchor),opt(h.anchor_a,anchor),h.f,h.eps_e.to_bits(),h.eps_i.to_bits(),h.flags&2!=0,h.flags&4!=0,h.flags&(4|8)!=0,if h.flags&8!=0 {"iteration_limit"}else{"converged"},h.flags&16!=0,h.requested>h.plan_after,h.iterations_count,validity)?;
        for(i,t)in self.iterations[..(h.iterations_count as usize).min(DEMAND_ITERATION_LIMIT)].iter().enumerate(){
            if i>0{write!(w,",")?;}
            let present=t.flags&1!=0;
            write!(w,"{{\"r\":{},\"e\":{},\"n\":{},\"scale\":{},\"samples\":{},\"empirical\":{},\"iid\":{},\"selected\":{},\"next_r\":{},\"flags\":{}}}",t.r,t.e,t.n,if present{(2u64<<t.scale).to_string()}else{"null".into()},if present{t.samples.to_string()}else{"null".into()},if present{t.empirical.to_string()}else{"null".into()},t.iid,t.selected,t.next_r,t.flags)?;
        }
        write!(w,"]}}") } }
#[derive(Debug, Clone, Copy)] pub struct Connection { pub handshake: [u8; 64], pub local_key: [u8;32], pub peer_key: [u8;32] }
#[derive(Debug, Clone, Copy)] pub struct Symbol { pub conn: usize, pub seq: u64, pub ordinal: u64, pub ns: u64,
    pub package: u64, pub root: u64, pub len: usize, pub width: usize, pub symbol: u32,
    pub group: usize, pub k: usize, pub source: bool, pub outcome: u8 }
#[derive(Debug, Clone, Copy)] pub struct Feedback { pub conn: usize, pub seq: u64, pub ns: u64, pub kind: u8 }
#[derive(Debug, Clone, Copy, Default)] pub struct Layout { pub conn: usize, pub generation: u64, pub package: u64, pub root: u64,
    pub len: usize, pub width: usize, pub k: usize, pub groups: usize, pub limit: Option<u32>,
    pub planned: u32, pub assembled: u32, pub phase: Option<u8>, pub app_id: Option<u32>, pub ns: u64, pub event: u8 }
#[derive(Debug)] pub struct Capture {
    pub demands: Vec<Demand>, pub demand_overflow: bool,
    pub adaptive_generations: [AdaptiveGeneration;ADAPTIVE_GENERATION_LIMIT], pub adaptive_generations_count:usize,
    pub connections: Vec<Connection>, pub tx: Vec<Symbol>, pub rx: Vec<Symbol>,
    pub feedback: Vec<Feedback>, pub layouts: Vec<Layout>, pub overflow: bool, pub unknown_identity: bool,
    pub start_ordinal: u64, pub end_ordinal: u64, pub drain_ns: u64 }
impl Capture {
    fn new(ordinal: u64) -> Self { Self {
        demands: Vec::new(), demand_overflow: false,
        adaptive_generations:[AdaptiveGeneration::default();ADAPTIVE_GENERATION_LIMIT], adaptive_generations_count:0,
        connections: Vec::with_capacity(CONNECTION_LIMIT),
        tx: Vec::with_capacity(PACKET_LIMIT), rx: Vec::with_capacity(PACKET_LIMIT),
        feedback: Vec::with_capacity(FEEDBACK_LIMIT), layouts: Vec::with_capacity(LAYOUT_LIMIT),
        overflow: false, unknown_identity: false, start_ordinal: ordinal, end_ordinal: ordinal, drain_ns: 0 } }
    pub fn write_new(&self, path: &std::path::Path, source_tree: &str, diff: &str, role: &str, phase: usize) -> io::Result<()> {
        self.write_capture(path, source_tree, diff, role, phase, None) }
    pub fn write_new_budget25(&self, path: &std::path::Path, source_tree: &str, diagnostic_diff: &str, budget25_diff: &str, role: &str, phase: usize, cap_percent: u32) -> io::Result<()> {
        if ![15, 25].contains(&cap_percent) || cap_percent != crate::fec_adapt::research_p4_repair_cap_percent() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "cap_percent must match initialized policy (15 or 25)")); }
        self.write_capture(path, source_tree, diagnostic_diff, role, phase, Some((budget25_diff, cap_percent))) }
    fn write_capture(&self, path: &std::path::Path, source_tree: &str, diff: &str, role: &str, phase: usize, budget25: Option<(&str, u32)>) -> io::Result<()> {
        self.write_capture_inner(path,source_tree,diff,role,phase,budget25,None) }
    pub fn write_new_empirical_calibration(&self,path:&std::path::Path,source_tree:&str,diagnostic_diff:&str,budget25_diff:&str,empirical_diff:&str,role:&str,phase:usize,cap_percent:u32,empirical_tail_calibration:u32)->io::Result<()> {
        if cap_percent!=25 || cap_percent!=crate::fec_adapt::research_p4_repair_cap_percent() || empirical_tail_calibration>1 || empirical_tail_calibration!=crate::fec_adapt::research_p4_empirical_tail_calibration() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,"empirical arm must match initialized cap25 policy")); }
        if self.demands.len()>DEMAND_LIMIT || self.demands.iter().any(|d|d.header.iterations_count as usize>DEMAND_ITERATION_LIMIT) || self.adaptive_generations_count>ADAPTIVE_GENERATION_LIMIT {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,"malformed demand capture dimensions")); }
        self.write_capture_inner(path,source_tree,diagnostic_diff,role,phase,Some((budget25_diff,cap_percent)),Some((empirical_diff,empirical_tail_calibration)))
    }
    fn write_capture_inner(&self,path:&std::path::Path,source_tree:&str,diff:&str,role:&str,phase:usize,budget25:Option<(&str,u32)>,empirical:Option<(&str,u32)>)->io::Result<()> {
        let f = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?; let mut w = io::BufWriter::new(f);
        let schema = if empirical.is_some() { "stp-empirical-calibration-evidence/1" } else if budget25.is_some() { BUDGET25_SCHEMA } else { SCHEMA };
        let extra = budget25.map_or(String::new(), |(diff, cap)| format!(",\"budget25_diff_sha256\":\"{diff}\",\"cap_percent\":{cap}"));
        let extra=extra+&empirical.map_or(String::new(),|(diff,q)|format!(",\"empirical_calibration_diff_sha256\":\"{diff}\",\"empirical_tail_calibration\":{q}"));
        writeln!(w, "{{\"schema\":\"{schema}\",\"source_tree_sha256\":\"{source_tree}\",\"diagnostic_diff_sha256\":\"{diff}\"{extra},\"role\":\"{role}\",\"phase_order_index\":{phase},\"overflow\":{},\"unknown_identity\":{},\"limits\":[{PACKET_LIMIT},{PACKET_LIMIT},{FEEDBACK_LIMIT},{LAYOUT_LIMIT},{CONNECTION_LIMIT}],\"ordinal_start\":{},\"ordinal_end\":{},\"drain_ns\":{},\"late_feedback_censored_after_drain\":true,\"native_worker_outcomes\":\"unknown\",\"connections\":[", self.overflow, self.unknown_identity, self.start_ordinal, self.end_ordinal, self.drain_ns)?;
        for (i, c) in self.connections.iter().enumerate() { if i != 0 { write!(w, ",")?; }
            let h: String = c.handshake.iter().map(|x| format!("{x:02x}")).collect();
            let local: String=c.local_key.iter().map(|x|format!("{x:02x}")).collect();
            let peer: String=c.peer_key.iter().map(|x|format!("{x:02x}")).collect();
            write!(w, "[\"{h}\",\"{local}\",\"{peer}\"]")?; }
        write!(w, "],\"tx\":[")?;
        fn symbols(w: &mut impl Write, records: &[Symbol]) -> io::Result<()> {
            for (i, s) in records.iter().enumerate() { if i != 0 { write!(w, ",")?; }
                write!(w, "[{},{},{},{},{},{},{},{},{},{},{},{},{}]", s.conn,s.seq,s.ordinal,s.ns,s.package,s.root,s.len,s.width,s.symbol,s.group,s.k,s.source,s.outcome)?; } Ok(()) }
        symbols(&mut w, &self.tx)?; write!(w, "],\"rx\":[")?; symbols(&mut w, &self.rx)?; write!(w, "],\"feedback\":[")?;
        for (i, f) in self.feedback.iter().enumerate() { if i != 0 { write!(w, ",")?; } write!(w,"[{},{},{},{}]",f.conn,f.seq,f.ns,f.kind)?; }
        write!(w, "],\"layouts\":[")?;
        for (i, l) in self.layouts.iter().enumerate() { if i != 0 { write!(w, ",")?; }
            let opt = |x: Option<u64>| x.map_or("null".into(), |x| x.to_string());
            write!(w,"[{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}]",l.conn,l.generation,l.package,l.root,l.len,l.width,l.k,l.groups,opt(l.limit.map(u64::from)),opt((l.event!=4).then_some(l.planned as u64)),opt((l.event!=4).then_some(l.assembled as u64)),opt(l.phase.map(u64::from)),opt(l.app_id.map(u64::from)),l.ns,l.event)?;
        }
        write!(w,"]")?;
        if empirical.is_some() {
            write!(w,",\"demand_limit\":{DEMAND_LIMIT},\"demand_iteration_limit\":{DEMAND_ITERATION_LIMIT},\"demand_overflow\":{},\"demand_record_bytes_bound\":{},\"demand_scope\":\"owning_network_thread_including_warmup\",\"demands\":[",self.demand_overflow,std::mem::size_of::<Demand>())?;
            for(i,d)in self.demands.iter().enumerate(){if i>0{write!(w,",")?;}d.write(&mut w)?;}
            write!(w,"],\"adaptive_generation_limit\":{ADAPTIVE_GENERATION_LIMIT},\"adaptive_generations\":[")?;
            for(i,g)in self.adaptive_generations[..self.adaptive_generations_count].iter().enumerate(){
                if i>0{write!(w,",")?;}
                write!(w,"{{\"generation\":{},\"conn\":{},\"created_ns\":{},\"first_observed_ns\":{}}}",g.generation,g.conn,g.created_ns,g.first_observed_ns)?;
            }
            write!(w,"]")?; }
        writeln!(w,"}}")?; w.flush() } }
struct State {
    demand_count: u64, latest_ns:u64,
    cap: Capture, context: usize, ordinal: u64, generation: u64, proof: u8, rx_current: Option<usize> }
thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
thread_local! {
    static DEMANDS_USED:std::cell::Cell<u64>=const {std::cell::Cell::new(0)};
    static DEMANDS_INVALID:std::cell::Cell<bool>=const {std::cell::Cell::new(false)}; }
pub fn enable(on: bool) { STATE.with(|s| {
    let mut b=s.borrow_mut();
    if let Some(old)=b.as_ref() {
        DEMANDS_USED.with(|n|n.set(old.demand_count+old.cap.demands.len()as u64));
        DEMANDS_INVALID.with(|v|v.set(v.get()||old.cap.demand_overflow)); }
    *b=on.then(|| State {
        demand_count:DEMANDS_USED.with(|n|n.get()), latest_ns:0,
        cap: {let c=Capture::new(0);
            let c={let mut c=c;
                let used=DEMANDS_USED.with(|n|n.get());c.demands=Vec::with_capacity(DEMAND_LIMIT.saturating_sub(used as usize));
                c.demand_overflow=DEMANDS_INVALID.with(|v|v.get())||used>0;c};c},
        context:usize::MAX,ordinal:0,generation:0,proof:3,rx_current:None }); }); }
pub fn active() -> bool { STATE.with(|s| s.borrow().is_some()) }
fn with(f: impl FnOnce(&mut State)) { STATE.with(|s| { if let Some(s) = &mut *s.borrow_mut() { f(s); } }); }
fn push<T>(v: &mut Vec<T>, x: T, limit: usize, overflow: &mut bool) -> Option<usize> {
    if v.len() == limit { *overflow = true; None } else { let i = v.len(); v.push(x); Some(i) } }
pub(crate) fn demand_checkpoint()->usize { STATE.with(|s|s.borrow().as_ref().map_or(0,|s|s.cap.demands.len())) }
pub(crate) fn demand_push(mut d:Demand) { with(|s| {
    d.header.conn=s.context as u32; d.header.ns=d.header.ns.max(s.latest_ns);
    if !s.cap.adaptive_generations[..s.cap.adaptive_generations_count].iter().any(|g|g.generation==d.header.adaptive_generation&&g.conn==d.header.conn) {
        if s.cap.adaptive_generations_count==ADAPTIVE_GENERATION_LIMIT {s.cap.demand_overflow=true;}
        else {s.cap.adaptive_generations[s.cap.adaptive_generations_count]=AdaptiveGeneration {generation:d.header.adaptive_generation,conn:d.header.conn,created_ns:d.header.adaptive_created_ns,first_observed_ns:d.header.ns};s.cap.adaptive_generations_count+=1;}
    }
    if s.demand_count.saturating_add(s.cap.demands.len() as u64)>=DEMAND_LIMIT as u64 {s.cap.demand_overflow=true;return;}
    if d.header.flags&16!=0 {s.cap.demand_overflow=true;}
    s.cap.demands.push(d); }); }
pub(crate) fn demand_finish(checkpoint:usize,reason:u8,requested:u32,plan_after:u32,owner_generation:u64,original_k:u32,limit:u32,reserved:u32,emitted:u64,sources_committed:u64,source_counter_overflow:bool) { with(|s| {
    if reason==0 {s.cap.demands.truncate(checkpoint);return;}
    for d in &mut s.cap.demands[checkpoint..] {
        let h=&mut d.header;h.query_batch=s.demand_count+checkpoint as u64;h.owner_generation=owner_generation;
        h.reason=reason;h.requested=requested;h.plan_after=plan_after;h.original_k=original_k;h.limit=limit;h.reserved=reserved;
        if owner_generation==u64::MAX {h.flags|=16;s.cap.demand_overflow=true;}
        match u32::try_from(emitted) {
            Ok(value)=>{h.emitted=value;h.repairs_committed=value;},
            Err(_)=>{h.flags|=16|64;s.cap.demand_overflow=true;} }
        match u32::try_from(sources_committed) {
            Ok(value) if !source_counter_overflow=>h.sources_committed=value,
            _=>{h.flags|=16|32;s.cap.demand_overflow=true;} } }
    for(i,d)in s.cap.demands.iter_mut().enumerate().skip(checkpoint) {d.header.index=s.demand_count+i as u64;} }); }
pub fn context(handshake: [u8;64], local: &[u8], peer: &[u8]) { with(|s| {
    let local_key=local.try_into().unwrap_or([0;32]);let peer_key=peer.try_into().unwrap_or([0;32]);
    let c = Connection { handshake, local_key, peer_key };
    s.context = if let Some(i) = s.cap.connections.iter().position(|x| x.handshake == handshake && x.local_key == local_key && x.peer_key == peer_key) { i }
    else { push(&mut s.cap.connections, c, CONNECTION_LIMIT, &mut s.cap.overflow).unwrap_or(usize::MAX) };
    if handshake == [0;64] || local_key == [0;32] || peer_key == [0;32] || local_key == peer_key || s.context == usize::MAX { s.cap.unknown_identity = true; }
}); }
pub fn commit_proof(kind: usize, proof: u8) { if kind == 1 { with(|s| s.proof = proof); } }
pub fn feedback(seq: u64, ns: u64, kind: u8) { with(|s| { {s.latest_ns=s.latest_ns.max(ns);} push(&mut s.cap.feedback, Feedback { conn:s.context,seq,ns,kind }, FEEDBACK_LIMIT,&mut s.cap.overflow); }); }
pub fn layout_start(mut l: Layout) -> Layout { with(|s| {
    s.generation = s.generation.checked_add(1).unwrap_or_else(|| { s.cap.overflow = true; u64::MAX });
    l.conn = s.context; l.generation = s.generation;
    {s.latest_ns=s.latest_ns.max(l.ns);}
    push(&mut s.cap.layouts,l,LAYOUT_LIMIT,&mut s.cap.overflow); }); l }
pub fn layout_event(mut l: Layout, planned: u32, assembled: u32, ns: u64, event: u8) { with(|s| {
    {s.latest_ns=s.latest_ns.max(ns);}
    l.conn=s.context; l.planned=planned; l.assembled=assembled; l.ns=ns; l.event=event;
    push(&mut s.cap.layouts,l,LAYOUT_LIMIT,&mut s.cap.overflow); }); }
fn symbol(frame: &crate::stp::WireFrame<'_>, conn: usize, seq: u64, ordinal:u64, ns:u64, outcome:u8) -> Option<Symbol> {
    let crate::stp::WireFrame::Fec { id,block_id,message_len,block_bytes,segment,.. } = frame else { return None; };
    let layout = crate::fec::MessageLayout::new(*message_len,*block_bytes);
    let (group,k,source) = layout.map_or((usize::MAX,0,false),|l| { let (g,local)=l.local_id(*block_id); (g,l.group(g).1,local < l.group(g).1 as u32) });
    Some(Symbol {conn,seq,ordinal,ns,package:*id,root:segment.map_or(*id,|s|s.root),len:*message_len,width:*block_bytes,symbol:*block_id,group,k,source,outcome})
}
pub fn tx(seq:u64,ns:u64,payload:&[u8]) { if !active() { return; } with(|s| {
    {s.latest_ns=s.latest_ns.max(ns);}
    let proof=std::mem::replace(&mut s.proof,3);
    s.ordinal=s.ordinal.checked_add(1).unwrap_or_else(||{s.cap.overflow=true;u64::MAX}); let mut rest=payload; let mut any=false;
    while let Some((frame,n))=crate::stp::read_frame(rest) { rest=&rest[n..];
        if let Some(r)=symbol(&frame,s.context,seq,s.ordinal,ns,proof) { any=true;push(&mut s.cap.tx,r,PACKET_LIMIT,&mut s.cap.overflow); } }
    if !any { push(&mut s.cap.tx,Symbol {conn:s.context,seq,ordinal:s.ordinal,ns,package:u64::MAX,root:u64::MAX,len:0,width:0,symbol:0,group:0,k:0,source:false,outcome:proof},PACKET_LIMIT,&mut s.cap.overflow); }
}); }
pub struct RxGuard { index: Option<usize> }
impl RxGuard {
    pub(crate) fn new(frame:&crate::stp::WireFrame<'_>,seq:u64,ns:u64) -> Self {
        let mut index=None;with(|s| { if let Some(r)=symbol(frame,s.context,seq,0,ns,0) {index=push(&mut s.cap.rx,r,PACKET_LIMIT,&mut s.cap.overflow);s.rx_current=index;} });Self{index}
    }
    pub fn outcome(&mut self, outcome:u8) { with(|s| { if let Some(i)=self.index { s.cap.rx[i].outcome=outcome; } }); } }
pub fn rx_status(outcome:u8) { with(|s| {if let Some(i)=s.rx_current {s.cap.rx[i].outcome=outcome;}}); }
pub fn replay(seq:u64,ns:u64,payload:&[u8]) { if !active(){return;} let mut rest=payload;
    while let Some((frame,n))=crate::stp::read_frame(rest) { rest=&rest[n..];let mut g=RxGuard::new(&frame,seq,ns);g.outcome(2); } }
pub fn take(ns:u64) -> Option<Capture> { STATE.with(|state| { let mut b=state.borrow_mut();let s=b.as_mut()?;
    let mut next=Capture::new(s.ordinal);next.connections.extend_from_slice(&s.cap.connections);
    {
        s.demand_count+=s.cap.demands.len() as u64; DEMANDS_USED.with(|n|n.set(s.demand_count));
        DEMANDS_INVALID.with(|v|v.set(v.get()||s.cap.demand_overflow)); s.cap.demands.shrink_to_fit();
        next.demands=Vec::with_capacity(DEMAND_LIMIT.saturating_sub(s.demand_count as usize));
        next.demand_overflow=s.cap.demand_overflow; next.adaptive_generations=s.cap.adaptive_generations;
        next.adaptive_generations_count=s.cap.adaptive_generations_count; }
    next.overflow=s.cap.overflow;next.unknown_identity=s.cap.unknown_identity;
    s.rx_current=None; s.cap.end_ordinal=s.ordinal;s.cap.drain_ns=ns;Some(std::mem::replace(&mut s.cap,next)) }) }
