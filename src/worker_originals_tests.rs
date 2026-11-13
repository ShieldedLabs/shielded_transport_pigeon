//! Private worker-only correctness tests; no public algorithm selector.
use super::*;
use std::sync::Arc;

fn geometry(k: usize) -> (MessageLayout, Arc<Vec<u8>>) {
    let bb = crate::stp::FEC_MIN_BLOCK_BYTES;
    let layout = MessageLayout::new((k - 1) * bb + bb / 2 + 1, bb).unwrap();
    let bytes = Arc::new(
        (0..layout.len)
            .map(|i| (i.wrapping_mul(37) ^ (i / 251)) as u8)
            .collect(),
    );
    (layout, bytes)
}
fn original(layout: MessageLayout, bytes: &[u8], id: usize) -> &[u8] {
    let start = id * layout.block_bytes;
    &bytes[start..(start + layout.block_bytes).min(layout.len)]
}
fn output_ptr(d: &WorkerDecoder) -> *const u8 {
    match d {
        WorkerDecoder::Originals { output, .. } => output.as_ptr(),
        WorkerDecoder::Native(d) => d.output.as_ptr(),
        WorkerDecoder::Failed => panic!("failed decoder"),
    }
}
#[test]
fn worker_originals_orders_duplicates_and_bounds() {
    assert_eq!(WORKER_BITMAP_BYTES, 590);
    assert!(std::mem::size_of::<WorkerDecoder>() < 4096);
    for k in [257, 1024, crate::stp::FEC_MAX_SOURCE_BLOCKS] {
        let (layout, bytes) = geometry(k);
        for order in 0..4 {
            let mut ids: Vec<usize> = (0..k).collect();
            match order {
                1 => ids.reverse(),
                2 => ids.rotate_left(k / 2),
                3 => {
                    ids.swap(214, 215);
                    if k > 700 {
                        ids.swap(420, 421);
                        ids.swap(700, 701);
                    }
                }
                _ => {}
            }
            let mut d = WorkerDecoder::new(layout, ids[0] as u32).unwrap();
            assert!(matches!(d, WorkerDecoder::Originals { .. }));
            let ptr = output_ptr(&d);
            for (n, &id) in ids.iter().enumerate() {
                let block = original(layout, &bytes, id);
                assert_eq!(
                    d.add(id as u32, &block[..block.len() - 1]),
                    Err(DecodeError::BadBlock)
                );
                assert_eq!(
                    d.add(id as u32, block),
                    Ok(if n + 1 == k {
                        DecodeStatus::Done
                    } else {
                        DecodeStatus::NeedMore
                    })
                );
                if n + 1 < k {
                    assert_eq!(d.add(id as u32, block), Ok(DecodeStatus::NeedMore));
                    let mut bad = block.to_vec();
                    bad[0] ^= 1;
                    assert_eq!(d.add(id as u32, &bad), Err(DecodeError::BadBlock));
                    assert!(d.recover().is_none());
                }
                assert!(matches!(d, WorkerDecoder::Originals { .. }));
                assert_eq!(output_ptr(&d), ptr);
            }
            let result = d.recover().unwrap();
            assert_eq!(result.as_ptr(), ptr);
            assert_eq!(&result, bytes.as_ref());
        }
    }
    let (small, _) = geometry(256);
    assert!(matches!(
        WorkerDecoder::new(small, 0),
        Some(WorkerDecoder::Native(_))
    ));
    let (too_large, _) = geometry(crate::stp::FEC_MAX_SOURCE_BLOCKS + 1);
    assert!(matches!(
        WorkerDecoder::new(too_large, 0),
        Some(WorkerDecoder::Native(_))
    ));
}

#[test]
fn worker_originals_promotion_reuses_output() {
    for k in [257, 1024, crate::stp::FEC_MAX_SOURCE_BLOCKS] {
        let (layout, bytes) = geometry(k);
        let mut enc = encode(bytes.clone(), layout.block_bytes).unwrap();
        for trigger in [0, k / 2, k - 1] {
            let mut d =
                WorkerDecoder::new(layout, if trigger == 0 { k as u32 } else { 0 }).unwrap();
            let ptr = output_ptr(&d);
            let mut baseline = MessageDecoder::with_layout(layout).unwrap();
            // Omit original k-1 permanently. For trigger k-1 the final repair
            // replays every saved original; trigger zero is repair-first.
            let mut ids: Vec<u32> = (0..k as u32 - 1).collect();
            ids.insert(trigger, k as u32);
            ids.extend(k as u32 + 1..k as u32 + 33);
            let mut completed = false;
            for id in ids {
                let block = enc.block(id).unwrap();
                let got = d.add(id, &block);
                assert_eq!(got, baseline.add(id, &block));
                assert_eq!(output_ptr(&d), ptr);
                if id >= k as u32 {
                    assert!(matches!(d, WorkerDecoder::Native(_)));
                }
                if got == Ok(DecodeStatus::Done) {
                    let output = d.recover().unwrap();
                    assert_eq!(output.as_ptr(), ptr);
                    assert_eq!(&output, bytes.as_ref());
                    assert_eq!(baseline.recover().unwrap(), output);
                    completed = true;
                    break;
                }
            }
            assert!(completed, "k={k} trigger={trigger}");
        }
    }
}

#[test]
fn worker_originals_native_retained_after_bad_block() {
    let (layout, bytes) = geometry(257);
    let mut enc = encode(bytes.clone(), layout.block_bytes).unwrap();
    let mut d = WorkerDecoder::new(layout, 0).unwrap();
    assert_eq!(
        d.add(0, original(layout, &bytes, 0)),
        Ok(DecodeStatus::NeedMore)
    );
    let repair = enc.block(layout.k as u32).unwrap();
    assert_eq!(d.add(layout.k as u32, &repair), Ok(DecodeStatus::NeedMore));
    let ptr = output_ptr(&d);
    let mut conflict = repair.clone();
    conflict[0] ^= 1;
    assert_eq!(
        d.add(layout.k as u32, &conflict),
        Err(DecodeError::BadBlock)
    );
    assert!(matches!(d, WorkerDecoder::Native(_)));
    assert_eq!(output_ptr(&d), ptr);
    for id in 1..layout.k {
        let got = d.add(id as u32, original(layout, &bytes, id)).unwrap();
        if got == DecodeStatus::Done {
            break;
        }
    }
    assert_eq!(d.recover().unwrap(), *bytes);
}

// Deliberately ignored by ordinary correctness runs. Run alone, optimized and
// serial under the exclusive host timing lock; no sockets or encode work timed.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "offline CPU/trigger-latency measurement; requires exclusive host lock"]
fn worker_originals_cpu_timing() {
    use std::time::Instant;
    #[allow(unsafe_code)]
    fn cpu_us() -> u64 {
        let mut ru = std::mem::MaybeUninit::<crate::platform::linux::rusage>::uninit();
        assert_eq!(
            unsafe {
                crate::platform::linux::getrusage(
                    crate::platform::linux::RUSAGE_SELF,
                    ru.as_mut_ptr(),
                )
            },
            0
        );
        let ru = unsafe { ru.assume_init() };
        (ru.ru_utime.tv_sec as u64 + ru.ru_stime.tv_sec as u64) * 1_000_000
            + ru.ru_utime.tv_usec as u64
            + ru.ru_stime.tv_usec as u64
    }
    fn run(
        layout: MessageLayout,
        bytes: &[u8],
        corpus: &[(u32, Vec<u8>)],
        automatic: bool,
        trigger: Option<usize>,
    ) -> (u64, u128, u64, u128, usize) {
        let cpu_start = cpu_us();
        let start = Instant::now();
        let mut d = if automatic {
            WorkerDecoder::new(layout, corpus[0].0).unwrap()
        } else {
            WorkerDecoder::Native(MessageDecoder::with_layout(layout).unwrap())
        };
        let ptr = output_ptr(&d);
        let mut trigger_cpu = 0;
        let mut trigger_wall = 0;
        let mut consumed = 0;
        let mut completed = false;
        for (i, (id, block)) in corpus.iter().enumerate() {
            let result = if trigger == Some(i) {
                let c = cpu_us();
                let t = Instant::now();
                let result = d.add(*id, block);
                trigger_wall = t.elapsed().as_nanos();
                trigger_cpu = cpu_us() - c;
                result
            } else {
                d.add(*id, block)
            };
            consumed += 1;
            if result.unwrap() == DecodeStatus::Done {
                completed = true;
                break;
            }
        }
        assert!(completed, "finite repair corpus exhausted");
        let recovered = d.recover().unwrap();
        let wall = start.elapsed().as_nanos();
        let cpu = cpu_us() - cpu_start;
        assert_eq!(recovered.as_ptr(), ptr, "no second full output allocation");
        assert_eq!(recovered.as_slice(), bytes);
        std::hint::black_box(&recovered);
        (cpu, wall, trigger_cpu, trigger_wall, consumed)
    }
    println!(
        "WORKER_BENCH_SCHEMA version=1 repetitions=8 cpu=process_us wall=monotonic_ns encode_timed=0 ctor_add_recover_timed=1 cleanup_timed=0"
    );
    for k in [257, 1024, crate::stp::FEC_MAX_SOURCE_BLOCKS] {
        let (layout, bytes) = geometry(k);
        let mut encoder = encode(bytes.clone(), layout.block_bytes).unwrap();
        // All input bytes, including redundant repair capacity, exist before
        // timing. Both arms borrow this exact same corpus, stopping at Done.
        let blocks: Vec<Vec<u8>> = (0..k as u32 + 33)
            .map(|id| encoder.block(id).unwrap())
            .collect();
        for case in [
            "clean",
            "reorder",
            "repair_first",
            "repair_mid",
            "repair_late",
        ] {
            let mut ids: Vec<usize> = (0..k).collect();
            let trigger = match case {
                "clean" => None,
                "reorder" => {
                    ids.swap(214, 215);
                    if k > 700 {
                        ids.swap(420, 421);
                        ids.swap(700, 701);
                    }
                    None
                }
                _ => {
                    ids.pop(); // actual erased final original, never restored
                    let n = match case {
                        "repair_first" => 0,
                        "repair_mid" => k / 2,
                        _ => k - 1,
                    };
                    ids.insert(n, k);
                    ids.extend(k + 1..k + 33);
                    Some(n)
                }
            };
            let corpus: Vec<(u32, Vec<u8>)> = ids
                .into_iter()
                .map(|id| (id as u32, blocks[id].clone()))
                .collect();
            let native = run(layout, &bytes, &corpus, false, trigger);
            let auto = run(layout, &bytes, &corpus, true, trigger);
            assert_eq!(
                native.4, auto.4,
                "preflight consumed identical symbol sequence"
            );
            for rep in 0..8 {
                for automatic in if rep % 2 == 0 {
                    [false, true]
                } else {
                    [true, false]
                } {
                    let (cpu, wall, trigger_cpu, trigger_wall, consumed) =
                        run(layout, &bytes, &corpus, automatic, trigger);
                    assert_eq!(consumed, native.4);
                    println!(
                        "WORKER_BENCH k={k} bytes={} case={case} rep={rep} arm={} whole_cpu_us={cpu} whole_wall_ns={wall} trigger_present={} trigger_cpu_us={trigger_cpu} trigger_wall_ns={trigger_wall} consumed={consumed} replayed={} output_reused=1",
                        layout.len,
                        if automatic { "auto" } else { "native" },
                        usize::from(trigger.is_some()),
                        if automatic { trigger.unwrap_or(0) } else { 0 }
                    );
                }
            }
        }
    }
}
