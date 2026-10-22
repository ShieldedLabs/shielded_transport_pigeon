use shielded_transport_pigeon::fec::{DecodeStatus, MessageDecoder, encode_message};
use std::sync::Arc;
use std::time::{Duration, Instant};
fn main() {
    println!(
        "bytes,block_bytes,repetitions,encode_mean_us,encode_max_us,repair_max_us,decode_total_mean_us,decode_call_max_us,decoder_create_max_us"
    );
    for len in [1_000_000usize, 2_000_000, 2 << 20] {
        for block_bytes in [1136usize, 9173] {
            let message = Arc::new(
                (0..len)
                    .map(|i| (i.wrapping_mul(73) >> 3) as u8)
                    .collect::<Vec<_>>(),
            );
            let mut encode_sum = Duration::ZERO;
            let mut encode_max = Duration::ZERO;
            let mut repair_max = Duration::ZERO;
            let mut decode_sum = Duration::ZERO;
            let mut decode_max = Duration::ZERO;
            let mut create_max = Duration::ZERO;
            let repetitions = 20;
            for _ in 0..repetitions {
                let start = Instant::now();
                let mut encoder = encode_message(message.clone(), block_bytes).unwrap();
                let elapsed = start.elapsed();
                encode_sum += elapsed;
                encode_max = encode_max.max(elapsed);
                let start = Instant::now();
                let mut decoder = MessageDecoder::new(len, block_bytes).unwrap();
                create_max = create_max.max(start.elapsed());
                let mut block = vec![0; block_bytes];
                let k = len.div_ceil(block_bytes) as u32;
                let mut total = Duration::ZERO;
                let mut complete = false;
                for id in 0..k * 2 {
                    let start = Instant::now();
                    let n = encoder.block_into(id, &mut block).unwrap();
                    if id >= k {
                        repair_max = repair_max.max(start.elapsed());
                    }
                    if id < k && id % 20 == 0 {
                        continue;
                    }
                    let start = Instant::now();
                    let status = decoder.add(id, &block[..n]).unwrap();
                    let elapsed = start.elapsed();
                    total += elapsed;
                    decode_max = decode_max.max(elapsed);
                    if status == DecodeStatus::Done {
                        complete = true;
                        break;
                    }
                }
                assert!(complete);
                assert_eq!(decoder.recover().unwrap(), *message);
                decode_sum += total;
            }
            println!(
                "{len},{block_bytes},{repetitions},{},{},{},{},{},{}",
                encode_sum.as_micros() / repetitions,
                encode_max.as_micros(),
                repair_max.as_micros(),
                decode_sum.as_micros() / repetitions,
                decode_max.as_micros(),
                create_max.as_micros()
            );
        }
    }
}
