//! Pure response-scheduling logic for the userspace sniffer: `--count` /
//! `--delay` copy offsets, `--rto-profile` retransmit tables (incl. the
//! per-target `internet` mix), `--loss-perc` and `--jitter-ms`, plus the
//! CLI conflict validation for these flags. Everything here is
//! side-effect free (randomness is a pure function of `--seed`, the probe
//! identity and the copy index, see [`probe_hash`]) so
//! it can be unit-tested without eBPF or sockets.

use std::str::FromStr;

/// Default for `--max-pending`.
pub const DEFAULT_MAX_PENDING: usize = 2_000_000;

/// Linux SYN-ACK retransmits (cumulative offsets after the first answer):
/// 1 s initial RTO, doubling, `tcp_synack_retries = 5`.
pub const LINUX_OFFSETS_MS: &[u64] = &[1_000, 3_000, 7_000, 15_000, 31_000];
/// Linux truncated after the 15 s retransmit (5 packets in total).
pub const LINUX_TRUNC_OFFSETS_MS: &[u64] = &[1_000, 3_000, 7_000, 15_000];
/// BSD-style: 3 s initial RTO, doubling, 3 retransmits.
pub const BSD_OFFSETS_MS: &[u64] = &[3_000, 9_000, 21_000];
/// Windows-style: 3 s initial RTO, doubling, 2 retransmits.
pub const WINDOWS_OFFSETS_MS: &[u64] = &[3_000, 9_000];
/// Single answer, no retransmits.
pub const NO_OFFSETS_MS: &[u64] = &[];

/// `--rto-profile` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtoProfile {
    Linux,
    Bsd,
    Windows,
    /// Per-target deterministic mix, see [`internet_offsets`].
    Internet,
}

impl FromStr for RtoProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "linux" => Ok(Self::Linux),
            "bsd" => Ok(Self::Bsd),
            "windows" => Ok(Self::Windows),
            "internet" => Ok(Self::Internet),
            other => Err(format!(
                "invalid rto-profile '{other}' (expected linux|bsd|windows|internet)"
            )),
        }
    }
}

/// clap value parser for `--rto-profile`.
pub fn parse_rto_profile(s: &str) -> Result<RtoProfile, String> {
    s.parse()
}

/// clap value parser for `--loss-perc`: a finite float in `0..=100`.
pub fn parse_loss_perc(s: &str) -> Result<f64, String> {
    let v: f64 = s
        .trim()
        .parse()
        .map_err(|e| format!("invalid loss percentage '{s}': {e}"))?;
    if !v.is_finite() || !(0.0..=100.0).contains(&v) {
        return Err(format!("loss percentage {v} not in 0..=100"));
    }
    Ok(v)
}

/// SplitMix64 finalizer (Steele/Lea/Flood). Used both as the PRNG step and
/// as the per-target hash for the `internet` mix.
pub fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Stable per-target key: IPv4 → the address as a big-endian u32;
/// IPv6 → the big-endian u128 folded as `hi64 ^ lo64`. `dst_ip` uses the
/// scanner convention (v4 in the first 4 bytes).
pub fn ip_key(version: u8, dst_ip: &[u8; 16]) -> u64 {
    if version == 4 {
        u32::from_be_bytes([dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]]) as u64
    } else {
        let v = u128::from_be_bytes(*dst_ip);
        ((v >> 64) as u64) ^ (v as u64)
    }
}

/// Bucket 0..100 of a target for the `internet` mix:
/// `splitmix64(ip_key) % 100`. Independent of `--seed`.
pub fn internet_bucket(key: u64) -> u64 {
    splitmix64(key) % 100
}

/// `internet` mix: per target deterministic choice of retransmit table.
/// Buckets: `0..31` linux (6 packets, 31 %), `31..73` bsd (4, 42 %),
/// `73..80` windows (3, 7 %), `80..84` linux truncated at 15 s (5, 4 %),
/// `84..100` single answer (16 %).
pub fn internet_offsets(key: u64) -> &'static [u64] {
    match internet_bucket(key) {
        0..=30 => LINUX_OFFSETS_MS,
        31..=72 => BSD_OFFSETS_MS,
        73..=79 => WINDOWS_OFFSETS_MS,
        80..=83 => LINUX_TRUNC_OFFSETS_MS,
        _ => NO_OFFSETS_MS,
    }
}

/// Retransmit offsets (ms after the first answer) for a target.
pub fn retransmit_offsets(profile: RtoProfile, key: u64) -> &'static [u64] {
    match profile {
        RtoProfile::Linux => LINUX_OFFSETS_MS,
        RtoProfile::Bsd => BSD_OFFSETS_MS,
        RtoProfile::Windows => WINDOWS_OFFSETS_MS,
        RtoProfile::Internet => internet_offsets(key),
    }
}

/// Per-probe randomness root for loss and jitter (`--seed`).
///
/// Every random decision is a pure function of the seed, the probe identity
/// and the copy index (see [`copy_rand`]), so the schedule of a probe does
/// not depend on the order in which probes are read from the ring or on how
/// many other probes were processed before it. The inputs are chained
/// through [`splitmix64`] instead of being XOR-ed directly, which would
/// make e.g. `port + 1` collide with `copy_index + 1`.
pub fn probe_hash(seed: u64, ip_key: u64, ports: u64, seq: u64) -> u64 {
    splitmix64(splitmix64(splitmix64(seed ^ ip_key) ^ ports) ^ seq)
}

/// Salt of the loss draw of a copy (see [`copy_rand`]).
pub const SALT_LOSS: u64 = 0;
/// Salt of the jitter draw of a copy (see [`copy_rand`]).
pub const SALT_JITTER: u64 = 1;

/// Random value for one decision (`salt`) of copy `copy_index` of a probe.
pub fn copy_rand(probe_hash: u64, copy_index: u64, salt: u64) -> u64 {
    splitmix64(probe_hash ^ splitmix64((copy_index << 1) | (salt & 1)))
}

/// True with probability `perc` percent, decided by the random value `r`.
/// `perc <= 0` never fires and `perc >= 100` always fires.
pub fn chance(perc: f64, r: u64) -> bool {
    if perc <= 0.0 {
        false
    } else if perc >= 100.0 {
        true
    } else {
        ((r >> 11) as f64 / (1u64 << 53) as f64) * 100.0 < perc
    }
}

/// Uniform jitter in `[0, max_ms]` (inclusive) from the random value `r`.
pub fn jitter(max_ms: u64, r: u64) -> u64 {
    if max_ms == 0 { 0 } else { r % (max_ms + 1) }
}

/// Seed when `--seed` is not given: time- and pid-derived.
pub fn random_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    splitmix64(nanos ^ ((std::process::id() as u64) << 32))
}

/// Response-scheduling parameters of the sniffer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScheduleConfig {
    pub count: u32,
    pub delay_ms: u64,
    pub rto: Option<RtoProfile>,
    pub loss_perc: f64,
    pub jitter_ms: u64,
}

/// Plans the send offsets (ms after the probe was drained from the ring)
/// of all copies of one probe into `out` (cleared first) and returns the
/// number of copies dropped by `--loss-perc`.
///
/// * `--rto-profile` (TCP only): first answer at offset 0 (never lost,
///   never jittered), then one copy per retransmit offset; retransmit `i`
///   (1-based copy index) is lost with `loss_perc` and otherwise delayed by
///   `[0, jitter_ms]`. UDP/ICMP probes (`tcp == false`) get a single
///   immediate answer under `--rto-profile`.
/// * `--count/--delay` with `delay > 0` (any protocol): copy `i` (0-based)
///   at `(i+1)*delay`; every copy (including the first) is subject to loss
///   and jitter.
/// * `delay == 0`: `count` copies at offset 0; no loss, no jitter.
///
/// Randomness comes from [`copy_rand`]`(probe_hash, copy_index, ..)`.
pub fn plan_copies(
    cfg: &ScheduleConfig,
    tcp: bool,
    target_key: u64,
    probe_hash: u64,
    out: &mut Vec<u64>,
) -> u64 {
    out.clear();
    let mut lost = 0;
    if let Some(profile) = cfg.rto {
        out.push(0);
        if !tcp {
            return 0;
        }
        for (i, &off) in retransmit_offsets(profile, target_key).iter().enumerate() {
            let idx = i as u64 + 1;
            if chance(cfg.loss_perc, copy_rand(probe_hash, idx, SALT_LOSS)) {
                lost += 1;
                continue;
            }
            out.push(off + jitter(cfg.jitter_ms, copy_rand(probe_hash, idx, SALT_JITTER)));
        }
        return lost;
    }
    for i in 0..cfg.count as u64 {
        if cfg.delay_ms == 0 {
            out.push(0);
            continue;
        }
        if chance(cfg.loss_perc, copy_rand(probe_hash, i, SALT_LOSS)) {
            lost += 1;
            continue;
        }
        out.push(
            (i + 1) * cfg.delay_ms + jitter(cfg.jitter_ms, copy_rand(probe_hash, i, SALT_JITTER)),
        );
    }
    lost
}

/// Flag combination to validate (values already range-checked by clap).
#[derive(Debug, Clone, Copy, Default)]
pub struct FlagCheck<'a> {
    pub mode: &'a str,
    pub valm: bool,
    pub closed: bool,
    pub raw_filter: bool,
    pub count: u32,
    pub delay_ms: u64,
    pub rto: bool,
}

/// Cross-flag validation for the scheduling/filter flags. Returns the
/// first conflict as an error message.
pub fn validate_flags(f: &FlagCheck<'_>) -> Result<(), String> {
    if f.raw_filter {
        if !f.valm {
            return Err("--raw-filter requires --valm".into());
        }
        if f.closed {
            return Err("--raw-filter cannot be combined with --closed".into());
        }
        if f.mode == "both" {
            return Err("--raw-filter cannot be combined with --mode both".into());
        }
    }
    if f.rto {
        if f.count > 1 {
            return Err("--rto-profile cannot be combined with --count > 1".into());
        }
        if f.delay_ms > 0 {
            return Err("--rto-profile cannot be combined with --delay > 0".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(count: u32, delay_ms: u64, rto: Option<RtoProfile>) -> ScheduleConfig {
        ScheduleConfig {
            count,
            delay_ms,
            rto,
            loss_perc: 0.0,
            jitter_ms: 0,
        }
    }

    fn plan(c: &ScheduleConfig, tcp: bool, key: u64, hash: u64) -> (Vec<u64>, u64) {
        let mut out = Vec::new();
        let lost = plan_copies(c, tcp, key, hash, &mut out);
        (out, lost)
    }

    fn offsets(c: &ScheduleConfig, key: u64) -> Vec<u64> {
        plan(c, true, key, 1).0
    }

    #[test]
    fn offset_tables() {
        assert_eq!(LINUX_OFFSETS_MS, &[1000, 3000, 7000, 15000, 31000]);
        assert_eq!(LINUX_TRUNC_OFFSETS_MS, &[1000, 3000, 7000, 15000]);
        assert_eq!(BSD_OFFSETS_MS, &[3000, 9000, 21000]);
        assert_eq!(WINDOWS_OFFSETS_MS, &[3000, 9000]);
        assert_eq!(
            offsets(&cfg(1, 0, Some(RtoProfile::Linux)), 0),
            vec![0, 1000, 3000, 7000, 15000, 31000]
        );
        assert_eq!(
            offsets(&cfg(1, 0, Some(RtoProfile::Bsd)), 0),
            vec![0, 3000, 9000, 21000]
        );
        assert_eq!(
            offsets(&cfg(1, 0, Some(RtoProfile::Windows)), 0),
            vec![0, 3000, 9000]
        );
    }

    #[test]
    fn rto_profile_only_applies_to_tcp() {
        let mut c = cfg(1, 0, Some(RtoProfile::Linux));
        c.loss_perc = 50.0;
        c.jitter_ms = 500;
        for hash in 0..100 {
            assert_eq!(plan(&c, false, 0, hash), (vec![0], 0));
        }
        assert_eq!(plan(&c, true, 0, 7).0[0], 0);
        // --count/--delay keeps working for any protocol
        assert_eq!(
            plan(&cfg(3, 500, None), false, 0, 1).0,
            vec![500, 1000, 1500]
        );
        assert_eq!(plan(&cfg(2, 0, None), false, 0, 1).0, vec![0, 0]);
    }

    #[test]
    fn count_delay_semantics() {
        // copy i at (i+1)*delay, first copy delayed too
        assert_eq!(offsets(&cfg(3, 500, None), 0), vec![500, 1000, 1500]);
        assert_eq!(offsets(&cfg(1, 0, None), 0), vec![0]);
        assert_eq!(offsets(&cfg(4, 0, None), 0), vec![0, 0, 0, 0]);
    }

    #[test]
    fn internet_mix_shares() {
        let n = 100_000u64;
        let mut counts = [0u64; 5];
        for i in 0..n {
            // 10.0.0.0/12-like addresses
            let ip = 0x0A00_0000u64 + i;
            let o = internet_offsets(ip);
            let idx = match o.len() {
                5 => 0,
                3 => 1,
                2 => 2,
                4 => 3,
                0 => 4,
                _ => unreachable!(),
            };
            counts[idx] += 1;
        }
        let expect = [31.0, 42.0, 7.0, 4.0, 16.0];
        for (c, e) in counts.iter().zip(expect) {
            let share = *c as f64 * 100.0 / n as f64;
            assert!((share - e).abs() < 0.6, "share {share} vs {e}");
        }
        // total packets per probe: 1 + retransmits
        let pkts: Vec<usize> = [
            LINUX_OFFSETS_MS,
            BSD_OFFSETS_MS,
            WINDOWS_OFFSETS_MS,
            LINUX_TRUNC_OFFSETS_MS,
            NO_OFFSETS_MS,
        ]
        .iter()
        .map(|o| o.len() + 1)
        .collect();
        assert_eq!(pkts, vec![6, 4, 3, 5, 1]);
    }

    #[test]
    fn internet_deterministic_per_ip_and_seed_independent() {
        let c = cfg(1, 0, Some(RtoProfile::Internet));
        for i in 0..1000u64 {
            let key = ip_key(4, &{
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(&(0x0A00_0000u32 + i as u32).to_be_bytes());
                b
            });
            assert_eq!(key, 0x0A00_0000 + i);
            let a = plan(&c, true, key, probe_hash(1, key, 80, 5));
            let b = plan(&c, true, key, probe_hash(999, key, 80, 5));
            assert_eq!(a, b);
            assert_eq!(a.0.len(), internet_offsets(key).len() + 1);
        }
    }

    #[test]
    fn ip_key_v6() {
        let mut b = [0u8; 16];
        b[7] = 1; // hi = 1
        b[15] = 2; // lo = 2
        assert_eq!(ip_key(6, &b), 3);
    }

    #[test]
    fn loss_never_hits_rto_first_answer() {
        let mut c = cfg(1, 0, Some(RtoProfile::Linux));
        c.loss_perc = 100.0;
        assert_eq!(plan(&c, true, 0, 3), (vec![0], 5));
    }

    #[test]
    fn loss_rate_and_bounds() {
        let mut c = cfg(1, 0, Some(RtoProfile::Linux));
        c.loss_perc = 3.3;
        let mut lost = 0;
        let n = 100_000u64;
        for i in 0..n {
            lost += plan(&c, true, 0, probe_hash(42, 0x0A00_0000 + i, 80, i)).1;
        }
        let rate = lost as f64 * 100.0 / (n * 5) as f64;
        assert!((rate - 3.3).abs() < 0.2, "loss rate {rate}");

        assert!((0..1000).all(|r| !chance(0.0, splitmix64(r))));
        assert!((0..1000).all(|r| chance(100.0, splitmix64(r))));
    }

    #[test]
    fn delayed_copies_subject_to_loss_but_zero_delay_not() {
        let mut c = cfg(3, 0, None);
        c.loss_perc = 100.0;
        c.jitter_ms = 1000;
        assert_eq!(plan(&c, true, 0, 1), (vec![0, 0, 0], 0));
        c.delay_ms = 100;
        assert_eq!(plan(&c, true, 0, 1), (vec![], 3));
    }

    #[test]
    fn jitter_bounds() {
        let mut c = cfg(1, 0, Some(RtoProfile::Bsd));
        c.jitter_ms = 250;
        let mut seen_max = 0;
        for i in 0..10_000u64 {
            let (out, _) = plan(&c, true, 0, probe_hash(9, 0, 0, i));
            assert_eq!(out[0], 0, "first answer never jittered");
            for (p, base) in out[1..].iter().zip(BSD_OFFSETS_MS) {
                assert!(*p >= *base && *p <= base + 250);
                seen_max = seen_max.max(p - base);
            }
        }
        assert!(seen_max >= 245);
        assert_eq!(jitter(0, 12345), 0);
        let mut c = cfg(2, 1000, None);
        c.jitter_ms = 60_000;
        for i in 0..1000u64 {
            let (out, _) = plan(&c, true, 0, probe_hash(9, 0, 0, i));
            assert!(out[0] >= 1000 && out[0] <= 61_000);
            assert!(out[1] >= 2000 && out[1] <= 62_000);
        }
    }

    /// Lossy + jittered config used by the determinism tests.
    fn noisy() -> ScheduleConfig {
        ScheduleConfig {
            count: 1,
            delay_ms: 0,
            rto: Some(RtoProfile::Linux),
            loss_perc: 30.0,
            jitter_ms: 900,
        }
    }

    #[test]
    fn plan_is_pure_function_of_seed_and_probe() {
        let c = noisy();
        let probes: Vec<(u64, u64, u64)> = (0..2000u64)
            .map(|i| (0x0A00_0000 + i * 2, 0x0006_A000_0050 + (i % 7), i * 7919))
            .collect();
        let run = |order: &mut dyn Iterator<Item = &(u64, u64, u64)>| {
            let mut m = std::collections::HashMap::new();
            for &(ip, ports, seq) in order {
                m.insert(
                    (ip, ports, seq),
                    plan(&c, true, ip, probe_hash(77, ip, ports, seq)),
                );
            }
            m
        };
        // ring read order (forward vs. reverse vs. interleaved) is irrelevant
        let fwd = run(&mut probes.iter());
        let rev = run(&mut probes.iter().rev());
        let inter = run(&mut probes
            .iter()
            .step_by(2)
            .chain(probes.iter().skip(1).step_by(2)));
        assert_eq!(fwd, rev);
        assert_eq!(fwd, inter);
        // the config actually produces losses and jitter (non-trivial test)
        assert!(fwd.values().any(|(_, lost)| *lost > 0));
        assert!(fwd.values().any(|(o, _)| o.len() > 1 && o[1] != 1000));
    }

    #[test]
    fn plan_depends_on_seed_and_identity() {
        let c = noisy();
        let base: Vec<_> = (0..200u64)
            .map(|i| plan(&c, true, i, probe_hash(1, i, 80, 5)))
            .collect();
        let other_seed: Vec<_> = (0..200u64)
            .map(|i| plan(&c, true, i, probe_hash(2, i, 80, 5)))
            .collect();
        let other_seq: Vec<_> = (0..200u64)
            .map(|i| plan(&c, true, i, probe_hash(1, i, 80, 6)))
            .collect();
        let other_port: Vec<_> = (0..200u64)
            .map(|i| plan(&c, true, i, probe_hash(1, i, 81, 5)))
            .collect();
        assert_ne!(base, other_seed);
        assert_ne!(base, other_seq);
        assert_ne!(base, other_port);
        assert_eq!(probe_hash(1, 2, 3, 4), probe_hash(1, 2, 3, 4));
        // argument positions matter (no plain XOR of the inputs)
        assert_ne!(probe_hash(1, 2, 3, 4), probe_hash(1, 2, 4, 3));
    }

    #[test]
    fn copy_draws_independent_per_index_and_salt() {
        let h = probe_hash(5, 6, 7, 8);
        let mut seen = std::collections::HashSet::new();
        for idx in 0..64 {
            assert!(seen.insert(copy_rand(h, idx, SALT_LOSS)));
            assert!(seen.insert(copy_rand(h, idx, SALT_JITTER)));
        }
        // XOR-collision guard: port+1 vs copy_index+1 must not alias
        assert_ne!(
            copy_rand(probe_hash(5, 6, 7, 8), 1, SALT_LOSS),
            copy_rand(probe_hash(5, 6, 6, 8), 0, SALT_LOSS)
        );
    }

    #[test]
    fn parsers() {
        assert_eq!(parse_rto_profile("linux"), Ok(RtoProfile::Linux));
        assert_eq!(parse_rto_profile("internet"), Ok(RtoProfile::Internet));
        assert!(parse_rto_profile("macos").is_err());
        assert_eq!(parse_loss_perc("3.3"), Ok(3.3));
        assert_eq!(parse_loss_perc("0"), Ok(0.0));
        assert_eq!(parse_loss_perc("100"), Ok(100.0));
        assert!(parse_loss_perc("100.1").is_err());
        assert!(parse_loss_perc("-1").is_err());
        assert!(parse_loss_perc("NaN").is_err());
        assert!(parse_loss_perc("inf").is_err());
    }

    #[test]
    fn flag_validation() {
        let ok = FlagCheck {
            mode: "raw",
            valm: true,
            count: 1,
            ..Default::default()
        };
        assert!(validate_flags(&ok).is_ok());
        assert!(
            validate_flags(&FlagCheck {
                raw_filter: true,
                ..ok
            })
            .is_ok()
        );
        assert!(
            validate_flags(&FlagCheck {
                raw_filter: true,
                valm: false,
                ..ok
            })
            .is_err()
        );
        assert!(
            validate_flags(&FlagCheck {
                raw_filter: true,
                closed: true,
                ..ok
            })
            .is_err()
        );
        assert!(
            validate_flags(&FlagCheck {
                raw_filter: true,
                mode: "both",
                ..ok
            })
            .is_err()
        );
        assert!(validate_flags(&FlagCheck { rto: true, ..ok }).is_ok());
        assert!(
            validate_flags(&FlagCheck {
                rto: true,
                count: 2,
                ..ok
            })
            .is_err()
        );
        assert!(
            validate_flags(&FlagCheck {
                rto: true,
                delay_ms: 1,
                ..ok
            })
            .is_err()
        );
        assert!(
            validate_flags(&FlagCheck {
                count: 5,
                delay_ms: 100,
                ..ok
            })
            .is_ok()
        );
    }
}
