//! Traffic history for the dashboard.
//!
//! WireGuard reports cumulative byte counters per peer that restart from zero
//! whenever the interface is recreated. This module turns them into per-interval
//! deltas, keeps lifetime totals, and stores two resolutions of history: one
//! sample per minute for 24 hours and ten-minute buckets for 7 days.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::storage::Storage;

/// Seconds between traffic samples.
pub const SAMPLE_SECONDS: i64 = 60;
const FINE_KEEP: i64 = 24 * 3600;
const COARSE_STEP: i64 = 600;
const COARSE_KEEP: i64 = 7 * 24 * 3600;
const PERSIST_EVERY: u32 = 5;

/// A time window the dashboard can chart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Range {
    Hour,
    Day,
    Week,
}

impl Range {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "1h" => Some(Self::Hour),
            "24h" => Some(Self::Day),
            "7d" => Some(Self::Week),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Hour => "1h",
            Self::Day => "24h",
            Self::Week => "7d",
        }
    }

    pub fn seconds(self) -> i64 {
        match self {
            Self::Hour => 3600,
            Self::Day => FINE_KEEP,
            Self::Week => COARSE_KEEP,
        }
    }

    /// Width of one chart point.
    pub fn step(self) -> i64 {
        match self {
            Self::Hour => 60,
            Self::Day => 300,
            Self::Week => 1800,
        }
    }
}

/// Bytes moved during one sampling interval. `rx` is received from peers (their
/// upload) and `tx` is sent to peers (their download).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    pub t: i64,
    pub rx: u64,
    pub tx: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peers: BTreeMap<String, [u64; 2]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub t: i64,
    pub rx: u64,
    pub tx: u64,
}

/// Aggregated history for one range.
#[derive(Clone, Debug)]
pub struct History {
    pub range: Range,
    pub step: i64,
    pub from: i64,
    pub to: i64,
    pub points: Vec<Point>,
    /// Per-peer `[rx, tx]` totals inside the window, keyed by public key.
    pub peers: BTreeMap<String, [u64; 2]>,
}

impl History {
    pub fn totals(&self) -> (u64, u64) {
        self.points
            .iter()
            .fold((0, 0), |(rx, tx), point| (rx + point.rx, tx + point.tx))
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct State {
    fine: VecDeque<Sample>,
    coarse: VecDeque<Sample>,
    /// Counters at the previous sample, to compute deltas.
    last: BTreeMap<String, [u64; 2]>,
    /// Lifetime totals per peer, kept after a peer is removed.
    totals: BTreeMap<String, [u64; 2]>,
    since: i64,
}

/// Bytes added since the previous reading. A first reading is only a baseline
/// and a smaller value means the counter restarted.
fn delta(previous: Option<u64>, current: u64) -> u64 {
    match previous {
        None => 0,
        Some(previous) if current >= previous => current - previous,
        Some(_) => current,
    }
}

fn add_peers(into: &mut BTreeMap<String, [u64; 2]>, from: &BTreeMap<String, [u64; 2]>) {
    for (key, value) in from {
        let entry = into.entry(key.clone()).or_insert([0, 0]);
        entry[0] += value[0];
        entry[1] += value[1];
    }
}

impl State {
    /// Record the current counters (`public key -> (rx, tx)`) taken at `now`.
    pub fn record(&mut self, now: i64, counters: &BTreeMap<String, (u64, u64)>) {
        if self.since == 0 {
            self.since = now;
        }
        let mut sample = Sample {
            t: now,
            ..Sample::default()
        };
        let mut next_last = BTreeMap::new();
        for (key, (rx, tx)) in counters {
            let previous = self.last.get(key);
            let drx = delta(previous.map(|value| value[0]), *rx);
            let dtx = delta(previous.map(|value| value[1]), *tx);
            next_last.insert(key.clone(), [*rx, *tx]);
            if drx == 0 && dtx == 0 {
                continue;
            }
            sample.rx += drx;
            sample.tx += dtx;
            sample.peers.insert(key.clone(), [drx, dtx]);
            let total = self.totals.entry(key.clone()).or_insert([0, 0]);
            total[0] += drx;
            total[1] += dtx;
        }
        self.last = next_last;

        let bucket = now.div_euclid(COARSE_STEP) * COARSE_STEP;
        match self.coarse.back_mut() {
            Some(back) if back.t == bucket => {
                back.rx += sample.rx;
                back.tx += sample.tx;
                add_peers(&mut back.peers, &sample.peers);
            }
            _ => self.coarse.push_back(Sample {
                t: bucket,
                rx: sample.rx,
                tx: sample.tx,
                peers: sample.peers.clone(),
            }),
        }
        self.fine.push_back(sample);

        while self.fine.front().is_some_and(|s| s.t < now - FINE_KEEP) {
            self.fine.pop_front();
        }
        while self.coarse.front().is_some_and(|s| s.t < now - COARSE_KEEP) {
            self.coarse.pop_front();
        }
    }

    /// Chart-ready points for `range`, with empty intervals filled with zeros.
    pub fn history(&self, range: Range, now: i64) -> History {
        let step = range.step();
        let count = range.seconds() / step;
        let to = now.div_euclid(step) * step;
        let from = to - (count - 1) * step;
        let mut points: Vec<Point> = (0..count)
            .map(|index| Point {
                t: from + index * step,
                rx: 0,
                tx: 0,
            })
            .collect();
        let mut peers = BTreeMap::new();
        let source = if range == Range::Week {
            &self.coarse
        } else {
            &self.fine
        };
        for sample in source {
            if sample.t < from || sample.t >= to + step {
                continue;
            }
            let index = ((sample.t - from) / step) as usize;
            if let Some(point) = points.get_mut(index) {
                point.rx += sample.rx;
                point.tx += sample.tx;
            }
            add_peers(&mut peers, &sample.peers);
        }
        History {
            range,
            step,
            from,
            to,
            points,
            peers,
        }
    }

    /// Lifetime totals as `(rx, tx)`, the first sample time, and the per-peer map.
    pub fn lifetime(&self) -> (u64, u64, i64, &BTreeMap<String, [u64; 2]>) {
        let (rx, tx) = self
            .totals
            .values()
            .fold((0, 0), |(rx, tx), value| (rx + value[0], tx + value[1]));
        (rx, tx, self.since, &self.totals)
    }
}

/// Shared, persisted traffic history.
pub struct MetricsService {
    state: Mutex<State>,
    storage: Arc<dyn Storage>,
    path: String,
    unsaved: Mutex<u32>,
}

impl MetricsService {
    pub fn new(storage: Arc<dyn Storage>, path: String) -> Self {
        let state = serde_json::from_value::<State>(storage.load_json(&path, Value::Null))
            .unwrap_or_default();
        Self {
            state: Mutex::new(state),
            storage,
            path,
            unsaved: Mutex::new(0),
        }
    }

    pub fn record(&self, now: i64, counters: &BTreeMap<String, (u64, u64)>) {
        self.state
            .lock()
            .expect("metrics lock")
            .record(now, counters);
        let mut unsaved = self.unsaved.lock().expect("metrics save lock");
        *unsaved += 1;
        if *unsaved >= PERSIST_EVERY {
            *unsaved = 0;
            drop(unsaved);
            self.persist();
        }
    }

    pub fn history(&self, range: Range, now: i64) -> History {
        self.state.lock().expect("metrics lock").history(range, now)
    }

    /// Lifetime `(rx, tx)`, first sample time and per-peer totals.
    pub fn lifetime(&self) -> (u64, u64, i64, BTreeMap<String, [u64; 2]>) {
        let state = self.state.lock().expect("metrics lock");
        let (rx, tx, since, totals) = state.lifetime();
        (rx, tx, since, totals.clone())
    }

    pub fn persist(&self) {
        let state = self.state.lock().expect("metrics lock");
        match serde_json::to_value(&*state) {
            Ok(value) => {
                if let Err(error) = self.storage.save_json(&self.path, &value) {
                    tracing::warn!("Could not save traffic history: {error}");
                }
            }
            Err(error) => tracing::warn!("Could not encode traffic history: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryStorage;

    fn counters(items: &[(&str, u64, u64)]) -> BTreeMap<String, (u64, u64)> {
        items
            .iter()
            .map(|(key, rx, tx)| (key.to_string(), (*rx, *tx)))
            .collect()
    }

    #[test]
    fn first_reading_is_only_a_baseline() {
        let mut state = State::default();
        state.record(1000, &counters(&[("a", 5000, 9000)]));
        let (rx, tx, since, _) = state.lifetime();
        assert_eq!((rx, tx, since), (0, 0, 1000));
    }

    #[test]
    fn deltas_accumulate_and_counter_resets_are_handled() {
        let mut state = State::default();
        state.record(1000, &counters(&[("a", 100, 200)]));
        state.record(1060, &counters(&[("a", 150, 260)]));
        assert_eq!(state.lifetime().0, 50);
        assert_eq!(state.lifetime().1, 60);
        // The interface restarted: the counter went back below the last value.
        state.record(1120, &counters(&[("a", 10, 20)]));
        assert_eq!(state.lifetime().0, 60);
        assert_eq!(state.lifetime().1, 80);
    }

    #[test]
    fn new_peers_start_from_a_baseline_and_removed_peers_keep_totals() {
        let mut state = State::default();
        state.record(1000, &counters(&[("a", 0, 0)]));
        state.record(1060, &counters(&[("a", 10, 10), ("b", 500, 500)]));
        state.record(1120, &counters(&[("b", 600, 700)]));
        let (_, _, _, totals) = state.lifetime();
        assert_eq!(totals.get("a"), Some(&[10, 10]));
        assert_eq!(totals.get("b"), Some(&[100, 200]));
    }

    #[test]
    fn history_buckets_samples_and_fills_gaps() {
        let mut state = State::default();
        let base = 1_000_020; // not aligned to a minute on purpose
        state.record(base, &counters(&[("a", 0, 0)]));
        state.record(base + 60, &counters(&[("a", 100, 40)]));
        state.record(base + 120, &counters(&[("a", 300, 90)]));
        let history = state.history(Range::Hour, base + 120);
        assert_eq!(history.points.len(), 60);
        assert_eq!(history.to - history.from, 59 * 60);
        let (rx, tx) = history.totals();
        assert_eq!((rx, tx), (300, 90));
        assert_eq!(history.peers.get("a"), Some(&[300, 90]));
        assert!(
            history
                .points
                .iter()
                .filter(|p| p.rx == 0 && p.tx == 0)
                .count()
                >= 57
        );
    }

    #[test]
    fn week_view_uses_ten_minute_buckets_and_old_samples_are_trimmed() {
        let mut state = State::default();
        let start = 2_000_000;
        state.record(start, &counters(&[("a", 0, 0)]));
        state.record(start + 60, &counters(&[("a", 10, 10)]));
        state.record(start + 120, &counters(&[("a", 30, 10)]));
        // Three samples in the same ten-minute bucket merge into one.
        assert_eq!(state.coarse.len(), 1);
        let week = state.history(Range::Week, start + 120);
        assert_eq!(week.points.len(), 336);
        assert_eq!(week.totals(), (30, 10));
        // A reading a day later drops the minute samples older than 24 hours.
        state.record(start + 25 * 3600, &counters(&[("a", 30, 10)]));
        assert!(state
            .fine
            .iter()
            .all(|s| s.t >= start + 25 * 3600 - FINE_KEEP));
        let day = state.history(Range::Day, start + 25 * 3600);
        assert_eq!(day.totals(), (0, 0));
        assert_eq!(
            state.history(Range::Week, start + 25 * 3600).totals(),
            (30, 10)
        );
    }

    #[test]
    fn ranges_parse_from_query_values() {
        assert_eq!(Range::parse("1h"), Some(Range::Hour));
        assert_eq!(Range::parse("24h"), Some(Range::Day));
        assert_eq!(Range::parse("7d"), Some(Range::Week));
        assert_eq!(Range::parse("1y"), None);
        assert_eq!(Range::Week.step() * 336, Range::Week.seconds());
    }

    #[test]
    fn history_survives_a_restart() {
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
        let service = MetricsService::new(storage.clone(), "metrics.json".to_string());
        service.record(5000, &counters(&[("a", 0, 0)]));
        service.record(5060, &counters(&[("a", 70, 30)]));
        service.persist();
        let reloaded = MetricsService::new(storage, "metrics.json".to_string());
        let (rx, tx, since, totals) = reloaded.lifetime();
        assert_eq!((rx, tx, since), (70, 30, 5000));
        assert_eq!(totals.get("a"), Some(&[70, 30]));
    }
}
