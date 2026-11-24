//! Live statistics, traffic history and health checks behind the dashboard.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::config::Config;
use crate::metrics::{MetricsService, Range};
use crate::system::{percent, SystemMonitor};
use crate::wireguard::WireGuardService;

/// Peers shown in the top talkers list.
const TOP_TALKERS: usize = 8;

pub struct StatsService {
    config: Arc<Config>,
    wg: Arc<WireGuardService>,
    metrics: Arc<MetricsService>,
    system: SystemMonitor,
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

fn check(id: &str, label: &str, status: &str, detail: impl Into<String>) -> Value {
    json!({"id": id, "label": label, "status": status, "detail": detail.into()})
}

/// The worst status among the checks: `fail`, then `warn`, otherwise `ok`.
pub fn overall_status(checks: &[Value]) -> &'static str {
    let has = |wanted: &str| {
        checks
            .iter()
            .any(|item| item.get("status").and_then(Value::as_str) == Some(wanted))
    };
    if has("fail") {
        "fail"
    } else if has("warn") {
        "warn"
    } else {
        "ok"
    }
}

impl StatsService {
    pub fn new(
        config: Arc<Config>,
        wg: Arc<WireGuardService>,
        metrics: Arc<MetricsService>,
    ) -> Self {
        let system = SystemMonitor::new(config.data_dir.clone());
        Self {
            config,
            wg,
            metrics,
            system,
        }
    }

    /// Take one traffic sample. Called on a timer.
    pub fn sample(&self) {
        let counters: BTreeMap<String, (u64, u64)> = self
            .wg
            .peer_status_map()
            .into_iter()
            .map(|(key, status)| (key, (status.rx_bytes, status.tx_bytes)))
            .collect();
        // No reading means `wg` failed; keep the previous counters instead of
        // treating the next reading as a new baseline.
        if counters.is_empty() {
            return;
        }
        self.metrics.record(now_epoch(), &counters);
    }

    fn peer_names(&self) -> BTreeMap<String, String> {
        self.wg
            .load_clients()
            .unwrap_or_default()
            .into_iter()
            .map(|client| (client.public_key, client.name))
            .collect()
    }

    /// Current numbers for the dashboard cards and gauges.
    pub fn snapshot(&self) -> Value {
        let now = now_epoch();
        let clients = self.wg.load_clients().unwrap_or_default();
        let status = self.wg.peer_status_map();
        let items: Vec<Value> = clients
            .iter()
            .map(|client| {
                let state = status.get(&client.public_key);
                json!({
                    "name": client.name,
                    "public_key": client.public_key,
                    "online": state.is_some_and(|value| value.online),
                    "last_handshake": state.map(|value| value.handshake),
                })
            })
            .collect();
        let online = items
            .iter()
            .filter(|item| item.get("online").and_then(Value::as_bool) == Some(true))
            .count();

        // Upload is what peers send to the server and download is what the server
        // sends back, from the peers' point of view.
        let (upload, download, since, _) = self.metrics.lifetime();
        let day = self.metrics.history(Range::Day, now);
        let (day_upload, day_download) = day.totals();

        let system = self.system.snapshot();
        let (health_status, health_checks) = self.health(clients.len(), online, &status);

        json!({
            "generated_at": now,
            "version": crate::version(),
            "peers": {"total": items.len(), "online": online, "items": items},
            "traffic": {
                "upload_total": upload,
                "download_total": download,
                "since": since,
                "last_24h": {"upload": day_upload, "download": day_download},
            },
            "system": {
                "cpu_percent": system.cpu_percent,
                "cores": system.cores,
                "memory_used": system.memory_used,
                "memory_total": system.memory_total,
                "memory_percent": percent(system.memory_used, system.memory_total),
                "disk_used": system.disk_used,
                "disk_total": system.disk_total,
                "disk_percent": percent(system.disk_used, system.disk_total),
                "disk_mount": system.disk_mount,
                "load": system.load,
                "uptime_seconds": system.uptime_seconds,
            },
            "health": {"status": health_status, "checks": health_checks},
        })
    }

    /// Chart points and the busiest peers for one range.
    pub fn history(&self, range: Range) -> Value {
        let history = self.metrics.history(range, now_epoch());
        let names = self.peer_names();
        let mut talkers: Vec<(String, [u64; 2])> = history
            .peers
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .filter(|(_, value)| value[0] + value[1] > 0)
            .collect();
        talkers.sort_by(|a, b| (b.1[0] + b.1[1]).cmp(&(a.1[0] + a.1[1])));
        talkers.truncate(TOP_TALKERS);
        let top: Vec<Value> = talkers
            .into_iter()
            .map(|(key, value)| {
                json!({
                    "name": names.get(&key).cloned().unwrap_or_else(|| "Removed peer".to_string()),
                    "public_key": key,
                    "upload": value[0],
                    "download": value[1],
                    "total": value[0] + value[1],
                })
            })
            .collect();
        let (upload, download) = history.totals();
        json!({
            "range": history.range.label(),
            "step": history.step,
            "from": history.from,
            "to": history.to,
            "points": history
                .points
                .iter()
                .map(|point| json!({"t": point.t, "upload": point.rx, "download": point.tx}))
                .collect::<Vec<_>>(),
            "totals": {"upload": upload, "download": download},
            "top_talkers": top,
        })
    }

    fn run_ok(&self, command: &[&str]) -> Option<String> {
        self.wg
            .runner
            .run(&argv(command), false, None)
            .ok()
            .filter(|result| result.returncode == 0)
            .map(|result| result.stdout)
    }

    fn health(
        &self,
        total: usize,
        online: usize,
        status: &BTreeMap<String, crate::wireguard::PeerStatus>,
    ) -> (&'static str, Vec<Value>) {
        let interface = self.config.wg_interface.as_str();
        let mut checks = Vec::new();

        match self.run_ok(&["wg", "show", interface, "listen-port"]) {
            Some(output) => {
                checks.push(check(
                    "interface",
                    "WireGuard interface",
                    "ok",
                    format!("{interface} is up"),
                ));
                let port = output.trim().parse::<u16>().ok();
                if port == Some(self.config.wg_port) {
                    checks.push(check(
                        "port",
                        "WireGuard port",
                        "ok",
                        format!("Listening on UDP {}", self.config.wg_port),
                    ));
                } else {
                    checks.push(check(
                        "port",
                        "WireGuard port",
                        "warn",
                        format!(
                            "Expected UDP {} but the interface reports {}",
                            self.config.wg_port,
                            output.trim()
                        ),
                    ));
                }
            }
            None => {
                checks.push(check(
                    "interface",
                    "WireGuard interface",
                    "fail",
                    format!("{interface} is not up"),
                ));
                checks.push(check(
                    "port",
                    "WireGuard port",
                    "fail",
                    "Peers cannot connect until the interface is up",
                ));
            }
        }

        let never = status.values().filter(|value| value.handshake == 0).count();
        let mut detail = format!("{online} of {total} online");
        if never > 0 {
            detail.push_str(&format!(", {never} never connected"));
        }
        let peers_status = if total == 0 || online == 0 {
            "warn"
        } else {
            "ok"
        };
        checks.push(check("peers", "Peers", peers_status, detail));

        let chain = self.config.filter_chain.as_str();
        match self.run_ok(&["iptables", "-w", "-t", "filter", "-S", chain]) {
            Some(_) => checks.push(check(
                "firewall",
                "Firewall rules",
                "ok",
                "Forwarding chains are applied",
            )),
            None => checks.push(check(
                "firewall",
                "Firewall rules",
                "warn",
                "Forwarding chains were not found",
            )),
        }

        if let Ok(value) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
            if value.trim() == "1" {
                checks.push(check("forwarding", "IP forwarding", "ok", "Enabled"));
            } else {
                checks.push(check(
                    "forwarding",
                    "IP forwarding",
                    "fail",
                    "Disabled, so peers cannot reach each other or the internet",
                ));
            }
        }

        let egress = if self.config.allow_internet_egress {
            "Peers can reach the internet through this server"
        } else {
            "Blocked (ALLOW_INTERNET_EGRESS=0)"
        };
        checks.push(check("egress", "Internet access", "ok", egress));

        (overall_status(&checks), checks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_and_history_have_the_shape_the_dashboard_expects() {
        use crate::runner::FakeRunner;
        use crate::storage::{InMemoryStorage, Storage};

        let config = Arc::new(Config::for_test(std::env::temp_dir()));
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
        let runner = Arc::new(FakeRunner::new());
        let clients = json!([{
            "name": "home", "address": "10.8.0.2", "private_key": "private",
            "public_key": "KEY1", "created_at": 1
        }]);
        storage
            .write_text(&config.clients_file.to_string_lossy(), &clients.to_string())
            .unwrap();
        let wg = Arc::new(WireGuardService::new(
            config.clone(),
            storage.clone(),
            runner.clone(),
        ));
        let metrics = Arc::new(MetricsService::new(storage, "metrics.json".to_string()));
        let stats = StatsService::new(config, wg, metrics);

        let now = now_epoch();
        runner.set_stdout(
            "wg show wg0 transfer",
            "KEY1	100	200
",
        );
        runner.set_stdout(
            "wg show wg0 latest-handshakes",
            format!(
                "KEY1	{now}
"
            ),
        );
        runner.set_stdout(
            "wg show wg0 listen-port",
            "51820
",
        );
        stats.sample();
        // The peer uploaded 1000 bytes and downloaded 5000 since the first reading.
        runner.set_stdout(
            "wg show wg0 transfer",
            "KEY1	1100	5200
",
        );
        stats.sample();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot["peers"]["total"], 1);
        assert_eq!(snapshot["peers"]["online"], 1);
        assert_eq!(snapshot["peers"]["items"][0]["name"], "home");
        assert_eq!(snapshot["traffic"]["upload_total"], 1000);
        assert_eq!(snapshot["traffic"]["download_total"], 5000);
        assert_eq!(snapshot["traffic"]["last_24h"]["download"], 5000);
        assert!(snapshot["system"]["memory_total"].as_u64().unwrap() > 0);
        assert!(snapshot["system"]["load"].as_array().unwrap().len() == 3);
        let checks = snapshot["health"]["checks"].as_array().unwrap();
        let status_of = |id: &str| {
            checks
                .iter()
                .find(|item| item["id"] == id)
                .map(|item| item["status"].as_str().unwrap().to_string())
        };
        assert_eq!(status_of("interface").as_deref(), Some("ok"));
        assert_eq!(status_of("port").as_deref(), Some("ok"));
        assert_eq!(status_of("peers").as_deref(), Some("ok"));

        let history = stats.history(Range::Hour);
        assert_eq!(history["range"], "1h");
        assert_eq!(history["points"].as_array().unwrap().len(), 60);
        assert_eq!(history["totals"]["upload"], 1000);
        assert_eq!(history["top_talkers"][0]["name"], "home");
        assert_eq!(history["top_talkers"][0]["total"], 6000);
    }

    #[test]
    fn a_down_interface_fails_the_health_check() {
        use crate::runner::FakeRunner;
        use crate::storage::{InMemoryStorage, Storage};

        let config = Arc::new(Config::for_test(std::env::temp_dir()));
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
        let runner = Arc::new(FakeRunner::new());
        runner.fail_next("wg show wg0 listen-port", 1);
        let wg = Arc::new(WireGuardService::new(
            config.clone(),
            storage.clone(),
            runner,
        ));
        let metrics = Arc::new(MetricsService::new(storage, "metrics.json".to_string()));
        let stats = StatsService::new(config, wg, metrics);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot["health"]["status"], "fail");
    }

    #[test]
    fn overall_status_is_the_worst_check() {
        let ok = check("a", "A", "ok", "fine");
        let warn = check("b", "B", "warn", "meh");
        let fail = check("c", "C", "fail", "bad");
        assert_eq!(overall_status(std::slice::from_ref(&ok)), "ok");
        assert_eq!(overall_status(&[ok.clone(), warn.clone()]), "warn");
        assert_eq!(overall_status(&[warn, fail, ok]), "fail");
        assert_eq!(overall_status(&[]), "ok");
    }
}
