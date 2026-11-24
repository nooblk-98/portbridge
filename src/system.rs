//! Host CPU, memory, disk and load readings for the dashboard gauges.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sysinfo::{Disks, System};

/// CPU usage is a rate, so it is only refreshed this often.
const CPU_REFRESH: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SystemStats {
    pub cpu_percent: f32,
    pub cores: usize,
    pub memory_used: u64,
    pub memory_total: u64,
    pub disk_used: u64,
    pub disk_total: u64,
    pub disk_mount: String,
    pub load: [f64; 3],
    pub uptime_seconds: u64,
}

struct Inner {
    /// `None` when the platform cannot report system information.
    system: Option<System>,
    disks: Option<Disks>,
    refreshed: Instant,
    cpu: f32,
}

pub struct SystemMonitor {
    inner: Mutex<Inner>,
    data_dir: PathBuf,
}

/// Percentage of `part` in `whole`, clamped to 0..=100.
pub fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64 / whole as f64 * 100.0).clamp(0.0, 100.0)
    }
}

impl SystemMonitor {
    pub fn new(data_dir: PathBuf) -> Self {
        let mut system = System::new().ok();
        if let Some(system) = system.as_mut() {
            // The first reading only primes the counters.
            system.refresh_cpu_usage();
            system.refresh_memory();
        }
        Self {
            inner: Mutex::new(Inner {
                system,
                disks: Disks::new_with_refreshed_list().ok(),
                refreshed: Instant::now(),
                cpu: 0.0,
            }),
            data_dir,
        }
    }

    pub fn snapshot(&self) -> SystemStats {
        let mut guard = self.inner.lock().expect("system lock");
        let inner = &mut *guard;
        let mut stats = SystemStats::default();

        if let Some(system) = inner.system.as_mut() {
            if inner.refreshed.elapsed() >= CPU_REFRESH {
                system.refresh_cpu_usage();
                inner.cpu = system.global_cpu_usage();
                inner.refreshed = Instant::now();
            }
            system.refresh_memory();
            stats.cpu_percent = inner.cpu;
            stats.cores = system.cpus().len().max(1);
            stats.memory_used = system.used_memory();
            stats.memory_total = system.total_memory();
        }

        if let Some(disks) = inner.disks.as_mut() {
            disks.refresh(true);
            // Report the disk that holds PortBridge's data, falling back to the largest.
            let data_dir = self
                .data_dir
                .canonicalize()
                .unwrap_or_else(|_| self.data_dir.clone());
            let disk = disks
                .iter()
                .filter(|disk| data_dir.starts_with(disk.mount_point()))
                .max_by_key(|disk| disk.mount_point().as_os_str().len())
                .or_else(|| disks.iter().max_by_key(|disk| disk.total_space()));
            if let Some(disk) = disk {
                stats.disk_total = disk.total_space();
                stats.disk_used = disk.total_space().saturating_sub(disk.available_space());
                stats.disk_mount = disk.mount_point().to_string_lossy().into_owned();
            }
        }

        if let Ok(load) = System::load_average() {
            stats.load = [load.one, load.five, load.fifteen];
        }
        stats.uptime_seconds = System::uptime().unwrap_or(0);
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_is_clamped_and_safe_for_zero() {
        assert_eq!(percent(0, 0), 0.0);
        assert_eq!(percent(50, 200), 25.0);
        assert_eq!(percent(300, 200), 100.0);
    }

    #[test]
    fn snapshot_reports_plausible_values() {
        let monitor = SystemMonitor::new(std::env::temp_dir());
        std::thread::sleep(Duration::from_millis(1100));
        let stats = monitor.snapshot();
        assert!(stats.memory_total > 0);
        assert!(stats.memory_used <= stats.memory_total);
        assert!(stats.cores >= 1);
        assert!((0.0..=100.0).contains(&stats.cpu_percent));
        assert!(stats.disk_total >= stats.disk_used);
        assert!(
            stats.disk_total > 0,
            "no disk was found for the data directory"
        );
    }
}
