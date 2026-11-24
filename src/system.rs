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

/// Choose which disk to report for `data_dir` from `(mount point, total size)`.
///
/// The mount that holds the directory wins, but a service sandbox can expose
/// the same filesystem again at the data directory itself (a bind mount). When a
/// parent mount has the same size, that parent is the real filesystem and gives
/// a clearer label than the bind mount. With no match, the largest disk is used.
pub fn pick_disk(data_dir: &std::path::Path, disks: &[(&std::path::Path, u64)]) -> Option<usize> {
    let mut holding: Vec<usize> = (0..disks.len())
        .filter(|&index| data_dir.starts_with(disks[index].0))
        .collect();
    holding.sort_by_key(|&index| disks[index].0.as_os_str().len());
    if let Some(&deepest) = holding.last() {
        let total = disks[deepest].1;
        return holding
            .iter()
            .copied()
            .find(|&index| disks[index].1 == total)
            .or(Some(deepest));
    }
    (0..disks.len()).max_by_key(|&index| disks[index].1)
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
            let candidates: Vec<(&std::path::Path, u64)> = disks
                .iter()
                .map(|disk| (disk.mount_point(), disk.total_space()))
                .collect();
            let chosen = pick_disk(&data_dir, &candidates);
            let disk = chosen.map(|index| &disks[index]);
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
    fn disk_choice_prefers_the_real_filesystem_over_a_bind_mount() {
        use std::path::Path;
        let data = Path::new("/var/lib/portbridge");
        // A sandbox bind mount repeats the root filesystem at the data directory.
        let disks = [
            (Path::new("/"), 50),
            (Path::new("/boot"), 1),
            (Path::new("/var/lib/portbridge"), 50),
        ];
        assert_eq!(pick_disk(data, &disks), Some(0));
        // A dedicated data volume has its own size and is reported as itself.
        let volume = [
            (Path::new("/"), 50),
            (Path::new("/var/lib/portbridge"), 200),
        ];
        assert_eq!(pick_disk(data, &volume), Some(1));
        // Nothing contains the directory: fall back to the largest disk.
        let other = [(Path::new("/mnt/a"), 10), (Path::new("/mnt/b"), 30)];
        assert_eq!(pick_disk(data, &other), Some(1));
        assert_eq!(pick_disk(data, &[]), None);
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
