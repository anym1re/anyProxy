//! What the machine under the node is short of.
//!
//! Read from the cgroup the service runs in rather than from `/proc/meminfo`:
//! the unit hides everything in `/proc` but the processes, and the cgroup is
//! where the installer put the limits anyway. Where the kernel keeps its own
//! pressure figures they are used as they are: how much of the last ten
//! seconds tasks spent waiting for memory or for a processor is the question
//! being asked, and how much of either is in use is not.

use std::path::{Path, PathBuf};

/// Where the cgroup tree is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Memory in use against the limit at which it is worth easing off, and at
/// which the kernel is about to start throttling in earnest.
const MEMORY_STRAINED: f64 = 0.85;
const MEMORY_CRITICAL: f64 = 0.95;

/// Share of time spent waiting for memory. Ten percent is already felt by
/// every client; forty is a machine that is mostly waiting.
const MEMORY_STALL_STRAINED: f64 = 10.0;
const MEMORY_STALL_CRITICAL: f64 = 40.0;

/// Share of time spent waiting for a processor. Never critical on its own: a
/// busy processor slows clients down and kills none of them.
const CPU_STALL_STRAINED: f64 = 50.0;

/// Open files against the limit. Past the second figure the next client to
/// arrive is the one that is refused.
const FILES_STRAINED: f64 = 0.80;
const FILES_CRITICAL: f64 = 0.95;

/// What was found.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    /// Processors the node may run on.
    pub cpus: u32,
    /// Bytes the cgroup is using.
    pub memory_used: u64,
    /// Bytes it may use before being throttled, when there is such a limit.
    pub memory_limit: Option<u64>,
    /// Percent of the last ten seconds spent waiting for memory.
    pub memory_stall: f64,
    /// Percent of the last ten seconds spent waiting for a processor.
    pub cpu_stall: f64,
    /// Files the engine holds open, when there is an engine.
    pub open_files: Option<u64>,
    /// Files it may hold open.
    pub file_limit: Option<u64>,
}

/// How short the machine is, in one word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pressure {
    /// Nothing is waiting for anything.
    Calm,
    /// Something is short; the node eases off what it can.
    Strained,
    /// The next client is the one that fails.
    Critical,
}

impl Pressure {
    /// The word the panel receives.
    pub fn as_reported(self) -> &'static str {
        match self {
            Self::Calm => "calm",
            Self::Strained => "strained",
            Self::Critical => "critical",
        }
    }

    /// Whether the node should stop spending on anything optional.
    pub fn eases_off(self) -> bool {
        !matches!(self, Self::Calm)
    }
}

impl Reading {
    /// The one word this reading amounts to.
    pub fn pressure(&self) -> Pressure {
        classify(
            self.memory_used,
            self.memory_limit,
            self.memory_stall,
            self.cpu_stall,
            self.open_files,
            self.file_limit,
        )
    }

    /// What the panel is told.
    pub fn report(&self) -> ap_proto::MachineReport {
        ap_proto::MachineReport {
            cpus: self.cpus,
            memory_used_mb: self.memory_used / (1024 * 1024),
            memory_limit_mb: self.memory_limit.map(|bytes| bytes / (1024 * 1024)),
            memory_stall: self.memory_stall,
            cpu_stall: self.cpu_stall,
            open_files: self.open_files,
            file_limit: self.file_limit,
            pressure: self.pressure().as_reported().to_owned(),
        }
    }
}

/// Reads the machine as it is now.
///
/// Nothing is found on a machine without a cgroup tree of this shape, which
/// is any machine that is not the node: the caller then has no reading and
/// says nothing, which is the truth.
pub fn observe(engine_pid: Option<u32>) -> Option<Reading> {
    let listing = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let dir = Path::new(CGROUP_ROOT).join(own_cgroup(&listing)?.trim_start_matches('/'));

    let memory_used = number(&dir.join("memory.current"))?;
    let memory_limit = number(&dir.join("memory.high"))
        .or_else(|| number(&dir.join("memory.max")))
        .or_else(total_memory);
    let memory_stall = stall(&dir.join("memory.pressure")).unwrap_or(0.0);
    let cpu_stall = stall(&dir.join("cpu.pressure")).unwrap_or(0.0);

    let (open_files, file_limit) = match engine_pid {
        Some(pid) => (open_files_of(pid), file_limit_of(pid)),
        None => (None, None),
    };

    Some(Reading {
        cpus: std::thread::available_parallelism()
            .map(|count| u32::try_from(count.get()).unwrap_or(u32::MAX))
            .unwrap_or(1),
        memory_used,
        memory_limit,
        memory_stall,
        cpu_stall,
        open_files,
        file_limit,
    })
}

/// The word for these figures.
pub fn classify(
    memory_used: u64,
    memory_limit: Option<u64>,
    memory_stall: f64,
    cpu_stall: f64,
    open_files: Option<u64>,
    file_limit: Option<u64>,
) -> Pressure {
    let mut worst = Pressure::Calm;
    let mut raise = |to: Pressure| {
        if rank(to) > rank(worst) {
            worst = to;
        }
    };

    if let Some(limit) = memory_limit.filter(|limit| *limit > 0) {
        let used = memory_used as f64 / limit as f64;
        if used >= MEMORY_CRITICAL {
            raise(Pressure::Critical);
        } else if used >= MEMORY_STRAINED {
            raise(Pressure::Strained);
        }
    }
    if memory_stall >= MEMORY_STALL_CRITICAL {
        raise(Pressure::Critical);
    } else if memory_stall >= MEMORY_STALL_STRAINED {
        raise(Pressure::Strained);
    }
    if cpu_stall >= CPU_STALL_STRAINED {
        raise(Pressure::Strained);
    }
    if let (Some(open), Some(limit)) = (open_files, file_limit.filter(|limit| *limit > 0)) {
        let used = open as f64 / limit as f64;
        if used >= FILES_CRITICAL {
            raise(Pressure::Critical);
        } else if used >= FILES_STRAINED {
            raise(Pressure::Strained);
        }
    }
    worst
}

fn rank(pressure: Pressure) -> u8 {
    match pressure {
        Pressure::Calm => 0,
        Pressure::Strained => 1,
        Pressure::Critical => 2,
    }
}

/// The cgroup this process is in, from the unified hierarchy's line.
pub fn own_cgroup(listing: &str) -> Option<String> {
    listing
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|path| path.trim().to_owned())
        .filter(|path| !path.is_empty())
}

/// The `some avg10` figure of a pressure file, in percent.
///
/// `some` rather than `full`: the moment any task is waiting is the moment a
/// client is waiting, and that is early enough to ease off.
pub fn parse_stall(text: &str) -> Option<f64> {
    text.lines()
        .find(|line| line.starts_with("some "))?
        .split_whitespace()
        .find_map(|field| field.strip_prefix("avg10="))?
        .parse()
        .ok()
}

/// The soft limit on open files from a process's `limits` file.
pub fn parse_file_limit(text: &str) -> Option<u64> {
    let line = text
        .lines()
        .find(|line| line.starts_with("Max open files"))?;
    let rest = line.strip_prefix("Max open files")?.trim_start();
    let soft = rest.split_whitespace().next()?;
    if soft == "unlimited" {
        return None;
    }
    soft.parse().ok()
}

/// A file holding one number, or the word `max` for no limit.
fn number(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn stall(path: &Path) -> Option<f64> {
    parse_stall(&std::fs::read_to_string(path).ok()?)
}

/// Memory in the machine, for a cgroup that has no limit of its own.
///
/// Read from `/proc/meminfo` when the unit lets that be seen, which the
/// node's unit does not; on such a node the installer has set a limit and
/// this is never reached.
fn total_memory() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kilobytes: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kilobytes * 1024)
}

fn open_files_of(pid: u32) -> Option<u64> {
    let entries = std::fs::read_dir(PathBuf::from(format!("/proc/{pid}/fd"))).ok()?;
    Some(entries.count() as u64)
}

fn file_limit_of(pid: u32) -> Option<u64> {
    parse_file_limit(&std::fs::read_to_string(format!("/proc/{pid}/limits")).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn a_quiet_machine_is_calm() {
        assert_eq!(
            classify(100 * MIB, Some(512 * MIB), 0.0, 0.0, Some(120), Some(65536)),
            Pressure::Calm
        );
    }

    #[test]
    fn memory_near_its_limit_strains_and_then_turns_critical() {
        assert_eq!(
            classify(440 * MIB, Some(512 * MIB), 0.0, 0.0, None, None),
            Pressure::Strained
        );
        assert_eq!(
            classify(490 * MIB, Some(512 * MIB), 0.0, 0.0, None, None),
            Pressure::Critical
        );
    }

    #[test]
    fn waiting_for_memory_counts_even_below_the_limit() {
        // Half the memory is free and tasks still spend a fifth of their time
        // waiting for it: the kernel knows something the ratio does not.
        assert_eq!(
            classify(200 * MIB, Some(512 * MIB), 20.0, 0.0, None, None),
            Pressure::Strained
        );
        assert_eq!(
            classify(200 * MIB, Some(512 * MIB), 45.0, 0.0, None, None),
            Pressure::Critical
        );
    }

    #[test]
    fn a_busy_processor_strains_but_never_kills() {
        assert_eq!(
            classify(100 * MIB, Some(512 * MIB), 0.0, 99.0, None, None),
            Pressure::Strained
        );
    }

    #[test]
    fn running_out_of_files_is_critical() {
        assert_eq!(
            classify(
                100 * MIB,
                Some(512 * MIB),
                0.0,
                0.0,
                Some(53000),
                Some(65536)
            ),
            Pressure::Strained
        );
        assert_eq!(
            classify(
                100 * MIB,
                Some(512 * MIB),
                0.0,
                0.0,
                Some(62500),
                Some(65536)
            ),
            Pressure::Critical
        );
    }

    #[test]
    fn the_worst_figure_wins() {
        assert_eq!(
            classify(490 * MIB, Some(512 * MIB), 0.0, 99.0, Some(10), Some(65536)),
            Pressure::Critical
        );
    }

    #[test]
    fn without_a_limit_memory_is_not_judged() {
        assert_eq!(
            classify(u64::MAX, None, 0.0, 0.0, None, None),
            Pressure::Calm
        );
        assert_eq!(
            classify(u64::MAX, Some(0), 0.0, 0.0, None, None),
            Pressure::Calm
        );
    }

    #[test]
    fn the_cgroup_is_taken_from_the_unified_line() {
        let listing = "0::/system.slice/anyproxy-agent.service\n";
        assert_eq!(
            own_cgroup(listing).as_deref(),
            Some("/system.slice/anyproxy-agent.service")
        );
        assert_eq!(own_cgroup("1:name=systemd:/\n"), None);
        assert_eq!(own_cgroup("0::\n"), None);
    }

    #[test]
    fn the_stall_is_the_some_average_over_ten_seconds() {
        let text = "some avg10=12.34 avg60=5.00 avg300=1.00 total=123456\n\
                    full avg10=2.00 avg60=1.00 avg300=0.50 total=6543\n";
        assert_eq!(parse_stall(text), Some(12.34));
        assert_eq!(parse_stall("full avg10=2.00\n"), None);
        assert_eq!(parse_stall(""), None);
    }

    #[test]
    fn the_file_limit_is_the_soft_one() {
        let text = "Limit                     Soft Limit           Hard Limit           Units\n\
                    Max processes             4096                 4096                 processes\n\
                    Max open files            65536                262144               files\n";
        assert_eq!(parse_file_limit(text), Some(65536));
        assert_eq!(
            parse_file_limit(
                "Max open files            unlimited            unlimited            files\n"
            ),
            None
        );
        assert_eq!(parse_file_limit("Max processes 1 1 processes\n"), None);
    }

    #[test]
    fn the_report_says_megabytes_and_a_word() {
        let reading = Reading {
            cpus: 1,
            memory_used: 440 * MIB,
            memory_limit: Some(512 * MIB),
            memory_stall: 3.5,
            cpu_stall: 0.0,
            open_files: Some(200),
            file_limit: Some(65536),
        };
        let report = reading.report();
        assert_eq!(report.memory_used_mb, 440);
        assert_eq!(report.memory_limit_mb, Some(512));
        assert_eq!(report.pressure, "strained");
    }

    #[test]
    fn only_calm_spends_on_the_optional() {
        assert!(!Pressure::Calm.eases_off());
        assert!(Pressure::Strained.eases_off());
        assert!(Pressure::Critical.eases_off());
    }
}
