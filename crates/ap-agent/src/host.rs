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
    /// Processor time the cgroup has used since boot, in microseconds.
    pub cpu_used_usec: Option<u64>,
    /// Bytes seen on the interfaces since boot.
    pub rx_bytes: Option<u64>,
    /// Bytes sent on them.
    pub tx_bytes: Option<u64>,
    /// Connections established on the ports the node serves.
    pub connections: Option<u64>,
    /// Resident memory of the agent and of the engine, in bytes.
    pub own_memory: Option<u64>,
    pub engine_memory: Option<u64>,
    /// Processor time each of them has used, in clock ticks.
    pub own_ticks: Option<u64>,
    pub engine_ticks: Option<u64>,
}

/// What the last reading said, so a rate can be worked out from the next.
///
/// Rates are counted here rather than in the panel: the panel sees only the
/// message it was sent, and between two messages a node can restart, which
/// would turn the difference of two counters into a speed that never
/// happened (0064).
#[derive(Debug, Clone, Default)]
pub struct Rates {
    at: Option<std::time::Instant>,
    cpu_used_usec: Option<u64>,
    rx_bytes: Option<u64>,
    tx_bytes: Option<u64>,
    own_ticks: Option<u64>,
    engine_ticks: Option<u64>,
    /// When the agent started, for its own uptime.
    started: Option<std::time::Instant>,
    /// How many times the engine has been started again.
    pub restarts: u32,
}

impl Rates {
    /// Starts counting from now.
    pub fn new() -> Self {
        Self {
            started: Some(std::time::Instant::now()),
            ..Self::default()
        }
    }

    /// Notes that the engine had to be started again.
    pub fn engine_restarted(&mut self) {
        self.restarts = self.restarts.saturating_add(1);
    }

    /// How long the agent has been running.
    pub fn uptime(&self) -> Option<u64> {
        self.started.map(|at| at.elapsed().as_secs())
    }

    /// Turns two readings into rates, and remembers this one.
    ///
    /// A counter that went backwards means the thing it counted started over,
    /// and nothing is reported for it this time rather than a negative speed.
    pub fn advance(&mut self, reading: &Reading, cpus: u32) -> Speeds {
        let now = std::time::Instant::now();
        let seconds = self
            .at
            .map(|before| now.duration_since(before).as_secs_f64())
            .filter(|seconds| *seconds > 0.5);

        let rate = |before: Option<u64>, after: Option<u64>| -> Option<f64> {
            let (before, after, seconds) = (before?, after?, seconds?);
            after.checked_sub(before).map(|grew| grew as f64 / seconds)
        };

        let speeds = Speeds {
            cpu_percent: rate(self.cpu_used_usec, reading.cpu_used_usec)
                .map(|per_second| per_second / 10_000.0 / f64::from(cpus.max(1))),
            rx_bps: rate(self.rx_bytes, reading.rx_bytes).map(|bytes| bytes as u64),
            tx_bps: rate(self.tx_bytes, reading.tx_bytes).map(|bytes| bytes as u64),
            own_cpu: rate(self.own_ticks, reading.own_ticks)
                .map(|ticks| ticks * 100.0 / (ticks_per_second() * f64::from(cpus.max(1)))),
            engine_cpu: rate(self.engine_ticks, reading.engine_ticks)
                .map(|ticks| ticks * 100.0 / (ticks_per_second() * f64::from(cpus.max(1)))),
        };

        self.at = Some(now);
        self.cpu_used_usec = reading.cpu_used_usec;
        self.rx_bytes = reading.rx_bytes;
        self.tx_bytes = reading.tx_bytes;
        self.own_ticks = reading.own_ticks;
        self.engine_ticks = reading.engine_ticks;
        speeds
    }
}

/// What a pair of readings amounts to.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Speeds {
    pub cpu_percent: Option<f64>,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub own_cpu: Option<f64>,
    pub engine_cpu: Option<f64>,
}

/// Clock ticks a second, which is what `/proc/<pid>/stat` counts in.
fn ticks_per_second() -> f64 {
    // Every Linux this runs on reports a hundred; the figure is not readable
    // without libc, and being wrong here would only scale a percentage.
    100.0
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
    pub fn report(&self, speeds: Speeds, rates: &Rates) -> ap_proto::MachineReport {
        let megabytes = |bytes: Option<u64>| bytes.map(|bytes| bytes / (1024 * 1024));
        let mut processes = Vec::new();
        if let Some(memory) = megabytes(self.own_memory) {
            processes.push(ap_proto::ProcessReport {
                name: "anyproxy-agent".to_owned(),
                cpu_percent: speeds.own_cpu,
                memory_mb: memory,
                restarts: 0,
            });
        }
        if let Some(memory) = megabytes(self.engine_memory) {
            processes.push(ap_proto::ProcessReport {
                name: "telemt".to_owned(),
                cpu_percent: speeds.engine_cpu,
                memory_mb: memory,
                restarts: rates.restarts,
            });
        }
        ap_proto::MachineReport {
            cpus: self.cpus,
            memory_used_mb: self.memory_used / (1024 * 1024),
            memory_limit_mb: self.memory_limit.map(|bytes| bytes / (1024 * 1024)),
            memory_stall: self.memory_stall,
            cpu_stall: self.cpu_stall,
            open_files: self.open_files,
            file_limit: self.file_limit,
            pressure: self.pressure().as_reported().to_owned(),
            cpu_percent: speeds.cpu_percent,
            uptime_seconds: rates.uptime(),
            connections: self.connections,
            rx_bps: speeds.rx_bps,
            tx_bps: speeds.tx_bps,
            processes,
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
        cpu_used_usec: cpu_used(&dir.join("cpu.stat")),
        rx_bytes: traffic().map(|(rx, _)| rx),
        tx_bytes: traffic().map(|(_, tx)| tx),
        connections: connections(&SERVED_PORTS),
        own_memory: resident_of(std::process::id()),
        engine_memory: engine_pid.and_then(resident_of),
        own_ticks: cpu_ticks_of(std::process::id()),
        engine_ticks: engine_pid.and_then(cpu_ticks_of),
    })
}

/// The ports a node answers on. A connection on any of them is a client.
const SERVED_PORTS: [u16; 4] = [443, 1080, 3128, 8443];

/// Processor time the cgroup has used, from `cpu.stat`.
fn cpu_used(path: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    parse_cpu_used(&text)
}

/// Reads `usage_usec` out of a cgroup's `cpu.stat`.
pub fn parse_cpu_used(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix("usage_usec "))
        .and_then(|value| value.trim().parse().ok())
}

/// Bytes in and out on every interface but the loopback.
fn traffic() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/net/dev").ok()?;
    Some(parse_traffic(&text))
}

/// Sums `/proc/net/dev`, leaving the loopback out: what a node sends to
/// itself is not what it carries.
pub fn parse_traffic(text: &str) -> (u64, u64) {
    let mut received = 0;
    let mut sent = 0;
    for line in text.lines().skip(2) {
        let Some((name, figures)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == "lo" {
            continue;
        }
        let numbers: Vec<u64> = figures
            .split_whitespace()
            .filter_map(|word| word.parse().ok())
            .collect();
        if numbers.len() >= 9 {
            received += numbers[0];
            sent += numbers[8];
        }
    }
    (received, sent)
}

/// Established connections on the ports a node serves.
fn connections(ports: &[u16]) -> Option<u64> {
    let mut total = 0;
    let mut seen = false;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            seen = true;
            total += parse_connections(&text, ports);
        }
    }
    seen.then_some(total)
}

/// Counts rows of `/proc/net/tcp` in state 01 — established — whose local
/// port is one the node serves.
pub fn parse_connections(text: &str, ports: &[u16]) -> u64 {
    text.lines()
        .skip(1)
        .filter(|line| {
            let mut words = line.split_whitespace();
            let local = words.nth(1).unwrap_or_default();
            let state = words.nth(1).unwrap_or_default();
            let port = local
                .rsplit(':')
                .next()
                .and_then(|hex| u16::from_str_radix(hex, 16).ok());
            state == "01" && port.is_some_and(|port| ports.contains(&port))
        })
        .count() as u64
}

/// Resident memory of a process, in bytes.
fn resident_of(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

/// Processor time a process has used, in clock ticks.
fn cpu_ticks_of(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_cpu_ticks(&text)
}

/// Adds the user and system fields of `/proc/<pid>/stat`.
///
/// The name of the process sits in brackets and may hold spaces, so the
/// fields are counted from the closing bracket rather than from the start.
pub fn parse_cpu_ticks(text: &str) -> Option<u64> {
    let rest = text.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let user: u64 = fields.get(11)?.parse().ok()?;
    let system: u64 = fields.get(12)?.parse().ok()?;
    Some(user + system)
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
            cpu_used_usec: None,
            rx_bytes: None,
            tx_bytes: None,
            connections: Some(78),
            own_memory: Some(34 * MIB),
            engine_memory: Some(210 * MIB),
            own_ticks: None,
            engine_ticks: None,
        };
        let mut rates = Rates::new();
        rates.engine_restarted();
        let report = reading.report(Speeds::default(), &rates);
        assert_eq!(report.memory_used_mb, 440);
        assert_eq!(report.memory_limit_mb, Some(512));
        assert_eq!(report.pressure, "strained");
        assert_eq!(report.connections, Some(78));
        // One entry for the agent and one for the engine, and the engine's
        // carries how many times it had to be started again.
        assert_eq!(report.processes.len(), 2);
        let engine = report
            .processes
            .iter()
            .find(|process| process.name == "telemt")
            .expect("the engine is reported");
        assert_eq!(engine.memory_mb, 210);
        assert_eq!(engine.restarts, 1);
    }

    #[test]
    fn only_calm_spends_on_the_optional() {
        assert!(!Pressure::Calm.eases_off());
        assert!(Pressure::Strained.eases_off());
        assert!(Pressure::Critical.eases_off());
    }

    #[test]
    fn processor_time_is_read_out_of_the_cgroup() {
        let stat = "usage_usec 123456789
user_usec 90000000
system_usec 33456789
";
        assert_eq!(parse_cpu_used(stat), Some(123_456_789));
        assert_eq!(
            parse_cpu_used(
                "nr_periods 0
"
            ),
            None
        );
    }

    #[test]
    fn the_loopback_is_not_traffic_the_node_carries() {
        let dev = "Inter-|   Receive                            |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets
    lo: 5000 10 0 0 0 0 0 0 6000 10 0 0 0 0 0 0
  eth0: 1000 20 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
  eth1: 300 3 0 0 0 0 0 0 400 3 0 0 0 0 0 0
";
        assert_eq!(parse_traffic(dev), (1300, 2400));
    }

    #[test]
    fn only_established_connections_on_served_ports_are_counted() {
        // Local address, then remote, then state: 01 is established, 0A is
        // listening. 01BB is 443, 0438 is 1080, 1F90 is 8080.
        let tcp = "  sl  local_address rem_address   st
   0: 0100007F:01BB 00000000:0000 0A
   1: 0100007F:01BB 0200007F:C001 01
   2: 0100007F:0438 0200007F:C002 01
   3: 0100007F:1F90 0200007F:C003 01
";
        assert_eq!(parse_connections(tcp, &[443, 1080]), 2);
        assert_eq!(parse_connections(tcp, &[8080]), 1);
    }

    #[test]
    fn a_process_name_with_spaces_does_not_move_the_figures() {
        // The name sits in brackets and may hold anything, so the fields are
        // counted from the closing bracket.
        let stat = "42 (my engine) S 1 42 42 0 -1 4194560 100 0 0 0 700 300 0 0 20 0 8 0 99";
        assert_eq!(parse_cpu_ticks(stat), Some(1000));
    }

    #[test]
    fn the_first_reading_carries_no_speed_and_a_restart_none_either() {
        let mut rates = Rates::new();
        let reading = |cpu: u64, rx: u64| Reading {
            cpus: 2,
            memory_used: 1,
            memory_limit: None,
            memory_stall: 0.0,
            cpu_stall: 0.0,
            open_files: None,
            file_limit: None,
            cpu_used_usec: Some(cpu),
            rx_bytes: Some(rx),
            tx_bytes: Some(0),
            connections: None,
            own_memory: None,
            engine_memory: None,
            own_ticks: None,
            engine_ticks: None,
        };
        // Nothing to measure against yet.
        assert_eq!(rates.advance(&reading(0, 0), 2), Speeds::default());
        // A counter that went backwards is a process that started over, and
        // a speed is not invented for it.
        let before = rates.advance(&reading(10, 10), 2);
        assert_eq!(
            before,
            Speeds::default(),
            "a second inside half a second is not a rate"
        );
        assert_eq!(rates.restarts, 0);
        rates.engine_restarted();
        assert_eq!(rates.restarts, 1);
    }
}
