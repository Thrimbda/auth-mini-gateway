//! Linux-only clocks, process identity, affinity, and host observations.
//!
//! The benchmark never mutates host policy. The only writes performed here are
//! affinity changes for the benchmark's own processes and threads.

use crate::seal::sha256_hex;
use crate::{Error, Result, ResultContext};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const GATEWAY_CPUS: &[u16] = &[0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23];
pub const FIXTURE_CPUS: &[u16] = &[8, 9, 10, 24, 25, 26];
pub const LOAD_CPUS: &[u16] = &[11, 12, 13, 14, 27, 28, 29, 30];
pub const CONTROL_CPUS: &[u16] = &[15, 31];
pub const CLK_TCK_EXPECTED: u64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClockKind {
    Monotonic,
    Boottime,
    Realtime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealtimeTriplet {
    pub boottime_before_ns: u64,
    pub realtime_ns: u64,
    pub boottime_after_ns: u64,
}

#[allow(unsafe_code)]
pub fn clock_ns(clock: ClockKind) -> Result<u64> {
    let id = match clock {
        ClockKind::Monotonic => libc::CLOCK_MONOTONIC,
        ClockKind::Boottime => libc::CLOCK_BOOTTIME,
        ClockKind::Realtime => libc::CLOCK_REALTIME,
    };
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a valid writable timespec and `id` is a Linux clock ID.
    if unsafe { libc::clock_gettime(id, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let seconds = u64::try_from(value.tv_sec).map_err(|_| Error::new("negative clock value"))?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| Error::new("negative clock nanos"))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanos))
        .ok_or_else(|| Error::new("clock value overflow"))
}

pub fn realtime_triplet() -> Result<RealtimeTriplet> {
    let before = clock_ns(ClockKind::Boottime)?;
    let realtime = clock_ns(ClockKind::Realtime)?;
    let after = clock_ns(ClockKind::Boottime)?;
    if after < before {
        return Err(Error::new("BOOTTIME moved backwards"));
    }
    Ok(RealtimeTriplet {
        boottime_before_ns: before,
        realtime_ns: realtime,
        boottime_after_ns: after,
    })
}

/// Formats a nonnegative Unix timestamp without consulting timezone databases.
pub fn utc_rfc3339(unix_seconds: u64) -> Result<String> {
    let days = unix_seconds / 86_400;
    let second_of_day = unix_seconds % 86_400;
    let (year, month, day) =
        civil_from_days(i64::try_from(days).map_err(|_| Error::new("UTC day count overflow"))?);
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000Z"
    ))
}

fn civil_from_days(unix_days: i64) -> (i64, i64, i64) {
    // Howard Hinnant's civil-from-days algorithm, with day zero at 1970-01-01.
    let z = unix_days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time_ticks: u64,
    pub parent_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcStat {
    pub pid: u32,
    pub comm: String,
    pub state: String,
    pub parent_pid: u32,
    pub user_ticks: u64,
    pub system_ticks: u64,
    pub major_faults: u64,
    pub start_time_ticks: u64,
    pub processor: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcStatus {
    pub vm_hwm_kib: Option<u64>,
    pub vm_rss_kib: Option<u64>,
    pub cpus_allowed_list: String,
    pub voluntary_context_switches: u64,
    pub nonvoluntary_context_switches: u64,
}

pub fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    let stat = read_proc_stat(pid, None)?;
    Ok(ProcessIdentity {
        pid,
        start_time_ticks: stat.start_time_ticks,
        parent_pid: stat.parent_pid,
    })
}

/// Proves that `identity` owns the exact listening socket before any
/// benchmark credential or request is sent to it.
pub fn verify_listening_socket_owner(
    identity: &ProcessIdentity,
    address: SocketAddr,
) -> Result<u64> {
    validate_identity(identity)?;
    let IpAddr::V4(ip) = address.ip() else {
        return Err(Error::new(
            "gateway listener ownership currently requires literal IPv4 loopback",
        ));
    };
    if !ip.is_loopback() {
        return Err(Error::new("gateway listener is not literal loopback"));
    }
    let encoded_ip = u32::from_le_bytes(ip.octets());
    let expected = format!("{encoded_ip:08X}:{:04X}", address.port());
    let table = fs::read_to_string("/proc/net/tcp")?;
    let mut inodes = BTreeSet::new();
    for line in table.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() > 9 && fields[1] == expected && fields[3] == "0A" {
            inodes.insert(fields[9].parse::<u64>().context("parse TCP socket inode")?);
        }
    }
    if inodes.len() != 1 {
        return Err(Error::new(format!(
            "expected one LISTEN inode for {address}, observed {}",
            inodes.len()
        )));
    }
    let inode = *inodes
        .iter()
        .next()
        .ok_or_else(|| Error::new("listener inode vanished"))?;
    let expected_link = format!("socket:[{inode}]");
    let mut owned = false;
    for entry in fs::read_dir(format!("/proc/{}/fd", identity.pid))? {
        let entry = entry?;
        match fs::read_link(entry.path()) {
            Ok(target) if target.to_string_lossy() == expected_link => {
                owned = true;
                break;
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if !owned {
        return Err(Error::new(format!(
            "LISTEN inode {inode} is not owned by spawned gateway PID {}",
            identity.pid
        )));
    }
    validate_identity(identity)?;
    Ok(inode)
}

pub fn validate_identity(identity: &ProcessIdentity) -> Result<ProcStat> {
    let stat = read_proc_stat(identity.pid, None)?;
    if stat.start_time_ticks != identity.start_time_ticks || stat.parent_pid != identity.parent_pid
    {
        return Err(Error::new(format!(
            "PID {} identity changed: expected start={} ppid={}, got start={} ppid={}",
            identity.pid,
            identity.start_time_ticks,
            identity.parent_pid,
            stat.start_time_ticks,
            stat.parent_pid
        )));
    }
    Ok(stat)
}

pub fn read_proc_stat(pid: u32, tid: Option<u32>) -> Result<ProcStat> {
    let path = match tid {
        Some(tid) => PathBuf::from(format!("/proc/{pid}/task/{tid}/stat")),
        None => PathBuf::from(format!("/proc/{pid}/stat")),
    };
    let text = fs::read_to_string(&path).context(format!("read {}", path.display()))?;
    parse_proc_stat(&text)
}

pub fn parse_proc_stat(text: &str) -> Result<ProcStat> {
    let open = text
        .find('(')
        .ok_or_else(|| Error::new("/proc stat missing comm open"))?;
    let close = text
        .rfind(')')
        .ok_or_else(|| Error::new("/proc stat missing comm close"))?;
    if close <= open {
        return Err(Error::new("/proc stat malformed comm"));
    }
    let pid = text[..open]
        .trim()
        .parse::<u32>()
        .context("parse /proc stat PID")?;
    let comm = text[open + 1..close].to_owned();
    let fields: Vec<&str> = text[close + 1..].split_ascii_whitespace().collect();
    if fields.len() < 37 {
        return Err(Error::new("/proc stat has too few fields"));
    }
    let parse_u64 = |index: usize, name: &str| -> Result<u64> {
        fields[index]
            .parse::<u64>()
            .context(format!("parse /proc stat {name}"))
    };
    Ok(ProcStat {
        pid,
        comm,
        state: fields[0].to_owned(),
        parent_pid: fields[1].parse::<u32>().context("parse /proc stat ppid")?,
        user_ticks: parse_u64(11, "utime")?,
        system_ticks: parse_u64(12, "stime")?,
        major_faults: parse_u64(9, "majflt")?,
        start_time_ticks: parse_u64(19, "starttime")?,
        processor: fields[36]
            .parse::<i32>()
            .context("parse /proc stat processor")?,
    })
}

pub fn read_proc_status(pid: u32, tid: Option<u32>) -> Result<ProcStatus> {
    let path = match tid {
        Some(tid) => PathBuf::from(format!("/proc/{pid}/task/{tid}/status")),
        None => PathBuf::from(format!("/proc/{pid}/status")),
    };
    let text = fs::read_to_string(&path).context(format!("read {}", path.display()))?;
    parse_proc_status(&text)
}

pub fn parse_proc_status(text: &str) -> Result<ProcStatus> {
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            fields.insert(name, value.trim());
        }
    }
    let parse_kib = |name: &str| -> Result<Option<u64>> {
        let Some(value) = fields.get(name) else {
            return Ok(None);
        };
        let mut parts = value.split_ascii_whitespace();
        let amount = parts
            .next()
            .ok_or_else(|| Error::new(format!("empty {name}")))?
            .parse::<u64>()
            .context(format!("parse {name}"))?;
        if parts.next() != Some("kB") || parts.next().is_some() {
            return Err(Error::new(format!("unexpected {name} unit")));
        }
        Ok(Some(amount))
    };
    let parse_counter = |name: &str| -> Result<u64> {
        fields
            .get(name)
            .ok_or_else(|| Error::new(format!("missing {name}")))?
            .parse::<u64>()
            .context(format!("parse {name}"))
    };
    Ok(ProcStatus {
        vm_hwm_kib: parse_kib("VmHWM")?,
        vm_rss_kib: parse_kib("VmRSS")?,
        cpus_allowed_list: fields
            .get("Cpus_allowed_list")
            .ok_or_else(|| Error::new("missing Cpus_allowed_list"))?
            .to_string(),
        voluntary_context_switches: parse_counter("voluntary_ctxt_switches")?,
        nonvoluntary_context_switches: parse_counter("nonvoluntary_ctxt_switches")?,
    })
}

pub fn task_ids(pid: u32) -> Result<Vec<u32>> {
    let mut tids = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/task")).context("enumerate process tasks")? {
        let entry = entry?;
        let name = entry.file_name();
        let text = name.to_str().ok_or_else(|| Error::new("non-UTF-8 TID"))?;
        tids.push(text.parse::<u32>().context("parse TID")?);
    }
    tids.sort_unstable();
    Ok(tids)
}

#[allow(unsafe_code)]
pub fn set_affinity(pid_or_tid: u32, cpus: &[u16]) -> Result<()> {
    if cpus.is_empty() {
        return Err(Error::new("empty affinity mask"));
    }
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is initialized and every CPU index is checked by CPU_SET.
    unsafe {
        libc::CPU_ZERO(&mut set);
        for cpu in cpus {
            libc::CPU_SET(usize::from(*cpu), &mut set);
        }
    }
    let raw_pid = i32::try_from(pid_or_tid).map_err(|_| Error::new("PID exceeds pid_t"))?;
    // SAFETY: the pointer and size describe the initialized cpu_set_t.
    if unsafe { libc::sched_setaffinity(raw_pid, std::mem::size_of::<libc::cpu_set_t>(), &set) }
        != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub fn parse_cpu_list(value: &str) -> Result<BTreeSet<u16>> {
    let mut cpus = BTreeSet::new();
    for item in value.trim().split(',') {
        if item.is_empty() {
            return Err(Error::new("empty CPU-list component"));
        }
        if let Some((first, last)) = item.split_once('-') {
            let first = first.parse::<u16>().context("parse CPU range start")?;
            let last = last.parse::<u16>().context("parse CPU range end")?;
            if first > last {
                return Err(Error::new("descending CPU range"));
            }
            cpus.extend(first..=last);
        } else {
            cpus.insert(item.parse::<u16>().context("parse CPU index")?);
        }
    }
    Ok(cpus)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuTicks {
    pub cpu: u16,
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTicks {
    pub fn scheduled(&self) -> Result<u64> {
        self.user
            .checked_add(self.nice)
            .and_then(|value| value.checked_add(self.system))
            .ok_or_else(|| Error::new("scheduled CPU ticks overflow"))
    }

    pub fn capacity(&self) -> Result<u64> {
        self.scheduled()?
            .checked_add(self.idle)
            .and_then(|value| value.checked_add(self.iowait))
            .and_then(|value| value.checked_add(self.irq))
            .and_then(|value| value.checked_add(self.softirq))
            .and_then(|value| value.checked_add(self.steal))
            .ok_or_else(|| Error::new("CPU capacity ticks overflow"))
    }
}

pub fn read_per_cpu_ticks() -> Result<BTreeMap<u16, CpuTicks>> {
    let text = fs::read_to_string("/proc/stat")?;
    let mut output = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(name) = fields.next() else { continue };
        let Some(index) = name.strip_prefix("cpu") else {
            continue;
        };
        if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let values = fields
            .map(|field| field.parse::<u64>().context("parse /proc/stat CPU tick"))
            .collect::<Result<Vec<_>>>()?;
        if values.len() < 8 {
            return Err(Error::new("/proc/stat CPU row has too few fields"));
        }
        let cpu = index.parse::<u16>().context("parse /proc/stat CPU")?;
        output.insert(
            cpu,
            CpuTicks {
                cpu,
                user: values[0],
                nice: values[1],
                system: values[2],
                idle: values[3],
                iowait: values[4],
                irq: values[5],
                softirq: values[6],
                steal: values[7],
            },
        );
    }
    if output.is_empty() {
        return Err(Error::new("no per-CPU rows in /proc/stat"));
    }
    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PressureTotals {
    pub cpu_some_us: u64,
    pub memory_full_us: u64,
    pub io_full_us: u64,
}

pub fn pressure_totals() -> Result<PressureTotals> {
    Ok(PressureTotals {
        cpu_some_us: pressure_total(Path::new("/proc/pressure/cpu"), "some")?,
        memory_full_us: pressure_total(Path::new("/proc/pressure/memory"), "full")?,
        io_full_us: pressure_total(Path::new("/proc/pressure/io"), "full")?,
    })
}

fn pressure_total(path: &Path, class: &str) -> Result<u64> {
    let text = fs::read_to_string(path).context(format!("read {}", path.display()))?;
    let line = text
        .lines()
        .find(|line| line.starts_with(class))
        .ok_or_else(|| Error::new(format!("missing {class} pressure row")))?;
    line.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix("total="))
        .ok_or_else(|| Error::new("pressure row missing total"))?
        .parse::<u64>()
        .context("parse pressure total")
}

pub fn swap_counters() -> Result<(u64, u64)> {
    let text = fs::read_to_string("/proc/vmstat")?;
    let mut input = None;
    let mut output = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("pswpin ") {
            input = Some(value.parse::<u64>().context("parse pswpin")?);
        } else if let Some(value) = line.strip_prefix("pswpout ") {
            output = Some(value.parse::<u64>().context("parse pswpout")?);
        }
    }
    Ok((
        input.ok_or_else(|| Error::new("missing pswpin"))?,
        output.ok_or_else(|| Error::new("missing pswpout"))?,
    ))
}

pub fn tctl_millidegrees() -> Result<u64> {
    let root = Path::new("/sys/class/hwmon");
    let mut candidates = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() && !entry.file_type()?.is_symlink() {
            continue;
        }
        let directory = entry.path();
        let name = fs::read_to_string(directory.join("name")).unwrap_or_default();
        if name.trim() != "k10temp" {
            continue;
        }
        for sensor in fs::read_dir(&directory)? {
            let sensor = sensor?;
            let file_name = sensor.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            if !file_name.starts_with("temp") || !file_name.ends_with("_label") {
                continue;
            }
            let label = fs::read_to_string(sensor.path()).unwrap_or_default();
            if label.trim() == "Tctl" {
                let input = directory.join(file_name.replace("_label", "_input"));
                candidates.push(input);
            }
        }
    }
    candidates.sort();
    let path = candidates
        .first()
        .ok_or_else(|| Error::new("Tctl k10temp sensor not found"))?;
    fs::read_to_string(path)?
        .trim()
        .parse::<u64>()
        .context("parse Tctl")
}

pub fn scaling_cur_frequencies_khz(cpus: &[u16]) -> Result<BTreeMap<u16, u64>> {
    if cpus.is_empty() {
        return Err(Error::new("frequency sample has an empty CPU set"));
    }
    let mut values = BTreeMap::new();
    for cpu in cpus {
        let path = PathBuf::from(format!(
            "/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq"
        ));
        let value = fs::read_to_string(&path)
            .context(format!("read {}", path.display()))?
            .trim()
            .parse::<u64>()
            .context(format!("parse {}", path.display()))?;
        if value == 0 || values.insert(*cpu, value).is_some() {
            return Err(Error::new("invalid/duplicate CPU frequency sample"));
        }
    }
    Ok(values)
}

#[allow(unsafe_code)]
pub fn filesystem_free_bytes(path: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let c_path = std::ffi::CString::new(bytes).map_err(|_| Error::new("path contains NUL"))?;
    let mut value: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c_path is NUL-terminated and value is a writable statvfs.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    value
        .f_bavail
        .checked_mul(value.f_frsize)
        .ok_or_else(|| Error::new("filesystem free-byte overflow"))
}

#[allow(unsafe_code)]
pub fn clock_ticks_per_second() -> Result<u64> {
    // SAFETY: _SC_CLK_TCK is a side-effect-free sysconf query.
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(value).map_err(|_| Error::new("sysconf(_SC_CLK_TCK) failed"))
}

#[allow(unsafe_code)]
pub fn nofile_limits() -> Result<(u64, u64)> {
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: limit is writable and RLIMIT_NOFILE is a valid resource.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((limit.rlim_cur, limit.rlim_max))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandIdentity {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub version: String,
}

pub fn command_identity(path: &Path, version_arguments: &[&str]) -> Result<CommandIdentity> {
    let canonical =
        fs::canonicalize(path).context(format!("canonicalize executable {}", path.display()))?;
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(Error::new("tool path is not a regular file"));
    }
    // Invoke the requested path rather than its target: rustup-style multicall
    // shims select Cargo versus rustc from argv[0]. The content hash still binds
    // the resolved executable bytes.
    let output = std::process::Command::new(path)
        .args(version_arguments)
        .output()
        .context(format!("run {}", canonical.display()))?;
    if !output.status.success() {
        return Err(Error::new(format!(
            "{} version command failed with {}",
            canonical.display(),
            output.status
        )));
    }
    let mut version = String::from_utf8(output.stdout)
        .map_err(|_| Error::new("tool version output is not UTF-8"))?;
    if !output.stderr.is_empty() {
        version.push_str(
            &String::from_utf8(output.stderr)
                .map_err(|_| Error::new("tool version stderr is not UTF-8"))?,
        );
    }
    Ok(CommandIdentity {
        path: format!("{} -> {}", path.display(), canonical.display()),
        bytes: metadata.len(),
        sha256: sha256_hex(&fs::read(&canonical)?),
        version: version.trim().to_owned(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPreflight {
    pub schema: String,
    pub smoke_ready: bool,
    pub campaign_ready: bool,
    pub blockers: Vec<String>,
    pub observations: BTreeMap<String, String>,
    pub start: RealtimeTriplet,
    pub end: RealtimeTriplet,
}

pub fn preflight(repository: &Path, observation: Duration) -> Result<HostPreflight> {
    let start = realtime_triplet()?;
    let mut blockers = Vec::new();
    let mut observations = BTreeMap::new();
    let current_affinity = read_proc_status(std::process::id(), None)?.cpus_allowed_list;
    let allowed = parse_cpu_list(&current_affinity)?;
    let required: BTreeSet<u16> = (0_u16..32).collect();
    observations.insert("self_cpus_allowed_list".to_owned(), current_affinity);
    if !required.is_subset(&allowed) {
        blockers.push("the current cpuset does not expose logical CPUs 0..31".to_owned());
    }
    let online_text = fs::read_to_string("/sys/devices/system/cpu/online")?;
    observations.insert("online_cpus".to_owned(), online_text.trim().to_owned());
    if !required.is_subset(&parse_cpu_list(&online_text)?) {
        blockers.push("logical CPUs 0..31 are not all online".to_owned());
    }
    let ticks = clock_ticks_per_second()?;
    observations.insert("clk_tck".to_owned(), ticks.to_string());
    if ticks != CLK_TCK_EXPECTED {
        blockers.push(format!("CLK_TCK is {ticks}, expected {CLK_TCK_EXPECTED}"));
    }
    let clocksource =
        fs::read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource")?;
    observations.insert("clocksource".to_owned(), clocksource.trim().to_owned());
    if clocksource.trim() != "tsc" {
        blockers.push("current clocksource is not tsc".to_owned());
    }
    let aslr = fs::read_to_string("/proc/sys/kernel/randomize_va_space")?;
    observations.insert("aslr".to_owned(), aslr.trim().to_owned());
    if aslr.trim() != "2" {
        blockers.push("ASLR is not set to 2".to_owned());
    }
    let (nofile_soft, nofile_hard) = nofile_limits()?;
    observations.insert("nofile_soft".to_owned(), nofile_soft.to_string());
    observations.insert("nofile_hard".to_owned(), nofile_hard.to_string());
    if nofile_soft < 10_000 {
        blockers.push("RLIMIT_NOFILE soft limit is below 10000".to_owned());
    }
    let free = filesystem_free_bytes(repository)?;
    observations.insert("repository_free_bytes".to_owned(), free.to_string());
    if free <= 20 * 1024 * 1024 * 1024 {
        blockers.push("repository filesystem does not have more than 20 GiB free".to_owned());
    }
    match tctl_millidegrees() {
        Ok(value) => {
            observations.insert("tctl_millidegrees".to_owned(), value.to_string());
            if value > 75_000 {
                blockers.push("Tctl exceeds the 75C arm-start gate".to_owned());
            }
        }
        Err(error) => blockers.push(format!("Tctl unavailable: {error}")),
    }
    check_cpu_policy(&mut observations, &mut blockers)?;
    let pressure_before = pressure_totals()?;
    let swap_before = swap_counters()?;
    let cpu_before = read_per_cpu_ticks()?;
    std::thread::sleep(observation);
    let pressure_after = pressure_totals()?;
    let swap_after = swap_counters()?;
    let cpu_after = read_per_cpu_ticks()?;
    let elapsed_us = observation.as_micros().max(1);
    let cpu_some_delta = pressure_after
        .cpu_some_us
        .checked_sub(pressure_before.cpu_some_us)
        .ok_or_else(|| Error::new("CPU PSI total decreased"))?;
    observations.insert("observation_us".to_owned(), elapsed_us.to_string());
    observations.insert(
        "cpu_psi_some_delta_us".to_owned(),
        cpu_some_delta.to_string(),
    );
    observations.insert(
        "memory_psi_full_delta_us".to_owned(),
        pressure_after
            .memory_full_us
            .saturating_sub(pressure_before.memory_full_us)
            .to_string(),
    );
    observations.insert(
        "io_psi_full_delta_us".to_owned(),
        pressure_after
            .io_full_us
            .saturating_sub(pressure_before.io_full_us)
            .to_string(),
    );
    if u128::from(cpu_some_delta) * 200 > elapsed_us {
        blockers.push("bounded CPU PSI some exceeds 0.50%".to_owned());
    }
    if pressure_after.memory_full_us != pressure_before.memory_full_us {
        blockers.push("memory full PSI advanced during preflight".to_owned());
    }
    if pressure_after.io_full_us != pressure_before.io_full_us {
        blockers.push("I/O full PSI advanced during preflight".to_owned());
    }
    if swap_after != swap_before {
        blockers.push("swap counters advanced during preflight".to_owned());
    }
    if cpu_after.values().any(|ticks| ticks.steal > 0)
        && cpu_before.iter().any(|(cpu, before)| {
            cpu_after
                .get(cpu)
                .is_some_and(|after| after.steal != before.steal)
        })
    {
        blockers.push("steal ticks advanced during preflight".to_owned());
    }
    let smoke_ready = !blockers.iter().any(|blocker| {
        blocker.contains("cpuset")
            || blocker.contains("not all online")
            || blocker.contains("CLK_TCK")
            || blocker.contains("20 GiB")
            || blocker.contains("Tctl unavailable")
    });
    let end = realtime_triplet()?;
    Ok(HostPreflight {
        schema: "amg-http2-perf/preflight/v1".to_owned(),
        smoke_ready,
        campaign_ready: blockers.is_empty(),
        blockers,
        observations,
        start,
        end,
    })
}

pub fn observe_quiet_exact() -> Result<crate::raw::QuietEvidence> {
    let pid = std::process::id();
    let frozen = quiet_thread_snapshot(pid)?;
    let orchestrator_threads = frozen
        .values()
        .map(|stat| {
            let assigned_cpu = u16::try_from(stat.processor)
                .map_err(|_| Error::new("orchestrator thread CPU does not fit u16"))?;
            Ok(crate::raw::QuietOrchestratorThread {
                pid,
                tid: stat.pid,
                start_time_ticks: stat.start_time_ticks,
                comm: stat.comm.clone(),
                assigned_cpu,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if orchestrator_threads.is_empty()
        || orchestrator_threads
            .iter()
            .any(|thread| !CONTROL_CPUS.contains(&thread.assigned_cpu))
    {
        return Err(Error::new(
            "persistent orchestrator threads are not confined to control CPUs",
        ));
    }
    let search_start_ns = clock_ns(ClockKind::Monotonic)?;
    let mut candidates = Vec::new();
    loop {
        let start_ns = clock_ns(ClockKind::Monotonic)?;
        if start_ns.saturating_sub(search_start_ns) > 120_000_000_000 {
            return Err(Error::new(
                "Q_obs did not find a clean interval within 120 seconds of Q_extra",
            ));
        }
        let end_ns = start_ns
            .checked_add(10_000_000_000)
            .ok_or_else(|| Error::new("Q_obs deadline overflow"))?;
        let pressure_before = pressure_totals()?;
        let swap_before = swap_counters()?;
        let cpu_before = read_per_cpu_ticks()?;
        let threads_before = quiet_thread_snapshot(pid)?;
        loop {
            let now = clock_ns(ClockKind::Monotonic)?;
            if now >= end_ns {
                break;
            }
            std::thread::sleep(Duration::from_nanos((end_ns - now).min(5_000_000)));
        }
        let pressure_after = pressure_totals()?;
        let swap_after = swap_counters()?;
        let cpu_after = read_per_cpu_ticks()?;
        let threads_after = quiet_thread_snapshot(pid)?;
        let mut inventory_stable =
            threads_before.keys().eq(frozen.keys()) && threads_after.keys().eq(frozen.keys());
        let mut subtracted = BTreeMap::<u16, u64>::new();
        for (tid, expected) in &frozen {
            let (Some(before), Some(after)) = (threads_before.get(tid), threads_after.get(tid))
            else {
                inventory_stable = false;
                continue;
            };
            if before.start_time_ticks != expected.start_time_ticks
                || after.start_time_ticks != expected.start_time_ticks
                || before.comm != expected.comm
                || after.comm != expected.comm
                || before.processor != expected.processor
                || after.processor != expected.processor
            {
                inventory_stable = false;
                continue;
            }
            let cpu = u16::try_from(expected.processor)
                .map_err(|_| Error::new("orchestrator thread CPU does not fit u16"))?;
            let delta = after
                .user_ticks
                .checked_add(after.system_ticks)
                .and_then(|value| {
                    before
                        .user_ticks
                        .checked_add(before.system_ticks)
                        .and_then(|start| value.checked_sub(start))
                })
                .ok_or_else(|| Error::new("orchestrator thread ticks decreased"))?;
            *subtracted.entry(cpu).or_default() = subtracted
                .get(&cpu)
                .copied()
                .unwrap_or_default()
                .checked_add(delta)
                .ok_or_else(|| Error::new("orchestrator subtraction overflow"))?;
        }
        let mut steal_ticks_delta = 0_u64;
        let mut cpus = Vec::with_capacity(cpu_before.len());
        for (cpu, before) in &cpu_before {
            let after = cpu_after
                .get(cpu)
                .ok_or_else(|| Error::new("Q_obs per-CPU row disappeared"))?;
            let scheduled_ticks = after
                .scheduled()?
                .checked_sub(before.scheduled()?)
                .ok_or_else(|| Error::new("Q_obs scheduled ticks decreased"))?;
            let capacity_ticks = after
                .capacity()?
                .checked_sub(before.capacity()?)
                .ok_or_else(|| Error::new("Q_obs capacity ticks decreased"))?;
            steal_ticks_delta = steal_ticks_delta
                .checked_add(
                    after
                        .steal
                        .checked_sub(before.steal)
                        .ok_or_else(|| Error::new("Q_obs steal ticks decreased"))?,
                )
                .ok_or_else(|| Error::new("Q_obs steal delta overflow"))?;
            let requested_subtraction = subtracted.get(cpu).copied().unwrap_or_default();
            if requested_subtraction > scheduled_ticks {
                inventory_stable = false;
            }
            let orchestrator_ticks_subtracted = requested_subtraction.min(scheduled_ticks);
            cpus.push(crate::raw::QuietCpuEvidence {
                cpu: *cpu,
                scheduled_ticks,
                capacity_ticks,
                orchestrator_ticks_subtracted,
                external_ticks: scheduled_ticks - orchestrator_ticks_subtracted,
            });
        }
        let mut candidate = crate::raw::QuietCandidateEvidence {
            start_ns,
            end_ns,
            cpu_psi_some_us: pressure_after
                .cpu_some_us
                .checked_sub(pressure_before.cpu_some_us)
                .ok_or_else(|| Error::new("Q_obs CPU PSI decreased"))?,
            memory_psi_full_us: pressure_after
                .memory_full_us
                .checked_sub(pressure_before.memory_full_us)
                .ok_or_else(|| Error::new("Q_obs memory PSI decreased"))?,
            io_psi_full_us: pressure_after
                .io_full_us
                .checked_sub(pressure_before.io_full_us)
                .ok_or_else(|| Error::new("Q_obs I/O PSI decreased"))?,
            swap_in_delta: swap_after
                .0
                .checked_sub(swap_before.0)
                .ok_or_else(|| Error::new("Q_obs swap-in decreased"))?,
            swap_out_delta: swap_after
                .1
                .checked_sub(swap_before.1)
                .ok_or_else(|| Error::new("Q_obs swap-out decreased"))?,
            steal_ticks_delta,
            cpus,
            orchestrator_inventory_stable: inventory_stable,
            accepted: false,
        };
        candidate.accepted = candidate.recomputed_clean();
        let accepted = candidate.accepted;
        candidates.push(candidate);
        if accepted {
            let final_candidate = candidates
                .last()
                .ok_or_else(|| Error::new("Q_obs accepted candidate vanished"))?;
            let evidence = crate::raw::QuietEvidence {
                schema: "amg-http2-perf/quiet/v2".to_owned(),
                clock: "CLOCK_MONOTONIC".to_owned(),
                start_ns: final_candidate.start_ns,
                end_ns: final_candidate.end_ns,
                q_extra_ns: final_candidate.start_ns.saturating_sub(search_start_ns),
                cpu_psi_some_us: final_candidate.cpu_psi_some_us,
                memory_psi_full_us: final_candidate.memory_psi_full_us,
                io_psi_full_us: final_candidate.io_psi_full_us,
                swap_in_delta: final_candidate.swap_in_delta,
                swap_out_delta: final_candidate.swap_out_delta,
                steal_ticks_delta: final_candidate.steal_ticks_delta,
                external_time_clean: final_candidate.external_time_clean(),
                search_start_ns,
                orchestrator_threads,
                candidates,
            };
            evidence.validate()?;
            return Ok(evidence);
        }
    }
}

fn quiet_thread_snapshot(pid: u32) -> Result<BTreeMap<u32, ProcStat>> {
    let mut snapshot = BTreeMap::new();
    for tid in task_ids(pid)? {
        let stat = read_proc_stat(pid, Some(tid))?;
        if snapshot.insert(tid, stat).is_some() {
            return Err(Error::new("duplicate orchestrator TID during Q_obs"));
        }
    }
    Ok(snapshot)
}

fn check_cpu_policy(
    observations: &mut BTreeMap<String, String>,
    blockers: &mut Vec<String>,
) -> Result<()> {
    let driver = fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver")?;
    observations.insert("scaling_driver".to_owned(), driver.trim().to_owned());
    if driver.trim() != "amd-pstate-epp" {
        blockers.push("CPU scaling driver is not amd-pstate-epp".to_owned());
    }
    for cpu in 0_u16..32 {
        let root = PathBuf::from(format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq"));
        let governor = fs::read_to_string(root.join("scaling_governor"))?;
        if governor.trim() != "performance" {
            blockers.push(format!("CPU {cpu} governor is not performance"));
        }
        let epp = fs::read_to_string(root.join("energy_performance_preference"))?;
        if epp.trim() != "performance" {
            blockers.push(format!("CPU {cpu} EPP is not performance"));
        }
    }
    let boost = fs::read_to_string("/sys/devices/system/cpu/cpufreq/boost")?;
    observations.insert("boost".to_owned(), boost.trim().to_owned());
    if boost.trim() != "1" {
        blockers.push("CPU boost is not enabled".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_stat_with_spaces_and_parentheses_in_comm() {
        let mut fields = vec!["S".to_owned(); 50];
        fields[1] = "41".to_owned();
        fields[9] = "3".to_owned();
        fields[11] = "101".to_owned();
        fields[12] = "7".to_owned();
        fields[19] = "123456".to_owned();
        fields[36] = "15".to_owned();
        let text = format!("42 (worker (bench)) {}", fields.join(" "));
        let parsed = parse_proc_stat(&text).expect("proc stat");
        assert_eq!(parsed.pid, 42);
        assert_eq!(parsed.comm, "worker (bench)");
        assert_eq!(parsed.parent_pid, 41);
        assert_eq!(parsed.user_ticks + parsed.system_ticks, 108);
        assert_eq!(parsed.start_time_ticks, 123456);
        assert_eq!(parsed.major_faults, 3);
        assert_eq!(parsed.processor, 15);
    }

    #[test]
    fn parses_cpu_lists_without_range_credit() {
        let cpus = parse_cpu_list("0-2,4,16-17\n").expect("CPU list");
        assert_eq!(
            cpus.into_iter().collect::<Vec<_>>(),
            vec![0, 1, 2, 4, 16, 17]
        );
        assert!(parse_cpu_list("4-2").is_err());
        assert!(parse_cpu_list("0,,1").is_err());
    }

    #[test]
    fn formats_utc_without_timezone_or_realtime_dependency() {
        assert_eq!(utc_rfc3339(0).expect("epoch"), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            utc_rfc3339(1_774_051_200).expect("2026 date"),
            "2026-03-21T00:00:00.000Z"
        );
    }

    #[test]
    fn parses_status_resource_fields() {
        let parsed = parse_proc_status(
            "VmHWM:\t120 kB\nVmRSS:\t100 kB\nCpus_allowed_list:\t0,16\nvoluntary_ctxt_switches:\t5\nnonvoluntary_ctxt_switches:\t2\n",
        )
        .expect("status");
        assert_eq!(parsed.vm_hwm_kib, Some(120));
        assert_eq!(parsed.vm_rss_kib, Some(100));
        assert_eq!(parsed.cpus_allowed_list, "0,16");
    }

    #[test]
    fn listener_inode_must_be_owned_by_the_exact_pid_start_tuple() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let identity = process_identity(std::process::id()).expect("identity");
        assert!(verify_listening_socket_owner(&identity, address).is_ok());
        let mut wrong = identity;
        wrong.start_time_ticks += 1;
        assert!(verify_listening_socket_owner(&wrong, address).is_err());
    }
}
