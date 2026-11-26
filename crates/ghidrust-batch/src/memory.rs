//! Memory budget monitoring.
//!
//! On Windows, queries the process **committed** (pagefile) memory via
//! `GetProcessMemoryInfo` (`PagefileUsage`), not the working set (RSS).
//! Committed memory is what actually matters for OOM: it reflects all
//! heap-allocated virtual memory, including stacker segments, regardless
//! of whether pages are resident.
//!
//! Also exposes system-wide available physical memory for adaptive
//! parallelism under pressure.
//!
//! On other platforms, falls back to a no-op estimate.

/// Memory snapshot for the current process and system.
#[derive(Debug, Clone, Copy)]
pub struct MemorySnapshot {
    /// Process committed (pagefile) memory in bytes.
    pub committed_bytes: u64,
    /// Process peak committed memory in bytes.
    pub peak_committed_bytes: u64,
    /// System-wide available physical memory in bytes (0 if unknown).
    pub system_avail_bytes: u64,
}

/// Get current process committed memory in bytes (PagefileUsage on Windows).
pub fn current_committed_bytes() -> u64 {
    #[cfg(windows)]
    {
        windows_committed()
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// Remaining system commit charge, from GetPerformanceInfo (not pagefile free bytes).
pub fn system_commit_spare_bytes() -> Option<u64> {
    #[cfg(windows)]
    {
        windows_system_commit().map(|(used, limit)| limit.saturating_sub(used))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Get a full memory snapshot (process + system).
pub fn snapshot() -> MemorySnapshot {
    #[cfg(windows)]
    {
        let (committed, peak) = windows_committed_pair();
        let avail = windows_system_avail();
        MemorySnapshot {
            committed_bytes: committed,
            peak_committed_bytes: peak,
            system_avail_bytes: avail,
        }
    }
    #[cfg(not(windows))]
    {
        MemorySnapshot {
            committed_bytes: 0,
            peak_committed_bytes: 0,
            system_avail_bytes: 0,
        }
    }
}

#[cfg(windows)]
fn windows_committed() -> u64 {
    windows_committed_pair().0
}

#[cfg(windows)]
fn windows_committed_pair() -> (u64, u64) {
    use std::mem::MaybeUninit;
    unsafe {
        let handle = GetCurrentProcess();
        let mut pmc = MaybeUninit::<PROCESS_MEMORY_COUNTERS>::zeroed();
        let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(handle, pmc.as_mut_ptr(), size) != 0 {
            let pmc = pmc.assume_init();
            (pmc.PagefileUsage as u64, pmc.PeakPagefileUsage as u64)
        } else {
            (0, 0)
        }
    }
}

#[cfg(windows)]
fn windows_system_avail() -> u64 {
    use std::mem::MaybeUninit;
    unsafe {
        let mut ms = MaybeUninit::<MEMORYSTATUSEX>::zeroed();
        let p = ms.as_mut_ptr();
        (*p).dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(p) != 0 {
            (*p).ullAvailPhys
        } else {
            0
        }
    }
}

#[cfg(windows)]
fn windows_system_commit() -> Option<(u64, u64)> {
    use std::mem::MaybeUninit;
    unsafe {
        let mut info = MaybeUninit::<PERFORMANCE_INFORMATION>::zeroed();
        let ptr = info.as_mut_ptr();
        (*ptr).cb = std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32;
        if GetPerformanceInfo(ptr, (*ptr).cb) == 0 {
            return None;
        }
        let info = info.assume_init();
        let page_size = info.page_size as u64;
        Some((
            info.commit_total as u64 * page_size,
            info.commit_limit as u64 * page_size,
        ))
    }
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct PROCESS_MEMORY_COUNTERS {
    cb: u32,
    PageFaultCount: u32,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MEMORYSTATUSEX {
    dwLength: u32,
    dwMemoryLoad: u32,
    ullTotalPhys: u64,
    ullAvailPhys: u64,
    ullTotalPageFile: u64,
    ullAvailPageFile: u64,
    ullTotalVirtual: u64,
    ullAvailVirtual: u64,
    ullAvailExtendedVirtual: u64,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
struct PERFORMANCE_INFORMATION {
    cb: u32,
    commit_total: usize,
    commit_limit: usize,
    commit_peak: usize,
    physical_total: usize,
    physical_available: usize,
    system_cache: usize,
    kernel_total: usize,
    kernel_paged: usize,
    kernel_nonpaged: usize,
    page_size: usize,
    handle_count: u32,
    process_count: u32,
    thread_count: u32,
}

#[cfg(windows)]
extern "system" {
    fn GetCurrentProcess() -> *mut std::ffi::c_void;
    fn GetProcessMemoryInfo(
        process: *mut std::ffi::c_void,
        ppsmemcounters: *mut PROCESS_MEMORY_COUNTERS,
        cb: u32,
    ) -> i32;
    fn GlobalMemoryStatusEx(lpBuffer: *mut MEMORYSTATUSEX) -> i32;
}

#[cfg(windows)]
#[link(name = "psapi")]
extern "system" {
    fn GetPerformanceInfo(info: *mut PERFORMANCE_INFORMATION, size: u32) -> i32;
}

/// Default memory budget in GiB for tests and batch runs.
pub const DEFAULT_BUDGET_GB: f64 = 4.0;

/// Check if committed memory is approaching the budget.
pub fn is_over_budget(budget_gb: f64) -> bool {
    let committed = current_committed_bytes();
    if committed == 0 {
        return false; // Can't measure, don't throttle.
    }
    let budget_bytes = (budget_gb * 1024.0 * 1024.0 * 1024.0) as u64;
    committed > (budget_bytes * 90 / 100) // 90% threshold
}

/// Check if system-wide available memory is critically low.
pub fn system_memory_pressure(min_avail_gb: f64) -> bool {
    let snap = snapshot();
    if snap.system_avail_bytes == 0 {
        return false; // Can't measure
    }
    let min_bytes = (min_avail_gb * 1024.0 * 1024.0 * 1024.0) as u64;
    snap.system_avail_bytes < min_bytes
}

/// Suggest a worker count reduction factor based on current memory pressure.
/// Returns 1.0 (no reduction) when memory is fine, down to 0.25 under heavy
/// pressure.
pub fn parallelism_factor(budget_gb: f64) -> f64 {
    let committed = current_committed_bytes();
    if committed == 0 {
        return 1.0;
    }
    let budget_bytes = budget_gb * 1024.0 * 1024.0 * 1024.0;
    let ratio = committed as f64 / budget_bytes;
    if ratio < 0.5 {
        1.0
    } else if ratio < 0.75 {
        0.75
    } else if ratio < 0.9 {
        0.5
    } else {
        0.25
    }
}
