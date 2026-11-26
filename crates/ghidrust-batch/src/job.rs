//! Windows Job Object enforcement shared by the complete worker pool.

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::sync::Arc;

    const JOB_OBJECT_QUERY: u32 = 0x0004;
    const JOB_OBJECT_LIMIT_JOB_MEMORY: u32 = 0x00000200;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x00002000;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_ops: u64,
        write_ops: u64,
        other_ops: u64,
        read_bytes: u64,
        write_bytes: u64,
        other_bytes: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimit {
        per_process_user_time: i64,
        per_job_user_time: i64,
        limit_flags: u32,
        minimum_working_set: usize,
        maximum_working_set: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimit {
        basic: BasicLimit,
        io: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory: usize,
        peak_job_memory: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn IsProcessInJob(process: *mut c_void, job: *mut c_void, result: *mut i32) -> i32;
        fn OpenJobObjectW(access: u32, inherit: i32, name: *const u16) -> *mut c_void;
        fn CreateJobObjectW(attrs: *mut c_void, name: *const u16) -> *mut c_void;
        fn SetInformationJobObject(
            job: *mut c_void,
            class: i32,
            info: *const c_void,
            size: u32,
        ) -> i32;
        fn QueryInformationJobObject(
            job: *mut c_void,
            class: i32,
            info: *mut c_void,
            size: u32,
            returned: *mut u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    struct Inner(*mut c_void);
    unsafe impl Send for Inner {}
    unsafe impl Sync for Inner {}
    impl Drop for Inner {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    #[derive(Clone)]
    pub struct WorkerJob(Arc<Inner>);

    impl WorkerJob {
        pub fn create(budget_gib: f64) -> Result<Self, String> {
            let limit = ((budget_gib * 1024f64.powi(3)) as usize).saturating_sub(128 * 1024 * 1024);
            if limit == 0 {
                return Err("worker Job Object budget is too small".into());
            }
            let handle = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
            if handle.is_null() {
                return Err(last_error("CreateJobObjectW"));
            }
            let mut info = ExtendedLimit::default();
            info.basic.limit_flags =
                JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            info.job_memory_limit = limit;
            let ok = unsafe {
                SetInformationJobObject(
                    handle,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    &info as *const _ as *const c_void,
                    std::mem::size_of_val(&info) as u32,
                )
            };
            if ok == 0 {
                unsafe {
                    CloseHandle(handle);
                }
                return Err(last_error("SetInformationJobObject"));
            }
            Ok(Self(Arc::new(Inner(handle))))
        }

        pub fn assign(&self, child: &std::process::Child) -> Result<(), String> {
            use std::os::windows::io::AsRawHandle;
            let process = child.as_raw_handle() as *mut c_void;
            let ok = unsafe { AssignProcessToJobObject(self.0 .0, process) };
            if ok == 0 {
                return Err(last_error("AssignProcessToJobObject(worker)"));
            }
            Ok(())
        }
    }

    pub fn verify_supervisor_budget(requested_gib: f64) -> Result<(), String> {
        let name = std::env::var("GHIDRUST_MEMORY_GUARD_JOB")
            .map_err(|_| "batch requires tools/memory_guard.py (named Windows Job Object)".to_string())?;
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let job = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, wide.as_ptr()) };
        if job.is_null() {
            return Err(
                "batch requires tools/memory_guard.py (named 4-GiB Windows Job Object)".into(),
            );
        }
        let mut info = ExtendedLimit::default();
        let mut returned = 0u32;
        let ok = unsafe {
            QueryInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of_val(&info) as u32,
                &mut returned,
            )
        };
        unsafe {
            CloseHandle(job);
        }
        if ok == 0 {
            return Err(last_error("QueryInformationJobObject(supervisor)"));
        }
        if info.basic.limit_flags & JOB_OBJECT_LIMIT_JOB_MEMORY == 0 {
            return Err("supervisor Job Object has no aggregate committed-memory limit".into());
        }
        let requested = (requested_gib * 1024f64.powi(3)) as usize;
        if info.job_memory_limit > requested {
            return Err(format!(
                "supervisor Job Object limit {} bytes exceeds requested batch budget {} bytes",
                info.job_memory_limit, requested
            ));
        }
        Ok(())
    }

    pub fn verify_current_process_in_any_job() -> Result<(), String> {
        let mut in_job = 0i32;
        let ok = unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) };
        if ok == 0 {
            return Err(last_error("IsProcessInJob"));
        }
        if in_job == 0 {
            return Err("batch worker must run inside a Windows Job Object".into());
        }
        Ok(())
    }

    fn last_error(operation: &str) -> String {
        format!("{operation} failed with Win32 error {}", unsafe {
            GetLastError()
        })
    }
}

#[cfg(windows)]
pub use imp::{verify_current_process_in_any_job, verify_supervisor_budget, WorkerJob};

#[cfg(not(windows))]
pub struct WorkerJob;
#[cfg(not(windows))]
impl WorkerJob {
    pub fn create(_: f64) -> Result<Self, String> {
        Err("protected batch mode requires Windows Job Objects".into())
    }
    pub fn assign(&self, _: &std::process::Child) -> Result<(), String> {
        Err("Windows Job Objects unavailable".into())
    }
    pub fn clone_handle(&self) -> Self {
        Self
    }
}
#[cfg(windows)]
impl WorkerJob {
    pub fn clone_handle(&self) -> Self {
        self.clone()
    }
}

#[cfg(not(windows))]
pub fn verify_supervisor_budget(_: f64) -> Result<(), String> {
    Err("protected batch mode requires tools/memory_guard.py and Windows Job Objects".into())
}
#[cfg(not(windows))]
pub fn verify_current_process_in_any_job() -> Result<(), String> {
    Err("batch worker requires Windows Job Objects".into())
}
