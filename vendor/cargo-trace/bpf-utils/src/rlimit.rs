use std::io::{Error, Result};

pub fn increase_memlock_rlimit() -> Result<()> {
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl as *mut _) != 0 {
            return Err(Error::last_os_error());
        }
        rl.rlim_max = libc::RLIM_INFINITY;
        rl.rlim_cur = libc::RLIM_INFINITY;
        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl as *const _) != 0 {
            return Err(Error::last_os_error());
        }
    }
    Ok(())
}
