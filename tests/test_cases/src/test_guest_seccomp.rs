use macros::{guest, host};

pub struct TestGuestSeccomp {
    pub(crate) no_new_privileges: bool,
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32, Test, TestSetup};
    use krun_sys::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;

    // getppid returns EACCES, getpgid(0) returns EPERM; other calls are allowed.
    #[cfg(target_arch = "x86_64")]
    const FILTER: &str =
        "IAAAAAAAAAAVAAABbgAAAAYAAAANAAUAFQAAA3kAAAAgAAAAEAAAABUAAAEAAAAABgAAAAEABQAGAAAAAAD/fw==";
    #[cfg(target_arch = "aarch64")]
    const FILTER: &str =
        "IAAAAAAAAAAVAAABrQAAAAYAAAANAAUAFQAAA5sAAAAgAAAAEAAAABUAAAEAAAAABgAAAAEABQAGAAAAAAD/fw==";

    // With NNP off, setup must finish even when the workload cannot read.
    #[cfg(target_arch = "x86_64")]
    const READ_DENIED_FILTER: &str =
        "IAAAAAAAAAAVAAABbgAAAAYAAAANAAUAFQAAA3kAAAAgAAAAEAAAABUAAAEAAAAABgAAAAEABQAgAAAAAAAAABUAAAEAAAAABgAAAA0ABQAGAAAAAAD/fw==";
    #[cfg(target_arch = "aarch64")]
    const READ_DENIED_FILTER: &str =
        "IAAAAAAAAAAVAAABrQAAAAYAAAANAAUAFQAAA5sAAAAgAAAAEAAAABUAAAEAAAAABgAAAAEABQAgAAAAAAAAABUAAAE/AAAABgAAAA0ABQAGAAAAAAD/fw==";

    impl Test for TestGuestSeccomp {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let root_dir = test_setup.tmp_dir.join("rootfs");
            std::fs::create_dir_all(&root_dir)?;
            std::fs::set_permissions(&root_dir, std::fs::Permissions::from_mode(0o755))?;
            let config = serde_json::json!({
                "process": {
                    "user": {"uid": 1000, "gid": 1000},
                    "noNewPrivileges": self.no_new_privileges,
                    "capabilities": {}
                },
                "annotations": {
                    "run.oci.seccomp_bpf_data": if self.no_new_privileges {
                        FILTER
                    } else {
                        READ_DENIED_FILTER
                    }
                }
            });
            std::fs::write(
                root_dir.join(".krun_config.json"),
                serde_json::to_vec(&config)?,
            )?;
            unsafe {
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 256))?;
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;
                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use nix::libc;

    impl Test for TestGuestSeccomp {
        fn in_guest(self: Box<Self>) {
            assert_eq!(unsafe { libc::getuid() }, 1000);
            assert_eq!(unsafe { libc::syscall(libc::SYS_getppid) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EACCES)
            );
            assert_eq!(unsafe { libc::syscall(libc::SYS_getpgid, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            let pid = unsafe { libc::getpid() };
            assert!(unsafe { libc::syscall(libc::SYS_getpgid, pid) } >= 0);
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_GET_NO_NEW_PRIVS,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                },
                i32::from(self.no_new_privileges)
            );
            if self.no_new_privileges {
                let supervisor = std::fs::read_to_string("/proc/1/status").unwrap();
                let seccomp = supervisor
                    .lines()
                    .find(|line| line.starts_with("Seccomp:"))
                    .unwrap();
                assert_eq!(seccomp.split_whitespace().nth(1), Some("0"));
            } else {
                assert_eq!(unsafe { libc::read(-1, std::ptr::null_mut(), 0) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EACCES)
                );
            }
            println!("OK");
        }
    }
}
