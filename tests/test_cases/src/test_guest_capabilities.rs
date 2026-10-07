use macros::{guest, host};

pub struct TestGuestCapabilities {
    pub(crate) inheritable: bool,
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32, Test, TestSetup};
    use krun_sys::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;

    impl Test for TestGuestCapabilities {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let root_dir = test_setup.tmp_dir.join("rootfs");
            std::fs::create_dir_all(&root_dir)?;
            std::fs::set_permissions(&root_dir, std::fs::Permissions::from_mode(0o755))?;
            let inheritable: &[&str] = if self.inheritable {
                &["CAP_NET_BIND_SERVICE"]
            } else {
                &[]
            };
            // Without inheritable, the requested ambient capability cannot be granted.
            let config = serde_json::json!({
                "process": {
                    "user": {"uid": 1000, "gid": 1000},
                    "noNewPrivileges": true,
                    "capabilities": {
                        "bounding": ["CAP_NET_BIND_SERVICE"],
                        "effective": ["CAP_NET_BIND_SERVICE"],
                        "permitted": ["CAP_NET_BIND_SERVICE"],
                        "inheritable": inheritable,
                        "ambient": ["CAP_NET_BIND_SERVICE"]
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

    impl Test for TestGuestCapabilities {
        fn in_guest(self: Box<Self>) {
            assert_eq!(unsafe { libc::getuid() }, 1000);
            assert_eq!(unsafe { libc::getgid() }, 1000);
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            let capability = |name| {
                let line = status.lines().find(|line| line.starts_with(name)).unwrap();
                u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap()
            };
            assert_eq!(capability("CapBnd:"), 1 << 10);
            let expected = if self.inheritable { 1 << 10 } else { 0 };
            for name in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
                assert_eq!(capability(name), expected, "{name}");
            }
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
                1
            );
            println!("OK");
        }
    }
}
