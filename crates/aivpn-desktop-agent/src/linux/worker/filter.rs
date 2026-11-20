use std::io;

#[cfg(not(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub(super) fn install() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Архитектура фильтра работника не поддерживается",
    ))
}

#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(super) fn install() -> io::Result<()> {
    let mut code = program();
    let filter = libc::sock_fprog {
        len: code
            .len()
            .try_into()
            .map_err(|_| io::Error::other("Слишком большой фильтр работника"))?,
        filter: code.as_mut_ptr(),
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &filter,
        )
    };
    if result != 0 {
        return Err(if result < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::other("Не все потоки приняли ограничения работника")
        });
    }
    Ok(())
}

#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn program() -> Vec<libc::sock_filter> {
    #[cfg(target_arch = "x86_64")]
    let architecture = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    let architecture = 0xc000_00b7;
    let mut code = vec![
        load(4),
        jump(libc::BPF_JEQ, architecture, 1, 0),
        ret(libc::SECCOMP_RET_KILL_PROCESS),
        load(0),
    ];
    #[cfg(target_arch = "x86_64")]
    code.extend([
        jump(libc::BPF_JSET, 0x4000_0000, 0, 1),
        ret(libc::SECCOMP_RET_KILL_PROCESS),
    ]);
    for call in denied_calls() {
        code.extend([jump(libc::BPF_JEQ, call as u32, 0, 1), refusal(libc::EPERM)]);
    }
    selected(&mut code, libc::SYS_clone3, vec![refusal(libc::ENOSYS)]);
    selected(&mut code, libc::SYS_socket, socket());
    selected(
        &mut code,
        libc::SYS_prctl,
        values(
            16,
            &[
                libc::PR_GET_DUMPABLE as u32,
                libc::PR_GET_NO_NEW_PRIVS as u32,
                libc::PR_GET_SECCOMP as u32,
                libc::PR_SET_NAME as u32,
            ],
        ),
    );
    selected(
        &mut code,
        libc::SYS_clone,
        vec![
            load(16),
            jump(libc::BPF_JSET, libc::CLONE_THREAD as u32, 0, 1),
            ret(libc::SECCOMP_RET_ALLOW),
            refusal(libc::EPERM),
        ],
    );
    let own = unsafe { libc::getpid() } as u32;
    for call in [libc::SYS_kill, libc::SYS_tgkill] {
        selected(&mut code, call, values(16, &[own]));
    }
    code.push(ret(libc::SECCOMP_RET_ALLOW));
    code
}

#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn denied_calls() -> Vec<libc::c_long> {
    let calls = vec![
        libc::SYS_ioctl,
        libc::SYS_socketpair,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_tkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_seccomp,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_setgroups,
        libc::SYS_capset,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
    ];
    #[cfg(target_arch = "x86_64")]
    {
        let mut calls = calls;
        calls.extend([libc::SYS_fork, libc::SYS_vfork]);
        calls
    }
    #[cfg(target_arch = "aarch64")]
    calls
}

#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn socket() -> Vec<libc::sock_filter> {
    let mut code = vec![
        load(16),
        jump(libc::BPF_JEQ, libc::AF_INET as u32, 2, 0),
        jump(libc::BPF_JEQ, libc::AF_INET6 as u32, 1, 0),
        refusal(libc::EPERM),
        load(24),
    ];
    code.push(libc::sock_filter {
        code: (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: 0xf,
    });
    code.extend([
        jump(libc::BPF_JEQ, libc::SOCK_STREAM as u32, 0, 1),
        ret(libc::SECCOMP_RET_ALLOW),
        jump(libc::BPF_JEQ, libc::SOCK_DGRAM as u32, 0, 1),
        ret(libc::SECCOMP_RET_ALLOW),
        refusal(libc::EPERM),
    ]);
    code
}

#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn values(offset: u32, allowed: &[u32]) -> Vec<libc::sock_filter> {
    let mut code = vec![load(offset)];
    for value in allowed {
        code.extend([
            jump(libc::BPF_JEQ, *value, 0, 1),
            ret(libc::SECCOMP_RET_ALLOW),
        ]);
    }
    code.push(refusal(libc::EPERM));
    code
}

#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn selected(
    code: &mut Vec<libc::sock_filter>,
    syscall: libc::c_long,
    body: Vec<libc::sock_filter>,
) {
    code.push(jump(
        libc::BPF_JEQ,
        syscall as u32,
        0,
        body.len().try_into().expect("Короткий блок фильтра"),
    ));
    code.extend(body);
}

#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn load(offset: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k: offset,
    }
}
#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn jump(operation: u32, value: u32, yes: u8, no: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | operation | libc::BPF_K) as u16,
        jt: yes,
        jf: no,
        k: value,
    }
}
#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn ret(value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: value,
    }
}
#[cfg(all(
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn refusal(code: i32) -> libc::sock_filter {
    ret(libc::SECCOMP_RET_ERRNO | code as u32)
}

#[cfg(all(
    test,
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[path = "../../../tests/support/worker_filter.rs"]
mod tests;
