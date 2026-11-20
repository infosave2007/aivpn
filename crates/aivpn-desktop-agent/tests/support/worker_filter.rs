use super::program;

#[cfg(target_arch = "x86_64")]
const ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const ARCH: u32 = 0xc000_00b7;

fn evaluate(call: libc::c_long, arguments: [u64; 6], architecture: u32) -> u32 {
    let mut data = [0u8; 64];
    data[..4].copy_from_slice(&(call as u32).to_ne_bytes());
    data[4..8].copy_from_slice(&architecture.to_ne_bytes());
    for (index, argument) in arguments.into_iter().enumerate() {
        data[16 + index * 8..24 + index * 8].copy_from_slice(&argument.to_ne_bytes());
    }
    let code = program();
    let (mut accumulator, mut pc) = (0u32, 0usize);
    for _ in 0..1000 {
        let instruction = code.get(pc).expect("Фильтр вышел за границы программы");
        pc += 1;
        match instruction.code {
            0x20 => {
                let offset = instruction.k as usize;
                accumulator = u32::from_ne_bytes(
                    data.get(offset..offset + 4)
                        .expect("Чтение вне seccomp_data")
                        .try_into()
                        .unwrap(),
                );
            }
            0x54 => accumulator &= instruction.k,
            0x15 => {
                pc += usize::from(if accumulator == instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                })
            }
            0x45 => {
                pc += usize::from(if accumulator & instruction.k != 0 {
                    instruction.jt
                } else {
                    instruction.jf
                })
            }
            0x06 => return instruction.k,
            opcode => panic!("Неизвестная инструкция фильтра {opcode:x}"),
        }
    }
    panic!("Фильтр не завершился");
}

fn errno(code: i32) -> u32 {
    libc::SECCOMP_RET_ERRNO | code as u32
}
fn result(call: libc::c_long, first: u64) -> u32 {
    evaluate(call, [first, 0, 0, 0, 0, 0], ARCH)
}

#[test]
fn packet_worker_allows_ip_transports_and_rejects_descriptor_export_sockets() {
    for family in [libc::AF_INET, libc::AF_INET6] {
        for kind in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
            for flags in [
                0,
                libc::SOCK_CLOEXEC,
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            ] {
                assert_eq!(
                    evaluate(
                        libc::SYS_socket,
                        [family as u64, (kind | flags) as u64, 0, 0, 0, 0],
                        ARCH
                    ),
                    libc::SECCOMP_RET_ALLOW
                );
            }
        }
        for kind in [libc::SOCK_RAW, libc::SOCK_SEQPACKET, libc::SOCK_DCCP] {
            assert_eq!(
                evaluate(
                    libc::SYS_socket,
                    [family as u64, kind as u64, 0, 0, 0, 0],
                    ARCH
                ),
                errno(libc::EPERM)
            );
        }
    }
    for family in [
        libc::AF_UNIX,
        libc::AF_PACKET,
        libc::AF_NETLINK,
        libc::AF_ALG,
    ] {
        assert_eq!(
            evaluate(
                libc::SYS_socket,
                [family as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0],
                ARCH
            ),
            errno(libc::EPERM)
        );
    }
}

#[test]
fn packet_worker_cannot_restore_privileges_or_acquire_other_process_descriptors() {
    for call in [
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
    ] {
        for arguments in [[0u64; 6], [u64::MAX; 6]] {
            assert_eq!(
                evaluate(call, arguments, ARCH),
                errno(libc::EPERM),
                "{call}"
            );
        }
    }
}

#[test]
fn packet_worker_keeps_runtime_io_and_restricts_process_creation_and_signals() {
    for call in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_ctl,
        libc::SYS_futex,
        libc::SYS_mmap,
    ] {
        assert_eq!(result(call, 0), libc::SECCOMP_RET_ALLOW, "{call}");
    }
    assert_eq!(
        result(
            libc::SYS_clone,
            (libc::CLONE_THREAD | libc::CLONE_VM | libc::CLONE_SIGHAND) as u64
        ),
        libc::SECCOMP_RET_ALLOW
    );
    for flags in [0, libc::SIGCHLD as u64, libc::CLONE_VM as u64] {
        assert_eq!(result(libc::SYS_clone, flags), errno(libc::EPERM));
    }
    assert_eq!(result(libc::SYS_clone3, 0), errno(libc::ENOSYS));
    #[cfg(target_arch = "x86_64")]
    for call in [libc::SYS_fork, libc::SYS_vfork] {
        assert_eq!(result(call, 0), errno(libc::EPERM));
    }
    let own = unsafe { libc::getpid() } as u64;
    for call in [libc::SYS_kill, libc::SYS_tgkill] {
        assert_eq!(result(call, own), libc::SECCOMP_RET_ALLOW);
        for other in [0, own + 1, u64::MAX] {
            assert_eq!(result(call, other), errno(libc::EPERM));
        }
    }
}

#[test]
fn packet_worker_cannot_change_its_seccomp_or_dumpable_state() {
    for option in [
        libc::PR_GET_DUMPABLE,
        libc::PR_GET_NO_NEW_PRIVS,
        libc::PR_GET_SECCOMP,
        libc::PR_SET_NAME,
    ] {
        assert_eq!(
            result(libc::SYS_prctl, option as u64),
            libc::SECCOMP_RET_ALLOW
        );
    }
    for option in [
        libc::PR_SET_DUMPABLE,
        libc::PR_SET_NO_NEW_PRIVS,
        libc::PR_SET_SECCOMP,
        libc::PR_SET_PTRACER,
        libc::PR_SET_KEEPCAPS,
    ] {
        assert_eq!(result(libc::SYS_prctl, option as u64), errno(libc::EPERM));
    }
}

#[test]
fn packet_worker_kills_a_different_syscall_abi_instead_of_bypassing_the_filter() {
    assert_eq!(
        evaluate(libc::SYS_getpid, [0; 6], 0x4000_0003),
        libc::SECCOMP_RET_KILL_PROCESS
    );
    assert_eq!(
        evaluate(libc::SYS_getpid, [0; 6], 0),
        libc::SECCOMP_RET_KILL_PROCESS
    );
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        result(libc::SYS_getpid | 0x4000_0000, 0),
        libc::SECCOMP_RET_KILL_PROCESS
    );
}
