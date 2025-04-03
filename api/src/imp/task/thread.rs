use core::{ffi::{c_char, c_void}, ptr};

use alloc::vec::Vec;
use arceos_posix_api::{self as api};
use axerrno::{LinuxError, LinuxResult};
use axtask::{TaskExtRef, current, yield_now};
use macro_rules_attribute::apply;
use num_enum::TryFromPrimitive;
use starry_core::{
    ctypes::{WaitFlags, WaitStatus},
    task::{exec, wait_pid},
};

use crate::{
    ptr::{PtrWrapper, UserConstPtr, UserPtr},
    syscall_instrument,
};

/// ARCH_PRCTL codes
///
/// It is only avaliable on x86_64, and is not convenient
/// to generate automatically via c_to_rust binding.
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(i32)]
enum ArchPrctlCode {
    /// Set the GS segment base
    SetGs = 0x1001,
    /// Set the FS segment base
    SetFs = 0x1002,
    /// Get the FS segment base
    GetFs = 0x1003,
    /// Get the GS segment base
    GetGs = 0x1004,
    /// The setting of the flag manipulated by ARCH_SET_CPUID
    GetCpuid = 0x1011,
    /// Enable (addr != 0) or disable (addr == 0) the cpuid instruction for the calling thread.
    SetCpuid = 0x1012,
}

#[apply(syscall_instrument)]
pub fn sys_getpid() -> LinuxResult<isize> {
    Ok(axtask::current().task_ext().proc_id as _)
}

#[apply(syscall_instrument)]
pub fn sys_getppid() -> LinuxResult<isize> {
    Ok(axtask::current().task_ext().get_parent() as _)
}

pub fn sys_exit(status: i32) -> ! {
    let curr = current();
    let clear_child_tid = curr.task_ext().clear_child_tid() as *mut i32;
    if !clear_child_tid.is_null() {
        // TODO: check whether the address is valid
        unsafe {
            // TODO: Encapsulate all operations that access user-mode memory into a unified function
            *(clear_child_tid) = 0;
        }
        // TODO: wake up threads, which are blocked by futex, and waiting for the address pointed by clear_child_tid
    }
    axtask::exit(status);
}

pub fn sys_exit_group(status: i32) -> ! {
    warn!("Temporarily replace sys_exit_group with sys_exit");
    axtask::exit(status);
}

/// To set the clear_child_tid field in the task extended data.
///
/// The set_tid_address() always succeeds
#[apply(syscall_instrument)]
pub fn sys_set_tid_address(tid_ptd: UserConstPtr<i32>) -> LinuxResult<isize> {
    let curr = current();
    curr.task_ext()
        .set_clear_child_tid(tid_ptd.address().as_ptr() as _);
    Ok(curr.id().as_u64() as isize)
}

#[cfg(target_arch = "x86_64")]
#[apply(syscall_instrument)]
pub fn sys_arch_prctl(code: i32, addr: UserPtr<u64>) -> LinuxResult<isize> {
    use axerrno::LinuxError;
    match ArchPrctlCode::try_from(code).map_err(|_| LinuxError::EINVAL)? {
        // According to Linux implementation, SetFs & SetGs does not return
        // error at all
        ArchPrctlCode::SetFs => {
            unsafe {
                axhal::arch::write_thread_pointer(addr.address().as_usize());
            }
            Ok(0)
        }
        ArchPrctlCode::SetGs => {
            unsafe {
                x86::msr::wrmsr(x86::msr::IA32_KERNEL_GSBASE, addr.address().as_usize() as _);
            }
            Ok(0)
        }
        ArchPrctlCode::GetFs => {
            unsafe {
                *addr.get()? = axhal::arch::read_thread_pointer() as u64;
            }
            Ok(0)
        }

        ArchPrctlCode::GetGs => {
            unsafe {
                *addr.get()? = x86::msr::rdmsr(x86::msr::IA32_KERNEL_GSBASE);
            }
            Ok(0)
        }
        ArchPrctlCode::GetCpuid => Ok(0),
        ArchPrctlCode::SetCpuid => Err(LinuxError::ENODEV),
    }
}

#[apply(syscall_instrument)]
pub fn sys_clone(
    flags: usize,
    user_stack: usize,
    ptid: usize,
    arg3: usize,
    arg4: usize,
) -> LinuxResult<isize> {
    let tls = arg3;
    let ctid = arg4;
    let curr_task = current();
    let stack = if user_stack == 0 {
        None
    } else {
        Some(user_stack)
    };
    if let Ok(new_task_id) = curr_task
        .task_ext()
        .clone_task(flags, stack, ptid, tls, ctid)
    {
        Ok(new_task_id as isize)
    } else {
        Err(LinuxError::ENOMEM)
    }
}

#[apply(syscall_instrument)]
pub fn sys_wait4(pid: i32, exit_code_ptr: UserPtr<i32>, option: u32) -> LinuxResult<isize> {
    let option_flag = WaitFlags::from_bits(option).unwrap();
    let exit_code_ptr = exit_code_ptr.nullable(UserPtr::get)?;
    loop {
        let answer = unsafe { wait_pid(pid, exit_code_ptr.unwrap_or_else(ptr::null_mut)) };
        match answer {
            Ok(pid) => {
                return Ok(pid as isize);
            }
            Err(status) => match status {
                WaitStatus::NotExist => {
                    return Err(LinuxError::ECHILD);
                }
                WaitStatus::Running => {
                    if option_flag.contains(WaitFlags::WNOHANG) {
                        return Ok(0);
                    } else {
                        yield_now();
                    }
                }
                _ => {
                    panic!("Shouldn't reach here!");
                }
            },
        }
    }
}

#[apply(syscall_instrument)]
pub fn sys_execve(
    path: UserConstPtr<c_char>,
    argv: UserConstPtr<usize>,
    envp: UserConstPtr<usize>,
) -> LinuxResult<isize> {
    let path_str = path.get_as_str()?;

    let args = argv
        .get_as_null_terminated()?
        .iter()
        .map(|arg| {
            UserConstPtr::<c_char>::from(*arg)
                .get_as_str()
                .map(Into::into)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let envs = envp
        .get_as_null_terminated()?
        .iter()
        .map(|env| {
            UserConstPtr::<c_char>::from(*env)
                .get_as_str()
                .map(Into::into)
        })
        .collect::<Result<Vec<_>, _>>()?;

    info!(
        "execve: path: {:?}, args: {:?}, envs: {:?}",
        path_str, args, envs
    );

    if let Err(e) = exec(path_str, &args, &envs) {
        error!("Failed to exec: {:?}", e);
        return Err::<isize, _>(LinuxError::ENOSYS);
    }

    unreachable!("execve should never return");
}

#[apply(syscall_instrument)]
pub fn sys_gettid() -> LinuxResult<isize> {
    warn!("sys_gettid: not implemented");
    Ok(axtask::current().task_ext().proc_id as _)
}

#[apply(syscall_instrument)]
pub fn sys_futex(
    _uaddr: UserPtr<i32>,
    _futex_op: i32,
    _val: i32,
    _timeout: UserConstPtr<api::ctypes::timespec>,
    _uaddr2: UserPtr<i32>,
    _val3: i32,
) -> LinuxResult<isize> {
    warn!("sys_futex: not implemented");
    Ok(0)
}

#[apply(syscall_instrument)]
pub fn sys_set_robust_list(
    _head: UserPtr<c_void>,
    _len: usize,
) -> LinuxResult<isize> {
    warn!("sys_set_robust_list: not implemented");
    Ok(0)
}


// #[repr(C)]
// #[derive(Clone, Copy, Debug)]
// // file descriptor used for poll
// pub struct PollFd {
//     /// 等待的fd
//     pub fd: i32,
//     /// 等待的事件
//     // pub events: PollEvents,
//     /// 返回的事件
//     // pub revents: PollEvents,
// }

// #[apply(syscall_instrument)]
// pub fn sys_poll(
//     fds: UserPtr<u32>,
//     nfds: u32,
//     timeout: i32,
// ) -> LinuxResult<isize> {
//     // warn!("sys_poll: not implemented");
//     // Ok(0)
//     let process = current();

//     // let start: VirtAddr = (fds as usize).into();
//     // let end = start + nfds * core::mem::size_of::<PollFd>();
//     // if process.manual_alloc_range_for_lazy(start, end).is_err() {
//     //     return Err(LinuxError::EFAULT);
//     // }

//     let mut fds: Vec<PollFd> = Vec::new();

//     for i in 0..nfds {
//         unsafe {
//             fds.push(*(fds.add(i)));
//         }
//     }
//     let deadline = (!timeout.is_negative()).then(|| wall_time() + Duration::from_millis(timeout as u64));
//     let deadline = unsafe { timeout.as_ref().map(|t| wall_time() + (*t).into()) };
//     let expire_time = current_ticks() as usize + crate::TimeVal::from_micro(timeout).turn_to_ticks() as usize;

//     let (set, ret_fds) = ppoll(fds, expire_time);
//     // 将得到的fd存储到原先的指针中
//     for (i, fd) in ret_fds.iter().enumerate() {
//         unsafe {
//             *(fds.add(i)) = *fd;
//         }
//     }
//     Ok(set)
// }

// #[apply(syscall_instrument)]
// pub fn sys_ppoll(
//     ufds: UserPtr<PollFd>,
//     nfds: u32,
//     tmo_p: UserConstPtr<api::ctypes::timespec>,
//     sigmask: UserConstPtr<api::ctypes::sigset_t>,
// ) -> LinuxResult<isize> {
//     // let ufds = args[0] as *mut PollFd;
//     // let nfds = args[1];
//     let timeout = args[2] as *const TimeSecs;
//     // let _mask = args[3];
//     let process = current_process();

//     let start: VirtAddr = (ufds as usize).into();
//     let end = start + nfds * core::mem::size_of::<PollFd>();
//     if process.manual_alloc_range_for_lazy(start, end).is_err() {
//         return Err(SyscallError::EFAULT);
//     }

//     let mut fds: Vec<PollFd> = Vec::new();

//     for i in 0..nfds {
//         unsafe {
//             fds.push(*(ufds.add(i)));
//         }
//     }

//     let expire_time = if timeout as usize != 0 {
//         if process.manual_alloc_type_for_lazy(timeout).is_err() {
//             return Err(SyscallError::EFAULT);
//         }
//         current_ticks() as usize + unsafe { (*timeout).get_ticks() }
//     } else {
//         usize::MAX
//     };

//     let (set, ret_fds) = ppoll(fds, expire_time);
//     // 将得到的fd存储到原先的指针中
//     for (i, fd) in ret_fds.iter().enumerate() {
//         unsafe {
//             *(ufds.add(i)) = *fd;
//         }
//     }
//     Ok(set)
// }

// fn ppoll(mut fds: Vec<PollFd>, expire_time: usize) -> (isize, Vec<PollFd>) {
//     loop { // 满足事件要求而被触发的事件描述符数量
//         let mut set: isize = 0;
//         let process = current_process();
//         for poll_fd in &mut fds {
//             let fd_table = process.fd_manager.fd_table.lock();
//             if let Some(file) = fd_table[poll_fd.fd as usize].as_ref() {
//                 poll_fd.revents = PollEvents::empty();
//                 // let file = file.lock();
//                 if file.in_exceptional_conditions() {
//                     poll_fd.revents |= PollEvents::ERR;
//                 }
//                 if file.is_hang_up() {
//                     poll_fd.revents |= PollEvents::HUP;
//                 }
//                 if poll_fd.events.contains(PollEvents::IN) && file.ready_to_read() {
//                     poll_fd.revents |= PollEvents::IN;
//                 }
//                 if poll_fd.events.contains(PollEvents::OUT) && file.ready_to_write() {
//                     poll_fd.revents |= PollEvents::OUT;
//                 }
//                 // 如果返回事件不为空,代表有响应
//                 if !poll_fd.revents.is_empty() {
//                     set += 1;
//                 }
//             } else {
//                 // 不存在也是一种响应
//                 poll_fd.revents = PollEvents::ERR;
//                 set += 1;
//             }
//         }
//         if set > 0 {
//             return (set, fds);
//         }
//         if current_ticks() as usize > expire_time {
//             // 过期了,直接返回
//             return (0, fds);
//         }
//         yield_now_task();

//         if process.have_signals().is_some() {
//             // 有信号,此时停止处理,直接返回
//             return (0, fds);
//         }
//     }
// }
