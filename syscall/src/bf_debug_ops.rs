/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
use crate::types::BfCharT;
use crate::types::BfCstrT;

/// <!-- description -->
///   @brief This syscall tells the microkernel to output reg0 and reg1 to
///     the console device the microkernel is currently using for
///     debugging.
///
/// <!-- inputs/outputs -->
///   @param val1 The first value to output to the microkernel's console
///   @param val2 The second value to output to the microkernel's console
///
pub fn bf_debug_op_out(val1: u64, val2: u64) {
    unsafe {
        crate::bf_syscall_impl::bf_debug_op_out_impl(val1, val2);
    }
}

#[cfg(test)]
mod test_bf_debug_op_out {
    static mut VAL1: u64 = 0;
    static mut VAL2: u64 = 0;

    #[no_mangle]
    fn bf_debug_op_out_impl(val1: u64, val2: u64) {
        unsafe {
            VAL1 = val1;
            VAL2 = val2;
        }
    }

    #[test]
    fn test_bf_debug_op_out() {
        super::bf_debug_op_out(23, 42);
        unsafe {
            assert!(VAL1 == 23);
            assert!(VAL2 == 42);
        }
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the state of a
///     VM to the console device the microkernel is currently using for
///     debugging.
///
/// <!-- inputs/outputs -->
///   @param vmid The VMID of the VM whose state is to be outputted
///
pub fn bf_debug_op_dump_vm(vmid: u16) {
    unsafe {
        crate::bf_syscall_impl::bf_debug_op_dump_vm_impl(vmid);
    }
}

#[cfg(test)]
mod test_bf_debug_op_dump_vm {
    static mut ID: u64 = 0;

    #[no_mangle]
    fn bf_debug_op_dump_vm_impl(vmid: u64) {
        unsafe {
            ID = vmid;
        }
    }

    #[test]
    fn test_bf_debug_op_dump_vm() {
        super::bf_debug_op_dump_vm(42);
        unsafe {
            assert!(ID == 42);
        }
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the state of a
///     VP to the console device the microkernel is currently using for
///     debugging.
///
/// <!-- inputs/outputs -->
///   @param vpid The VPID of the VP whose state is to be outputted
///
pub fn bf_debug_op_dump_vp(vpid: u16) {
    unsafe {
        crate::bf_syscall_impl::bf_debug_op_dump_vp_impl(vpid);
    }
}

#[cfg(test)]
mod test_bf_debug_op_dump_vp {
    static mut ID: u64 = 0;

    #[no_mangle]
    fn bf_debug_op_dump_vp_impl(vpid: u64) {
        unsafe {
            ID = vpid;
        }
    }

    #[test]
    fn test_bf_debug_op_dump_vp() {
        super::bf_debug_op_dump_vp(42);
        unsafe {
            assert!(ID == 42);
        }
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the state of a
///     VS to the console device the microkernel is currently using for
///     debugging.
///
/// <!-- inputs/outputs -->
///   @param vsid The VSID of the VS whose state is to be outputted
///
pub fn bf_debug_op_dump_vs(vsid: u16) {
    unsafe {
        crate::bf_syscall_impl::bf_debug_op_dump_vs_impl(vsid);
    }
}

#[cfg(test)]
mod test_bf_debug_op_dump_vs {
    static mut ID: u64 = 0;

    #[no_mangle]
    fn bf_debug_op_dump_vs_impl(vsid: u64) {
        unsafe {
            ID = vsid;
        }
    }

    #[test]
    fn test_bf_debug_op_dump_vs() {
        super::bf_debug_op_dump_vs(42);
        unsafe {
            assert!(ID == 42);
        }
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the VMExit log.
///     The VMExit log is a chronological log of the "X" number of exits
///     that have occurred on a specific physical processor.
///
/// <!-- inputs/outputs -->
///   @param ppid The PPID of the PP to dump the log from
///
pub fn bf_debug_op_dump_vmexit_log(ppid: u16) {
    unsafe {
        crate::bf_syscall_impl::bf_debug_op_dump_vmexit_log_impl(ppid);
    }
}

#[cfg(test)]
mod test_bf_debug_op_dump_vmexit_log {
    static mut ID: u64 = 0;

    #[no_mangle]
    fn bf_debug_op_dump_vmexit_log_impl(ppid: u64) {
        unsafe {
            ID = ppid;
        }
    }

    #[test]
    fn test_bf_debug_op_dump_vmexit_log() {
        super::bf_debug_op_dump_vmexit_log(42);
        unsafe {
            assert!(ID == 42);
        }
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output a provided
///     character to the microkernel's console.
///
/// <!-- inputs/outputs -->
///   @param c The character to output
///
pub fn bf_debug_op_write_c(c: BfCharT) {
    unsafe {
        crate::bf_syscall_impl::bf_debug_op_write_c_impl(c);
    }
}

#[cfg(test)]
mod test_bf_debug_op_write_c {
    static mut C: super::BfCharT = 0;

    #[no_mangle]
    fn bf_debug_op_write_c_impl(c: super::BfCharT) {
        unsafe {
            C = c;
        }
    }

    #[test]
    fn test_bf_debug_op_write_c() {
        super::bf_debug_op_write_c(42);
        unsafe {
            assert!(C == 42);
        }
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output a provided
///     string to the microkernel's console.
///
/// <!-- inputs/outputs -->
///   @param str The virtual address of a null terminated string to output
///
pub fn bf_debug_op_write_str(str: BfCstrT) {
    unsafe {
        crate::bf_syscall_impl::bf_debug_op_write_str_impl(str);
    }
}

#[cfg(test)]
mod test_bf_debug_op_write_str {
    // TODO
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output an extension's
///     state to the console device the microkernel is currently using
///     for debugging.
///
/// <!-- inputs/outputs -->
///   @param extid The EXTID of the extensions's state to output
///
pub fn bf_debug_op_dump_ext(extid: u16) {
    unsafe {
        crate::bf_syscall_impl::bf_debug_op_dump_ext_impl(extid);
    }
}

#[cfg(test)]
mod test_bf_debug_op_dump_ext {
    static mut ID: u64 = 0;

    #[no_mangle]
    fn bf_debug_op_dump_ext_impl(extid: u64) {
        unsafe {
            ID = extid;
        }
    }

    #[test]
    fn test_bf_debug_op_dump_ext() {
        super::bf_debug_op_dump_ext(42);
        unsafe {
            assert!(ID == 42);
        }
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the page pool's
///     stats to the console device the microkernel is currently using
///     for debugging.
///
pub fn bf_debug_op_dump_page_pool() {
    unsafe {
        crate::bf_syscall_impl::bf_debug_op_dump_page_pool_impl();
    }
}

#[cfg(test)]
mod test_bf_debug_op_dump_page_pool {
    static mut EXECUTED: bool = false;

    #[no_mangle]
    fn bf_debug_op_dump_page_pool_impl() {
        unsafe {
            EXECUTED = true;
        }
    }

    #[test]
    fn test_bf_debug_op_dump_page_pool() {
        super::bf_debug_op_dump_page_pool();
        unsafe {
            assert!(EXECUTED);
        }
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the huge pool's
///     stats to the console device the microkernel is currently using
///     for debugging.
///
pub fn bf_debug_op_dump_huge_pool() {
    unsafe {
        crate::bf_syscall_impl::bf_debug_op_dump_huge_pool_impl();
    }
}

#[cfg(test)]
mod test_bf_debug_op_dump_huge_pool {
    static mut EXECUTED: bool = false;

    #[no_mangle]
    fn bf_debug_op_dump_huge_pool_impl() {
        unsafe {
            EXECUTED = true;
        }
    }

    #[test]
    fn test_bf_debug_op_dump_huge_pool() {
        super::bf_debug_op_dump_huge_pool();
        unsafe {
            assert!(EXECUTED);
        }
    }
}
