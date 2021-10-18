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

/// <!-- description -->
///   @brief This syscall tells the microkernel to output reg0 and reg1 to
///     the console device the microkernel is currently using for
///     debugging.
///
/// <!-- inputs/outputs -->
///   @param val1 The first value to output to the microkernel's console
///   @param val2 The second value to output to the microkernel's console
///
pub fn bf_debug_op_out(val1: bsl::SafeU64, val2: bsl::SafeU64) {
    unsafe {
        crate::bf_debug_op_out_impl(val1.get(), val2.get());
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the state of a
///     VM to the console device the microkernel is currently using for
///     debugging.
///
/// <!-- inputs/outputs -->
///   @param vmid The ID of the VM whose state is to be outputted
///
pub fn bf_debug_op_dump_vm(vmid: bsl::SafeU16) {
    unsafe {
        crate::bf_debug_op_dump_vm_impl(vmid.get());
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the state of a
///     VP to the console device the microkernel is currently using for
///     debugging.
///
/// <!-- inputs/outputs -->
///   @param vpid The ID of the VP whose state is to be outputted
///
pub fn bf_debug_op_dump_vp(vpid: bsl::SafeU16) {
    unsafe {
        crate::bf_debug_op_dump_vp_impl(vpid.get());
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the state of a
///     VS to the console device the microkernel is currently using for
///     debugging.
///
/// <!-- inputs/outputs -->
///   @param vsid The ID of the VS whose state is to be outputted
///
pub fn bf_debug_op_dump_vs(vsid: bsl::SafeU16) {
    unsafe {
        crate::bf_debug_op_dump_vs_impl(vsid.get());
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
pub fn bf_debug_op_dump_vmexit_log(ppid: bsl::SafeU16) {
    unsafe {
        crate::bf_debug_op_dump_vmexit_log_impl(ppid.get());
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output a provided
///     character to the microkernel's console.
///
/// <!-- inputs/outputs -->
///   @param c The character to output
///
pub fn bf_debug_op_write_c(c: bsl::CharT) {
    unsafe {
        crate::bf_debug_op_write_c_impl(c);
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output a provided
///     string to the microkernel's console.
///
/// <!-- inputs/outputs -->
///   @param str The virtual address of a null terminated string to output
///
pub fn bf_debug_op_write_str(str: bsl::CStrT, len: u64) {
    unsafe {
        crate::bf_debug_op_write_str_impl(str, len);
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output an extension's
///     state to the console device the microkernel is currently using
///     for debugging.
///
/// <!-- inputs/outputs -->
///   @param extid The EXTID of the extensions's state to output
///
pub fn bf_debug_op_dump_ext(extid: bsl::SafeU16) {
    unsafe {
        crate::bf_debug_op_dump_ext_impl(extid.get());
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the page pool's
///     stats to the console device the microkernel is currently using
///     for debugging.
///
pub fn bf_debug_op_dump_page_pool() {
    unsafe {
        crate::bf_debug_op_dump_page_pool_impl();
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel to output the huge pool's
///     stats to the console device the microkernel is currently using
///     for debugging.
///
pub fn bf_debug_op_dump_huge_pool() {
    unsafe {
        crate::bf_debug_op_dump_huge_pool_impl();
    }
}
