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
///   @brief This syscall tells the microkernel to exit the execution
///     of an extension, providing a means to fast fail.
///
pub fn bf_control_op_exit() {
    unsafe {
        crate::bf_syscall_impl::bf_control_op_exit_impl();
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel that the extension would
///     like to wait for a callback. This is a blocking syscall that never
///     returns and should be used to return from the successful execution
///     of the _start function.
///
pub fn bf_control_op_wait() {
    unsafe {
        crate::bf_syscall_impl::bf_control_op_wait_impl();
    }
}

/// <!-- description -->
///   @brief This syscall tells the microkernel that the extension would
///     like to try again from a fast fail callback. This syscall is a
///     blocking syscall that never returns and should be used to return
///     from the fail_entry function.
///
pub fn bf_control_op_again() {
    unsafe {
        crate::bf_syscall_impl::bf_control_op_again_impl();
    }
}
