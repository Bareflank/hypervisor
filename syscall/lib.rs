// @copyright
// Copyright (C) 2020 Assured Information Security, Inc.
//
// @copyright
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// @copyright
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// @copyright
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![no_std]

#[macro_use]
extern crate bsl;

#[path = "constants.rs"]
#[doc(hidden)]
pub mod constants;
pub use constants::*;

#[path = "include/bf_types.rs"]
#[doc(hidden)]
pub mod bf_types;
pub use bf_types::*;

#[path = "include/bf_constants.rs"]
#[doc(hidden)]
pub mod bf_constants;
pub use bf_constants::*;

#[cfg(feature = "AuthenticAMD")]
#[path = "include/x64/amd/bf_reg_t.rs"]
#[doc(hidden)]
pub mod bf_reg_t;

#[cfg(feature = "GenuineIntel")]
#[path = "include/x64/intel/bf_reg_t.rs"]
#[doc(hidden)]
pub mod bf_reg_t;

pub use bf_reg_t::*;

#[path = "src/bf_syscall_impl.rs"]
#[doc(hidden)]
pub mod bf_syscall_impl;
pub use bf_syscall_impl::*;

macro_rules! print_thread_id {
    ($($arg:tt)*) => {
        unsafe {
            print!(
                " [{}{:04x}{}:{}{:04x}{}:{}{:04x}{}:{}{:04x}{}:{}{:04x}{}:{}US{}]",
                bsl::cyn,
                crate::bf_tls_extid_impl(),
                bsl::rst,
                bsl::cyn,
                crate::bf_tls_vmid_impl(),
                bsl::rst,
                bsl::cyn,
                crate::bf_tls_vpid_impl(),
                bsl::rst,
                bsl::cyn,
                crate::bf_tls_vsid_impl(),
                bsl::rst,
                bsl::cyn,
                crate::bf_tls_ppid_impl(),
                bsl::rst,
                bsl::blu,
                bsl::rst
            );
        }
    };
}

#[path = "src/bf_control_ops.rs"]
#[doc(hidden)]
pub mod bf_control_ops;
pub use bf_control_ops::*;

#[path = "src/bf_debug_ops.rs"]
#[doc(hidden)]
pub mod bf_debug_ops;
pub use bf_debug_ops::*;

#[path = "src/bf_syscall_t.rs"]
#[doc(hidden)]
pub mod bf_syscall_t;
pub use bf_syscall_t::*;
