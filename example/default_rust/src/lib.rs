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

// -----------------------------------------------------------------------------
// Includes
// -----------------------------------------------------------------------------

#![no_std]
#![feature(thread_local)]
#![feature(panic_info_message)]

#[macro_use]
extern crate bsl;
extern crate syscall;

macro_rules! print_thread_id {
    ($($arg:tt)*) => {
        unsafe {
            print!(
                " [{}{:04x}{}:{}{:04x}{}:{}{:04x}{}:{}{:04x}{}:{}{:04x}{}:{}US{}]",
                bsl::cyn,
                syscall::bf_tls_extid_impl(),
                bsl::rst,
                bsl::cyn,
                syscall::bf_tls_vmid_impl(),
                bsl::rst,
                bsl::cyn,
                syscall::bf_tls_vpid_impl(),
                bsl::rst,
                bsl::cyn,
                syscall::bf_tls_vsid_impl(),
                bsl::rst,
                bsl::cyn,
                syscall::bf_tls_ppid_impl(),
                bsl::rst,
                bsl::blu,
                bsl::rst
            );
        }
    };
}

#[path = "../include/allocated_status_t.rs"]
#[doc(hidden)]
pub mod allocated_status_t;
pub use allocated_status_t::*;

#[cfg(feature = "AuthenticAMD")]
#[path = "x64/amd/gs_t.rs"]
#[doc(hidden)]
pub mod gs_t;

#[cfg(feature = "GenuineIntel")]
#[path = "x64/intel/gs_t.rs"]
#[doc(hidden)]
pub mod gs_t;

#[cfg(feature = "AuthenticAMD")]
#[path = "x64/amd/tls_t.rs"]
#[doc(hidden)]
pub mod tls_t;

#[cfg(feature = "GenuineIntel")]
#[path = "x64/intel/tls_t.rs"]
#[doc(hidden)]
pub mod tls_t;

#[cfg(feature = "AuthenticAMD")]
#[path = "x64/intrinsic_t.rs"]
#[doc(hidden)]
pub mod intrinsic_t;

#[cfg(feature = "GenuineIntel")]
#[path = "x64/intrinsic_t.rs"]
#[doc(hidden)]
pub mod intrinsic_t;

pub use gs_t::*;
pub use intrinsic_t::*;
pub use tls_t::*;

#[cfg(feature = "AuthenticAMD")]
#[path = "x64/amd/gs_initialize.rs"]
#[doc(hidden)]
pub mod gs_initialize;

#[cfg(feature = "GenuineIntel")]
#[path = "x64/intel/gs_initialize.rs"]
#[doc(hidden)]
pub mod gs_initialize;

#[cfg(feature = "AuthenticAMD")]
#[path = "x64/amd/tls_initialize.rs"]
#[doc(hidden)]
pub mod tls_initialize;

#[cfg(feature = "GenuineIntel")]
#[path = "x64/intel/tls_initialize.rs"]
#[doc(hidden)]
pub mod tls_initialize;

pub use gs_initialize::*;
pub use tls_initialize::*;

#[path = "vp_t.rs"]
#[doc(hidden)]
pub mod vp_t;
pub use vp_t::*;

#[path = "vp_pool_t.rs"]
#[doc(hidden)]
pub mod vp_pool_t;
pub use vp_pool_t::*;

#[cfg(feature = "AuthenticAMD")]
#[path = "x64/amd/vs_t.rs"]
#[doc(hidden)]
pub mod vs_t;

#[cfg(feature = "GenuineIntel")]
#[path = "x64/intel/vs_t.rs"]
#[doc(hidden)]
pub mod vs_t;

pub use vs_t::*;

#[path = "vs_pool_t.rs"]
#[doc(hidden)]
pub mod vs_pool_t;
pub use vs_pool_t::*;

#[path = "dispatch_bootstrap.rs"]
#[doc(hidden)]
pub mod dispatch_bootstrap;
pub use dispatch_bootstrap::*;

#[cfg(feature = "AuthenticAMD")]
#[path = "x64/amd/dispatch_vmexit.rs"]
#[doc(hidden)]
pub mod dispatch_vmexit;

#[cfg(feature = "GenuineIntel")]
#[path = "x64/intel/dispatch_vmexit.rs"]
#[doc(hidden)]
pub mod dispatch_vmexit;

pub use dispatch_vmexit::*;

#[path = "dispatch_fail.rs"]
#[doc(hidden)]
pub mod dispatch_fail;
pub use dispatch_fail::*;

// -----------------------------------------------------------------------------
// Globals
// -----------------------------------------------------------------------------

// TODO:
// - The use of globals requires the use of unsafe, which is not good. We
//   should find a way to ensure that we can have global storage for all of
//   entry points, but without the need for unsafe.
//

static mut G_SYS: syscall::BfSyscallT = syscall::BfSyscallT::new();
static mut G_INTRINSIC: crate::IntrinsicT = crate::IntrinsicT::new();

static mut G_VP_POOL: crate::VpPoolT = crate::VpPoolT::new();
static mut G_VS_POOL: crate::VsPoolT = crate::VsPoolT::new();

static mut G_GS: crate::GsT = crate::GsT::new();

#[thread_local]
static mut G_TLS: crate::TlsT = crate::TlsT::new();

// -----------------------------------------------------------------------------
// Entry Functions
// -----------------------------------------------------------------------------

#[no_mangle]
fn putchar(c: u8) {
    unsafe {
        syscall::bf_debug_op_write_c_impl(c);
    }
}

#[no_mangle]
fn bootstrap_entry(ppid: u16) {
    let ret: bsl::ErrcType;

    // NOTE:
    // - Call into the bootstrap handler. This entry point serves as a
    //   trampoline between C and C++. Specifically, the microkernel
    //   cannot call a member function directly, and can only call
    //   a C style function.
    //

    unsafe {
        ret = dispatch_bootstrap(
            &G_GS,
            &mut G_TLS,
            &mut G_SYS,
            &G_INTRINSIC,
            &mut G_VP_POOL,
            &mut G_VS_POOL,
            bsl::to_u16(ppid),
        );
    }

    if !ret {
        print_v!("{}", bsl::here());
        syscall::bf_control_op_exit();
        return;
    }

    // NOTE:
    // - This code should never be reached. The bootstrap handler should
    //   always call one of the "run" ABIs to return back to the
    //   microkernel when a bootstrap is finished. If this is called, it
    //   is because the bootstrap handler returned with an error.
    //

    syscall::bf_control_op_exit();
}

#[no_mangle]
fn vmexit_entry(vsid: u16, exit_reason: u64) {
    let ret: bsl::ErrcType;

    // NOTE:
    // - Call into the bootstrap handler. This entry point serves as a
    //   trampoline between C and C++. Specifically, the microkernel
    //   cannot call a member function directly, and can only call
    //   a C style function.
    //

    unsafe {
        ret = dispatch_vmexit(
            &G_GS,
            &G_TLS,
            &mut G_SYS,
            &G_INTRINSIC,
            &G_VP_POOL,
            &G_VS_POOL,
            bsl::to_u16(vsid),
            bsl::to_u64(exit_reason),
        );
    }

    if !ret {
        print_v!("{}", bsl::here());
        syscall::bf_control_op_exit();
        return;
    }

    // NOTE:
    // - This code should never be reached. The VMExit handler should
    //   always call one of the "run" ABIs to return back to the
    //   microkernel when a VMExit is finished. If this is called, it
    //   is because the VMExit handler returned with an error.
    //

    syscall::bf_control_op_exit();
}

#[no_mangle]
fn fail_entry(errc: u64, addr: u64) {
    let ret: bsl::ErrcType;

    // NOTE:
    // - Call into the fast fail handler. This entry point serves as a
    //   trampoline between C and C++. Specifically, the microkernel
    //   cannot call a member function directly, and can only call
    //   a C style function.
    //

    unsafe {
        ret = dispatch_fail(
            &G_GS,
            &G_TLS,
            &G_SYS,
            &G_INTRINSIC,
            &G_VP_POOL,
            &G_VS_POOL,
            bsl::to_u64(errc),
            bsl::to_u64(addr),
        );
    }

    if !ret {
        print_v!("{}", bsl::here());
        syscall::bf_control_op_exit();
        return;
    }

    // NOTE:
    // - This code should never be reached. The fast fail handler should
    //   always call one of the "run" ABIs to return back to the
    //   microkernel when a fast fail is finished. If this is called, it
    //   is because the fast fail handler returned with an error.
    //

    syscall::bf_control_op_exit();
}

#[no_mangle]
pub fn ext_main_entry(version: u32) -> i32 {
    let mut ret: bsl::ErrcType;

    unsafe {
        ret = G_SYS.initialize(
            bsl::to_u32(version),
            bootstrap_entry as bsl::CPtrT,
            vmexit_entry as bsl::CPtrT,
            fail_entry as bsl::CPtrT,
        );
    }
    if !ret {
        print_v!("{}", bsl::here());
        syscall::bf_control_op_exit();
        return bsl::exit_failure;
    }

    unsafe {
        ret = gs_initialize(&mut G_GS, &G_SYS, &G_INTRINSIC);
    }
    if !ret {
        print_v!("{}", bsl::here());
        syscall::bf_control_op_exit();
        return bsl::exit_failure;
    }

    unsafe {
        G_VP_POOL.initialize(&G_GS, &G_TLS, &G_SYS, &G_INTRINSIC);
        G_VS_POOL.initialize(&G_GS, &G_TLS, &G_SYS, &G_INTRINSIC);
    }

    syscall::bf_control_op_wait();
    return bsl::exit_success;
}

#[panic_handler]
pub fn panic_implementation(info: &core::panic::PanicInfo<'_>) -> ! {
    match info.message() {
        Some(s) => print!("{}", s),
        None => print!("unknown panic occurred\n"),
    }

    syscall::bf_control_op_exit();
    loop {}
}
