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

#ifndef MOCK_TLS_T_HPP
#define MOCK_TLS_T_HPP

#include <state_save_t.hpp>

#include <bsl/cstdint.hpp>
#include <bsl/errc_type.hpp>

namespace mk
{
    /// @struct mk::tls_t
    ///
    /// <!-- description -->
    ///   @brief Implements a mocked version of tls_t.
    ///
    struct tls_t final
    {
        /// --------------------------------------------------------------------
        /// Extension State
        /// --------------------------------------------------------------------

        /// @brief RAX, stores the extension's syscall
        bsl::uintmx ext_syscall;
        /// @brief RDI, stores the value of REG0 for the extension
        bsl::uintmx ext_reg0;
        /// @brief RSI, stores the value of REG1 for the extension
        bsl::uintmx ext_reg1;
        /// @brief RDX, stores the value of REG2 for the extension
        bsl::uintmx ext_reg2;
        /// @brief R10, stores the value of REG3 for the extension
        bsl::uintmx ext_reg3;
        /// @brief R8, stores the value of REG4 for the extension
        bsl::uintmx ext_reg4;
        /// @brief R9, stores the value of REG5 for the extension
        bsl::uintmx ext_reg5;

        /// --------------------------------------------------------------------
        /// ESR State
        /// --------------------------------------------------------------------

        /// @brief stores the value of ip for the ESR
        bsl::uintmx esr_ip;
        /// @brief stores the value of sp for the ESR
        bsl::uintmx esr_sp;

        /// @brief stores the value of the ESR vector
        bsl::uintmx esr_vector;
        /// @brief stores the value of the ESR error code
        bsl::uintmx esr_error_code;

        /// @brief stores the value of a page fault address for the ESR
        bsl::uintmx esr_pf_addr;

        /// --------------------------------------------------------------------
        /// Fast Fail Information
        /// --------------------------------------------------------------------

        /// @brief stores the current fast fail address
        bsl::uintmx current_fast_fail_ip;
        /// @brief stores the current fast fail stack
        bsl::uintmx current_fast_fail_sp;

        /// @brief stores the mk_main fast fail address
        bsl::uintmx mk_main_fast_fail_ip;
        /// @brief stores the mk_main fast fail stack
        bsl::uintmx mk_main_fast_fail_sp;

        /// @brief stores the call_ext fast fail address
        bsl::uintmx call_ext_fast_fail_ip;
        /// @brief stores the call_ext fast fail stack
        bsl::uintmx call_ext_fast_fail_sp;

        /// @brief stores the dispatch_syscall fast fail address
        bsl::uintmx dispatch_syscall_fast_fail_ip;
        /// @brief stores the dispatch_syscall fast fail stack
        bsl::uintmx dispatch_syscall_fast_fail_sp;

        /// @brief stores the vmexit loop address
        bsl::uintmx vmexit_loop_ip;
        /// @brief stores the vmexit loop stack
        bsl::uintmx vmexit_loop_sp;

        /// --------------------------------------------------------------------
        /// Context Information
        /// --------------------------------------------------------------------

        /// @brief stores the virtual address of this TLS block
        tls_t *self;

        /// @brief stores the currently active VMID
        bsl::uint16 ppid;
        /// @brief stores the total number of online PPs
        bsl::uint16 online_pps;
        /// @brief reserved
        bsl::uint16 reserved_padding0;
        /// @brief reserved
        bsl::uint16 reserved_padding1;

        /// @brief stores the currently active extension
        void *ext;
        /// @brief stores the extension registered for VMExits
        void *ext_vmexit;
        /// @brief stores the extension registered for fast fail events
        void *ext_fail;

        /// @brief stores the loader provided state for the microkernel
        loader::state_save_t *mk_state;
        /// @brief stores the loader provided state for the root VP
        loader::state_save_t *root_vp_state;

        /// @brief stores the currently active extension ID
        bsl::uint16 active_extid;
        /// @brief stores the currently active VMID
        bsl::uint16 active_vmid;
        /// @brief stores the currently active VPID
        bsl::uint16 active_vpid;
        /// @brief stores the currently active VSID
        bsl::uint16 active_vsid;

        /// @brief stores the sp used by extensions for callbacks
        bsl::uintmx sp;
        /// @brief stores the tps used by extensions for callbacks
        bsl::uintmx tp;

        /// @brief used to store a return address for unsafe ops
        bsl::uintmx unsafe_rip;

        /// @brief reserved
        bsl::uintmx reserved_padding2;
        /// @brief reserved
        bsl::uintmx reserved_padding3;

        /// @brief stores whether or not the first launch succeeded
        bsl::uintmx first_launch_succeeded;

        /// @brief stores the currently active root page table
        void *active_rpt;

        /// --------------------------------------------------------------------
        /// Failure Handling
        /// --------------------------------------------------------------------

        /// @brief stores a whether or not state is changing
        bool state_reversal_required;

        /// @brief stores the syscall return status
        bsl::uintmx syscall_ret_status;

        /// @brief logs an extid for state reversal if needed
        bsl::uint16 log_extid;
        /// @brief logs a vmid for state reversal if needed
        bsl::uint16 log_vmid;
        /// @brief logs a vpid for state reversal if needed
        bsl::uint16 log_vpid;
        /// @brief logs a vsid for state reversal if needed
        bsl::uint16 log_vsid;

        /// @brief logs an ext for state reversal if needed
        void *log_ext;
        /// @brief logs a vm for state reversal if needed
        void *log_vm;
        /// @brief logs a vp for state reversal if needed
        void *log_vp;
        /// @brief logs a vs for state reversal if needed
        void *log_vs;

        /// --------------------------------------------------------------------
        /// Unit Test Specific
        /// --------------------------------------------------------------------

        /// @brief used by some of the unit tests
        bsl::errc_type test_ret;
    };
}

#endif
