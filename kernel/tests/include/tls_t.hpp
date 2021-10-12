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

#ifndef TLS_T_HPP
#define TLS_T_HPP

#include <basic_entries_t.hpp>
#include <l0e_t.hpp>
#include <l1e_t.hpp>
#include <l2e_t.hpp>
#include <l3e_t.hpp>
#include <state_save_t.hpp>

#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// @brief ext_t prototype
    class ext_t;

    /// <!-- description -->
    ///   @brief Defines the extension's mocked version of tls_t, used for
    ///     unit testing. Specifically, this version only contains portions
    ///     that are common for all architectures.
    ///
    struct tls_t final
    {
        /// --------------------------------------------------------------------
        /// Extension State
        /// --------------------------------------------------------------------

        /// @brief stores the extension's syscall/return
        bsl::uint64 ext_syscall;
        /// @brief stores the value of REG0 for the extension
        bsl::uint64 ext_reg0;
        /// @brief stores the value of REG1 for the extension
        bsl::uint64 ext_reg1;
        /// @brief stores the value of REG2 for the extension
        bsl::uint64 ext_reg2;
        /// @brief stores the value of REG3 for the extension
        bsl::uint64 ext_reg3;
        /// @brief stores the value of REG4 for the extension
        bsl::uint64 ext_reg4;
        /// @brief stores the value of REG5 for the extension
        bsl::uint64 ext_reg5;
        /// @brief stores the extension's stack pointer
        bsl::uint64 ext_sp;

        /// --------------------------------------------------------------------
        /// ESR State
        /// --------------------------------------------------------------------

        /// @brief stores the value of rip for the ESR
        bsl::uint64 esr_ip;
        /// @brief stores the value of rsp for the ESR
        bsl::uint64 esr_sp;

        /// @brief stores the value of the ESR vector
        bsl::uint64 esr_vector;
        /// @brief stores the value of the ESR error code
        bsl::uint64 esr_error_code;

        /// @brief stores the value of cr2 for the ESR
        bsl::uint64 esr_pf_addr;

        /// --------------------------------------------------------------------
        /// Fail Handler States
        /// --------------------------------------------------------------------

        /// @brief stores the value of rsp for the MK
        bsl::uint64 mk_sp;
        /// @brief stores the value of rsp for the MK when calling fail
        bsl::uint64 mk_handling_esr;

        /// @brief stores the value of rsp for the MK when failing
        bsl::uint64 mk_fail_sp;
        /// @brief stores the fail sp used by extensions for callbacks
        bsl::uint64 ext_fail_sp;

        /// --------------------------------------------------------------------
        /// Context Information
        /// --------------------------------------------------------------------

        /// @brief stores the currently active VMID
        bsl::uint16 ppid;
        /// @brief stores the total number of online PPs
        bsl::uint16 online_pps;
        /// @brief stores the VSID whose VMCS is loaded on Intel
        bsl::uint16 loaded_vsid;

        /// @brief stores the currently active extension
        ext_t *ext;
        /// @brief stores the extension registered for VMExits
        ext_t *ext_vmexit;
        /// @brief stores the extension registered for fast fail events
        ext_t *ext_fail;

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
        bsl::uint64 sp;
        /// @brief stores the tps used by extensions for callbacks
        bsl::uint64 tp;

        /// @brief stores whether or not the first launch succeeded
        bsl::uint64 first_launch_succeeded;

        /// @brief stores the currently active root page table
        void *active_rpt;

        /// --------------------------------------------------------------------
        /// Unit Test Only
        /// --------------------------------------------------------------------

        /// @brief API specific return type for tests
        bsl::errc_type test_ret;
        /// @brief API specific return type for tests
        bsl::safe_u64 test_virt;
        /// @brief API specific return type for tests
        bsl::safe_u64 test_phys;
        /// @brief API specific return type for tests
        lib::basic_entries_t<lib::l3e_t, lib::l2e_t, lib::l1e_t, lib::l0e_t> test_ents;
    };
}

#endif
