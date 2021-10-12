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
        /// Microkernel State
        /// --------------------------------------------------------------------

        /// @brief stores the value of rbx for the microkernel (0x000)
        bsl::uint64 mk_rbx;
        /// @brief stores the value of rbp for the microkernel (0x008)
        bsl::uint64 mk_rbp;
        /// @brief stores the value of r12 for the microkernel (0x010)
        bsl::uint64 mk_r12;
        /// @brief stores the value of r13 for the microkernel (0x018)
        bsl::uint64 mk_r13;
        /// @brief stores the value of r14 for the microkernel (0x020)
        bsl::uint64 mk_r14;
        /// @brief stores the value of r15 for the microkernel (0x028)
        bsl::uint64 mk_r15;

        /// --------------------------------------------------------------------
        /// Extension State
        /// --------------------------------------------------------------------

        /// @brief RAX, stores the extension's syscall (0x030)
        bsl::uint64 ext_syscall;
        /// @brief RBX, reserved (0x038)
        bsl::uint64 reserved_rbx;
        /// @brief RCX, reserved (0x040)
        bsl::uint64 reserved_rcx;
        /// @brief RDX, stores the value of REG2 for the extension (0x048)
        bsl::uint64 ext_reg2;
        /// @brief RBP, reserved (0x050)
        bsl::uint64 reserved_rbp;
        /// @brief RSI, stores the value of REG1 for the extension (0x058)
        bsl::uint64 ext_reg1;
        /// @brief RDI, stores the value of REG0 for the extension (0x060)
        bsl::uint64 ext_reg0;
        /// @brief R8, stores the value of REG4 for the extension (0x068)
        bsl::uint64 ext_reg4;
        /// @brief R9, stores the value of REG5 for the extension (0x070)
        bsl::uint64 ext_reg5;
        /// @brief R10, stores the value of REG3 for the extension (0x078)
        bsl::uint64 ext_reg3;
        /// @brief R11, reserved (0x080)
        bsl::uint64 reserved_r11;
        /// @brief R12, reserved (0x088)
        bsl::uint64 reserved_r12;
        /// @brief R13, reserved (0x090)
        bsl::uint64 reserved_r13;
        /// @brief R14, reserved (0x098)
        bsl::uint64 reserved_r14;
        /// @brief R15, reserved (0x0A0)
        bsl::uint64 reserved_r15;
        /// @brief stores the extension's stack pointer (0x0A8)
        bsl::uint64 ext_sp;

        /// --------------------------------------------------------------------
        /// ESR State
        /// --------------------------------------------------------------------

        /// @brief stores the value of rax for the ESR (0x0B0)
        bsl::uint64 esr_rax;
        /// @brief stores the value of rbx for the ESR (0x0B8)
        bsl::uint64 esr_rbx;
        /// @brief stores the value of rcx for the ESR (0x0C0)
        bsl::uint64 esr_rcx;
        /// @brief stores the value of rdx for the ESR (0x0C8)
        bsl::uint64 esr_rdx;
        /// @brief stores the value of rbp for the ESR (0x0D0)
        bsl::uint64 esr_rbp;
        /// @brief stores the value of rsi for the ESR (0x0D8)
        bsl::uint64 esr_rsi;
        /// @brief stores the value of rdi for the ESR (0x0E0)
        bsl::uint64 esr_rdi;
        /// @brief stores the value of r8 for the ESR (0x0E8)
        bsl::uint64 esr_r8;
        /// @brief stores the value of r9 for the ESR (0x0F0)
        bsl::uint64 esr_r9;
        /// @brief stores the value of r10 for the ESR (0x0F8)
        bsl::uint64 esr_r10;
        /// @brief stores the value of r11 for the ESR (0x100)
        bsl::uint64 esr_r11;
        /// @brief stores the value of r12 for the ESR (0x108)
        bsl::uint64 esr_r12;
        /// @brief stores the value of r13 for the ESR (0x110)
        bsl::uint64 esr_r13;
        /// @brief stores the value of r14 for the ESR (0x118)
        bsl::uint64 esr_r14;
        /// @brief stores the value of r15 for the ESR (0x120)
        bsl::uint64 esr_r15;
        /// @brief stores the value of rip for the ESR (0x128)
        bsl::uint64 esr_ip;
        /// @brief stores the value of rsp for the ESR (0x130)
        bsl::uint64 esr_sp;

        /// @brief stores the value of the ESR vector (0x138)
        bsl::uint64 esr_vector;
        /// @brief stores the value of the ESR error code (0x140)
        bsl::uint64 esr_error_code;

        /// @brief stores the value of cr0 for the ESR (0x148)
        bsl::uint64 esr_cr0;
        /// @brief stores the value of cr2 for the ESR (0x150)
        bsl::uint64 esr_pf_addr;
        /// @brief stores the value of cr3 for the ESR (0x158)
        bsl::uint64 esr_cr3;
        /// @brief stores the value of cr4 for the ESR (0x160)
        bsl::uint64 esr_cr4;

        /// @brief stores the value of cs for the ESR (0x168)
        bsl::uint64 esr_cs;
        /// @brief stores the value of ss for the ESR (0x170)
        bsl::uint64 esr_ss;

        /// @brief stores the value of ss for the ESR (0x178)
        bsl::uint64 esr_rflags;

        /// --------------------------------------------------------------------
        /// Fail Handler States
        /// --------------------------------------------------------------------

        /// @brief stores the value of rsp for the MK (0x180)
        bsl::uint64 mk_sp;
        /// @brief stores the value of rsp for the MK when calling fail (0x188)
        bsl::uint64 mk_handling_esr;

        /// @brief stores the value of rsp for the MK when failing (0x190)
        bsl::uint64 mk_fail_sp;
        /// @brief stores the fail sp used by extensions for callbacks (0x198)
        bsl::uint64 ext_fail_sp;

        /// @brief reserved (0x1A0)
        bsl::uint64 reserved_tmp4;
        /// @brief reserved (0x1A8)
        bsl::uint64 reserved_tmp5;

        /// @brief reserved (0x1B0)
        bsl::uint64 reserved_tmp6;
        /// @brief reserved (0x1B8)
        bsl::uint64 reserved_tmp7;

        /// @brief reserved (0x1C0)
        bsl::uint64 reserved_tmp8;
        /// @brief reserved (0x1C8)
        bsl::uint64 reserved_tmp9;

        /// --------------------------------------------------------------------
        /// Context Information
        /// --------------------------------------------------------------------

        /// @brief stores the virtual address of this TLS block (0x200)
        tls_t *self;

        /// @brief stores the currently active VMID (0x208)
        bsl::uint16 ppid;
        /// @brief stores the total number of online PPs (0x20A)
        bsl::uint16 online_pps;
        /// @brief stores the VSID whose VMCS is loaded on Intel (0x20C)
        bsl::uint16 loaded_vsid;
        /// @brief reserved (0x20E)
        bsl::uint16 reserved_padding0;

        /// @brief stores the currently active extension (0x210)
        ext_t *ext;
        /// @brief stores the extension registered for VMExits (0x218)
        ext_t *ext_vmexit;
        /// @brief stores the extension registered for fast fail events (0x220)
        ext_t *ext_fail;

        /// @brief stores the loader provided state for the microkernel (0x228)
        loader::state_save_t *mk_state;
        /// @brief stores the loader provided state for the root VP (0x230)
        loader::state_save_t *root_vp_state;

        /// @brief stores the currently active extension ID (0x238)
        bsl::uint16 active_extid;
        /// @brief stores the currently active VMID (0x23A)
        bsl::uint16 active_vmid;
        /// @brief stores the currently active VPID (0x23C)
        bsl::uint16 active_vpid;
        /// @brief stores the currently active VSID (0x23E)
        bsl::uint16 active_vsid;

        /// @brief stores the sp used by extensions for callbacks (0x240)
        bsl::uint64 sp;
        /// @brief stores the tps used by extensions for callbacks (0x248)
        bsl::uint64 tp;

        /// @brief used to store a return address for unsafe ops (0x250)
        bsl::uint64 unsafe_rip;

        /// @brief used to signal NMIs are not safe (0x258)
        bsl::uint64 nmi_lock;
        /// @brief used to singal an NMI has fired (0x260)
        bsl::uint64 nmi_pending;

        /// @brief stores whether or not the first launch succeeded (0x268)
        bsl::uint64 first_launch_succeeded;

        /// @brief stores the currently active root page table (0x270)
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
