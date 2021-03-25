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

#include <state_save_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/details/carray.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// @brief defines the size of the reserved1 field in the tls_t
    constexpr auto TLS_T_RESERVED1_SIZE{0x030_umax};
    /// @brief defines the size of the reserved2 field in the tls_t
    constexpr auto TLS_T_RESERVED2_SIZE{0x008_umax};
    /// @brief defines the size of the reserved3 field in the tls_t
    constexpr auto TLS_T_RESERVED3_SIZE{0x007_umax};
    /// @brief defines the size of the reserved4 field in the tls_t
    constexpr auto TLS_T_RESERVED4_SIZE{0x040_umax};

    /// IMPORTANT:
    /// - If the size of the TLS is changed, the mk_main_entry will need to
    ///   be updated to reflect the new size. It might make sense to have a
    ///   header file that defines a constant that both this code and the
    ///   assembly logic can share
    ///

    /// @brief defines the the total size of the TLS block
    constexpr auto TLS_T_SIZE{0x300_umax};

    /// @struct mk::tls_t
    ///
    /// <!-- description -->
    ///   @brief Defines the layout of the microkernel's TLS block. This
    ///     should not be confused with the TLS blocks given to an extension,
    ///     for which there are two, the TLS block for thread_local and the
    ///     TLS block provided by the microkernel's ABI.
    ///
    struct tls_t final
    {
        /// --------------------------------------------------------------------
        /// Microkernel State
        /// --------------------------------------------------------------------

        /// @brief stores the value of rbx for the microkernel (0x000)
        bsl::uintmax mk_rbx;
        /// @brief stores the value of rbp for the microkernel (0x008)
        bsl::uintmax mk_rbp;
        /// @brief stores the value of r12 for the microkernel (0x010)
        bsl::uintmax mk_r12;
        /// @brief stores the value of r13 for the microkernel (0x018)
        bsl::uintmax mk_r13;
        /// @brief stores the value of r14 for the microkernel (0x020)
        bsl::uintmax mk_r14;
        /// @brief stores the value of r15 for the microkernel (0x028)
        bsl::uintmax mk_r15;

        /// --------------------------------------------------------------------
        /// Extension State
        /// --------------------------------------------------------------------

        /// @brief RAX, stores the extension's syscall (0x030)
        bsl::uintmax ext_syscall;
        /// @brief RBX, reserved (0x038)
        bsl::uintmax reserved_reg1;
        /// @brief RCX, reserved (0x040)
        bsl::uintmax reserved_reg2;
        /// @brief RDX, stores the value of REG2 for the extension (0x048)
        bsl::uintmax ext_reg2;
        /// @brief RBP, reserved (0x050)
        bsl::uintmax reserved_reg3;
        /// @brief RSI, stores the value of REG1 for the extension (0x058)
        bsl::uintmax ext_reg1;
        /// @brief RDI, stores the value of REG0 for the extension (0x060)
        bsl::uintmax ext_reg0;
        /// @brief R8, stores the value of REG4 for the extension (0x068)
        bsl::uintmax ext_reg4;
        /// @brief R9, stores the value of REG5 for the extension (0x070)
        bsl::uintmax ext_reg5;
        /// @brief R10, stores the value of REG3 for the extension (0x078)
        bsl::uintmax ext_reg3;
        /// @brief R11, reserved (0x080)
        bsl::uintmax reserved_reg4;
        /// @brief R12, reserved (0x088)
        bsl::uintmax reserved_reg5;
        /// @brief R13, reserved (0x090)
        bsl::uintmax reserved_reg6;
        /// @brief R14, reserved (0x098)
        bsl::uintmax reserved_reg7;
        /// @brief R15, reserved (0x0A0)
        bsl::uintmax reserved_reg8;
        /// @brief RSP, reserved (0x0A8)
        bsl::uintmax reserved_reg9;

        /// --------------------------------------------------------------------
        /// ESR State
        /// --------------------------------------------------------------------

        /// @brief stores the value of rax for the ESR (0x0B0)
        bsl::uintmax esr_rax;
        /// @brief stores the value of rbx for the ESR (0x0B8)
        bsl::uintmax esr_rbx;
        /// @brief stores the value of rcx for the ESR (0x0C0)
        bsl::uintmax esr_rcx;
        /// @brief stores the value of rdx for the ESR (0x0C8)
        bsl::uintmax esr_rdx;
        /// @brief stores the value of rbp for the ESR (0x0D0)
        bsl::uintmax esr_rbp;
        /// @brief stores the value of rsi for the ESR (0x0D8)
        bsl::uintmax esr_rsi;
        /// @brief stores the value of rdi for the ESR (0x0E0)
        bsl::uintmax esr_rdi;
        /// @brief stores the value of r8 for the ESR (0x0E8)
        bsl::uintmax esr_r8;
        /// @brief stores the value of r9 for the ESR (0x0F0)
        bsl::uintmax esr_r9;
        /// @brief stores the value of r10 for the ESR (0x0F8)
        bsl::uintmax esr_r10;
        /// @brief stores the value of r11 for the ESR (0x100)
        bsl::uintmax esr_r11;
        /// @brief stores the value of r12 for the ESR (0x108)
        bsl::uintmax esr_r12;
        /// @brief stores the value of r13 for the ESR (0x110)
        bsl::uintmax esr_r13;
        /// @brief stores the value of r14 for the ESR (0x118)
        bsl::uintmax esr_r14;
        /// @brief stores the value of r15 for the ESR (0x120)
        bsl::uintmax esr_r15;
        /// @brief stores the value of rip for the ESR (0x128)
        bsl::uintmax esr_ip;
        /// @brief stores the value of rsp for the ESR (0x130)
        bsl::uintmax esr_sp;

        /// @brief stores the value of the ESR vector (0x138)
        bsl::uintmax esr_vector;
        /// @brief stores the value of the ESR error code (0x140)
        bsl::uintmax esr_error_code;

        /// @brief stores the value of cr0 for the ESR (0x148)
        bsl::uintmax esr_cr0;
        /// @brief stores the value of cr2 for the ESR (0x150)
        bsl::uintmax esr_pf_addr;
        /// @brief stores the value of cr3 for the ESR (0x158)
        bsl::uintmax esr_cr3;
        /// @brief stores the value of cr4 for the ESR (0x160)
        bsl::uintmax esr_cr4;

        /// @brief stores the value of cs for the ESR (0x168)
        bsl::uintmax esr_cs;
        /// @brief stores the value of ss for the ESR (0x170)
        bsl::uintmax esr_ss;

        /// @brief stores the value of ss for the ESR (0x178)
        bsl::uintmax esr_rflags;

        /// --------------------------------------------------------------------
        /// Fast Fail Information
        /// --------------------------------------------------------------------

        /// @brief stores the current fast fail address (0x180)
        bsl::uintmax current_fast_fail_ip;
        /// @brief stores the current fast fail stack (0x188)
        bsl::uintmax current_fast_fail_sp;

        /// @brief stores the mk_main fast fail address (0x190)
        bsl::uintmax mk_main_fast_fail_ip;
        /// @brief stores the mk_main fast fail stack (0x198)
        bsl::uintmax mk_main_fast_fail_sp;

        /// @brief stores the call_ext fast fail address (0x1A0)
        bsl::uintmax call_ext_fast_fail_ip;
        /// @brief stores the call_ext fast fail stack (0x1A8)
        bsl::uintmax call_ext_fast_fail_sp;

        /// @brief stores the dispatch_syscall fast fail address (0x1B0)
        bsl::uintmax dispatch_syscall_fast_fail_ip;
        /// @brief stores the dispatch_syscall fast fail stack (0x1B8)
        bsl::uintmax dispatch_syscall_fast_fail_sp;

        /// @brief stores the vmexit loop address (0x1C0)
        bsl::uintmax vmexit_loop_ip;
        /// @brief stores the vmexit loop stack (0x1C8)
        bsl::uintmax vmexit_loop_sp;

        /// @brief reserve the rest of the TLS block for later use.
        bsl::details::carray<bsl::uint8, TLS_T_RESERVED1_SIZE.get()> reserved1;

        /// --------------------------------------------------------------------
        /// Context Information
        /// --------------------------------------------------------------------

        /// @brief stores the virtual address of this TLS block (0x200)
        tls_t *self;

        /// @brief stores the currently active VMID (0x208)
        bsl::uint16 ppid;
        /// @brief stores the total number of online PPs (0x20A)
        bsl::uint16 online_pps;
        /// @brief stores the VPSID whose VMCS is loaded on Intel (0x20C)
        bsl::uint16 loaded_vpsid;
        /// @brief reserved (0x20E)
        bsl::uint16 reserved_padding0;

        /// @brief stores the currently active extension (0x210)
        void *ext;
        /// @brief stores the extension registered for VMExits (0x218)
        void *ext_vmexit;
        /// @brief stores the extension registered for fast fail events (0x220)
        void *ext_fail;

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
        /// @brief stores the currently active VPSID (0x23E)
        bsl::uint16 active_vpsid;

        /// @brief stores the sp used by extensions for callbacks (0x240)
        bsl::uintmax sp;
        /// @brief stores the tps used by extensions for callbacks (0x248)
        bsl::uintmax tp;

        /// @brief used to store a return address for unsafe ops (0x250)
        bsl::uintmax unsafe_rip;

        /// @brief used to signal NMIs are not safe (0x258)
        bsl::uintmax nmi_lock;
        /// @brief used to singal an NMI has fired (0x260)
        bsl::uintmax nmi_pending;

        /// @brief stores whether or not the first launch succeeded (0x268)
        bsl::uintmax first_launch_succeeded;

        /// @brief stores the currently active root page table (0x270)
        void *active_rpt;

        /// @brief reserve the rest of the TLS block for later use.
        bsl::details::carray<bsl::uint8, TLS_T_RESERVED2_SIZE.get()> reserved2;

        /// --------------------------------------------------------------------
        /// Failure Handling
        /// --------------------------------------------------------------------

        /// @brief stores a whether or not state is changing (0x280)
        bool state_reversal_required;

        /// @brief reserves the rest of the TLS block for later use.
        bsl::details::carray<bsl::uint8, TLS_T_RESERVED3_SIZE.get()> reserved3;

        /// @brief stores the syscall return status (0x288)
        bsl::uintmax syscall_ret_status;

        /// @brief logs an extid for state reversal if needed (0x290)
        bsl::uint16 log_extid;
        /// @brief logs a vmid for state reversal if needed (0x292)
        bsl::uint16 log_vmid;
        /// @brief logs a vpid for state reversal if needed (0x294)
        bsl::uint16 log_vpid;
        /// @brief logs a vpsid for state reversal if needed (0x296)
        bsl::uint16 log_vpsid;

        /// @brief logs an ext for state reversal if needed (0x298)
        void *log_ext;
        /// @brief logs a vm for state reversal if needed (0x2A0)
        void *log_vm;
        /// @brief logs a vp for state reversal if needed (0x2A8)
        void *log_vp;
        /// @brief logs a vps for state reversal if needed (0x2B0)
        void *log_vps;

        /// @brief reserve the rest of the TLS block for later use.
        bsl::details::carray<bsl::uint8, TLS_T_RESERVED4_SIZE.get()> reserved4;

        /// --------------------------------------------------------------------
        /// Unit Test Specific
        /// --------------------------------------------------------------------

        /// @brief reserved for unit testing
        bsl::errc_type test_ret;
        /// @brief reserved
        bsl::uint32 reserved_padding1;
    };

    /// @brief make sure the tls_t is the size of a page
    static_assert(sizeof(tls_t) == TLS_T_SIZE);
}

#pragma pack(pop)

#endif
