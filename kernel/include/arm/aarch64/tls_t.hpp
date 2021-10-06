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

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// @brief defines the size of the reserved1 field in the tls_t
    constexpr auto TLS_T_RESERVED1_SIZE{0x020_umx};
    /// @brief defines the size of the reserved2 field in the tls_t
    constexpr auto TLS_T_RESERVED2_SIZE{0x008_umx};
    /// @brief defines the size of the reserved3 field in the tls_t
    constexpr auto TLS_T_RESERVED3_SIZE{0x007_umx};
    /// @brief defines the size of the reserved4 field in the tls_t
    constexpr auto TLS_T_RESERVED4_SIZE{0x040_umx};

    /// IMPORTANT:
    /// - If the size of the TLS is changed, the mk_main_entry will need to
    ///   be updated to reflect the new size. It might make sense to have a
    ///   header file that defines a constant that both this code and the
    ///   assembly logic can share
    ///

    /// @brief defines the the total size of the TLS block
    constexpr auto TLS_T_SIZE{0x400_umx};

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

        /// @brief stores the value of x18 for the microkernel (0x000)
        bsl::uintmx mk_x18;
        /// @brief stores the value of x19 for the microkernel (0x008)
        bsl::uintmx mk_x19;
        /// @brief stores the value of x20 for the microkernel (0x010)
        bsl::uintmx mk_x20;
        /// @brief stores the value of x21 for the microkernel (0x018)
        bsl::uintmx mk_x21;
        /// @brief stores the value of x22 for the microkernel (0x020)
        bsl::uintmx mk_x22;
        /// @brief stores the value of x23 for the microkernel (0x028)
        bsl::uintmx mk_x23;
        /// @brief stores the value of x24 for the microkernel (0x030)
        bsl::uintmx mk_x24;
        /// @brief stores the value of x25 for the microkernel (0x038)
        bsl::uintmx mk_x25;
        /// @brief stores the value of x26 for the microkernel (0x040)
        bsl::uintmx mk_x26;
        /// @brief stores the value of x27 for the microkernel (0x048)
        bsl::uintmx mk_x27;
        /// @brief stores the value of x28 for the microkernel (0x050)
        bsl::uintmx mk_x28;
        /// @brief stores the value of x29 for the microkernel (0x058)
        bsl::uintmx mk_x29;
        /// @brief stores the value of x30 for the microkernel (0x060)
        bsl::uintmx mk_x30;

        /// --------------------------------------------------------------------
        /// Extension State
        /// --------------------------------------------------------------------

        /// @brief x0, stores the extension's syscall (0x068)
        bsl::uintmx ext_syscall;
        /// @brief x1, stores the value of REG1 for the extension (0x070)
        bsl::uintmx ext_reg0;
        /// @brief x2, stores the value of REG1 for the extension (0x078)
        bsl::uintmx ext_reg1;
        /// @brief x3, stores the value of REG1 for the extension (0x080)
        bsl::uintmx ext_reg2;
        /// @brief x4, stores the value of REG1 for the extension (0x088)
        bsl::uintmx ext_reg3;
        /// @brief x5, stores the value of REG1 for the extension (0x090)
        bsl::uintmx ext_reg4;
        /// @brief x6, stores the value of REG1 for the extension (0x098)
        bsl::uintmx ext_reg5;
        /// @brief x7, stores the value of REG1 for the extension (0x0A0)
        bsl::uintmx reserved_reg7;
        /// @brief x8, stores the value of REG1 for the extension (0x0A8)
        bsl::uintmx reserved_reg8;
        /// @brief x9, stores the value of REG1 for the extension (0x0B0)
        bsl::uintmx reserved_reg9;
        /// @brief x10, stores the value of REG1 for the extension (0x0B8)
        bsl::uintmx reserved_reg10;
        /// @brief x11, stores the value of REG1 for the extension (0x0C0)
        bsl::uintmx reserved_reg11;
        /// @brief x12, stores the value of REG1 for the extension (0x0C8)
        bsl::uintmx reserved_reg12;
        /// @brief x13, stores the value of REG1 for the extension (0x0D0)
        bsl::uintmx reserved_reg13;
        /// @brief x14, stores the value of REG1 for the extension (0x0D8)
        bsl::uintmx reserved_reg14;
        /// @brief x15, stores the value of REG1 for the extension (0x0E0)
        bsl::uintmx reserved_reg15;
        /// @brief x16, stores the value of REG1 for the extension (0x0E8)
        bsl::uintmx reserved_reg16;
        /// @brief x17, stores the value of REG1 for the extension (0x0F0)
        bsl::uintmx reserved_reg17;
        /// @brief x18, stores the value of REG1 for the extension (0x0F8)
        bsl::uintmx reserved_reg18;
        /// @brief x19, stores the value of REG1 for the extension (0x100)
        bsl::uintmx reserved_reg19;
        /// @brief x20, stores the value of REG1 for the extension (0x108)
        bsl::uintmx reserved_reg20;
        /// @brief x21, stores the value of REG1 for the extension (0x110)
        bsl::uintmx reserved_reg21;
        /// @brief x22, stores the value of REG1 for the extension (0x118)
        bsl::uintmx reserved_reg22;
        /// @brief x23, stores the value of REG1 for the extension (0x120)
        bsl::uintmx reserved_reg23;
        /// @brief x24, stores the value of REG1 for the extension (0x128)
        bsl::uintmx reserved_reg24;
        /// @brief x25, stores the value of REG1 for the extension (0x130)
        bsl::uintmx reserved_reg25;
        /// @brief x26, stores the value of REG1 for the extension (0x138)
        bsl::uintmx reserved_reg26;
        /// @brief x27, stores the value of REG1 for the extension (0x140)
        bsl::uintmx reserved_reg27;
        /// @brief x28, stores the value of REG1 for the extension (0x148)
        bsl::uintmx reserved_reg28;
        /// @brief x29, stores the value of REG1 for the extension (0x150)
        bsl::uintmx reserved_reg29;
        /// @brief x30, stores the value of REG1 for the extension (0x158)
        bsl::uintmx reserved_reg30;

        /// --------------------------------------------------------------------
        /// ESR State
        /// --------------------------------------------------------------------

        /// @brief stores the value of x0 for the ESR (0x160)
        bsl::uintmx esr_x0;
        /// @brief stores the value of x1 for the ESR (0x168)
        bsl::uintmx esr_x1;
        /// @brief stores the value of x2 for the ESR (0x170)
        bsl::uintmx esr_x2;
        /// @brief stores the value of x3 for the ESR (0x178)
        bsl::uintmx esr_x3;
        /// @brief stores the value of x4 for the ESR (0x180)
        bsl::uintmx esr_x4;
        /// @brief stores the value of x5 for the ESR (0x188)
        bsl::uintmx esr_x5;
        /// @brief stores the value of x6 for the ESR (0x190)
        bsl::uintmx esr_x6;
        /// @brief stores the value of x7 for the ESR (0x198)
        bsl::uintmx esr_x7;
        /// @brief stores the value of x8 for the ESR (0x1A0)
        bsl::uintmx esr_x8;
        /// @brief stores the value of x9 for the ESR (0x1A8)
        bsl::uintmx esr_x9;
        /// @brief stores the value of x10 for the ESR (0x1B0)
        bsl::uintmx esr_x10;
        /// @brief stores the value of x11 for the ESR (0x1B8)
        bsl::uintmx esr_x11;
        /// @brief stores the value of x12 for the ESR (0x1C0)
        bsl::uintmx esr_x12;
        /// @brief stores the value of x13 for the ESR (0x1C8)
        bsl::uintmx esr_x13;
        /// @brief stores the value of x14 for the ESR (0x1D0)
        bsl::uintmx esr_x14;
        /// @brief stores the value of x15 for the ESR (0x1D8)
        bsl::uintmx esr_x15;
        /// @brief stores the value of x16 for the ESR (0x1E0)
        bsl::uintmx esr_x16;
        /// @brief stores the value of x17 for the ESR (0x1E8)
        bsl::uintmx esr_x17;
        /// @brief stores the value of x18 for the ESR (0x1F0)
        bsl::uintmx esr_x18;
        /// @brief stores the value of x19 for the ESR (0x1F8)
        bsl::uintmx esr_x19;
        /// @brief stores the value of x20 for the ESR (0x200)
        bsl::uintmx esr_x20;
        /// @brief stores the value of x21 for the ESR (0x208)
        bsl::uintmx esr_x21;
        /// @brief stores the value of x22 for the ESR (0x210)
        bsl::uintmx esr_x22;
        /// @brief stores the value of x23 for the ESR (0x218)
        bsl::uintmx esr_x23;
        /// @brief stores the value of x24 for the ESR (0x220)
        bsl::uintmx esr_x24;
        /// @brief stores the value of x25 for the ESR (0x228)
        bsl::uintmx esr_x25;
        /// @brief stores the value of x26 for the ESR (0x230)
        bsl::uintmx esr_x26;
        /// @brief stores the value of x27 for the ESR (0x238)
        bsl::uintmx esr_x27;
        /// @brief stores the value of x28 for the ESR (0x240)
        bsl::uintmx esr_x28;
        /// @brief stores the value of x29 for the ESR (0x248)
        bsl::uintmx esr_x29;
        /// @brief stores the value of x30 for the ESR (0x250)
        bsl::uintmx esr_x30;

        /// @brief stores the value of sp for the ESR (0x258)
        bsl::uintmx esr_sp;
        /// @brief stores the value of ip for the ESR (0x260)
        bsl::uintmx esr_ip;

        /// @brief stores the value of the ESR vector (0x268)
        bsl::uintmx esr_vector;
        /// @brief stores the value of the ESR error code (0x270)
        bsl::uintmx esr_error_code;

        /// @brief stores the value of far for the ESR (0x278)
        bsl::uintmx esr_pf_addr;
        /// @brief stores the value of esr for the ESR (0x280)
        bsl::uintmx esr_esr;

        /// @brief stores the value of SPSR for the ESR (0x288)
        bsl::uintmx esr_spsr;

        /// --------------------------------------------------------------------
        /// Fast Fail Information
        /// --------------------------------------------------------------------

        /// @brief stores the current fast fail address (0x290)
        bsl::uintmx current_fast_fail_ip;
        /// @brief stores the current fast fail stack (0x298)
        bsl::uintmx current_fast_fail_sp;

        /// @brief stores the mk_main fast fail address (0x2A0)
        bsl::uintmx mk_main_fast_fail_ip;
        /// @brief stores the mk_main fast fail stack (0x2A8)
        bsl::uintmx mk_main_fast_fail_sp;

        /// @brief stores the call_ext fast fail address (0x2B0)
        bsl::uintmx call_ext_fast_fail_ip;
        /// @brief stores the call_ext fast fail stack (0x2B8)
        bsl::uintmx call_ext_fast_fail_sp;

        /// @brief stores the dispatch_syscall fast fail address (0x2C0)
        bsl::uintmx dispatch_syscall_fast_fail_ip;
        /// @brief stores the dispatch_syscall fast fail stack (0x2C8)
        bsl::uintmx dispatch_syscall_fast_fail_sp;

        /// @brief stores the vmexit loop address (0x2D0)
        bsl::uintmx vmexit_loop_ip;
        /// @brief stores the vmexit loop stack (0x2D8)
        bsl::uintmx vmexit_loop_sp;

        /// @brief reserve the rest of the TLS block for later use.
        bsl::array<bsl::uint8, TLS_T_RESERVED1_SIZE.get()> reserved1;

        /// --------------------------------------------------------------------
        /// Context Information
        /// --------------------------------------------------------------------

        /// @brief stores the virtual address of this TLS block (0x300)
        tls_t *self;

        /// @brief stores the currently active VMID (0x308)
        bsl::uint16 ppid;
        /// @brief stores the total number of online PPs (0x30A)
        bsl::uint16 online_pps;
        /// @brief reserved (0x30C)
        bsl::uint16 reserved_padding0;
        /// @brief reserved (0x30E)
        bsl::uint16 reserved_padding1;

        /// @brief stores the currently active extension (0x310)
        void *ext;
        /// @brief stores the extension registered for VMExits (0x318)
        void *ext_vmexit;
        /// @brief stores the extension registered for fast fail events (0x320)
        void *ext_fail;

        /// @brief stores the loader provided state for the microkernel (0x328)
        loader::state_save_t *mk_state;
        /// @brief stores the loader provided state for the root VP (0x330)
        loader::state_save_t *root_vp_state;

        /// @brief stores the currently active extension ID (0x338)
        bsl::uint16 active_extid;
        /// @brief stores the currently active VMID (0x33A)
        bsl::uint16 active_vmid;
        /// @brief stores the currently active VPID (0x33C)
        bsl::uint16 active_vpid;
        /// @brief stores the currently active VSID (0x33E)
        bsl::uint16 active_vsid;

        /// @brief stores the sp used by extensions for callbacks (0x340)
        bsl::uintmx sp;
        /// @brief stores the tps used by extensions for callbacks (0x348)
        bsl::uintmx tp;

        /// @brief used to store a return address for unsafe ops (0x350)
        bsl::uintmx unsafe_rip;

        /// @brief reserved (0x358)
        bsl::uintmx reserved_padding2;
        /// @brief reserved (0x360)
        bsl::uintmx reserved_padding3;

        /// @brief stores whether or not the first launch succeeded (0x368)
        bsl::uintmx first_launch_succeeded;

        /// @brief stores the currently active root page table (0x370)
        void *active_rpt;

        /// @brief reserve the rest of the TLS block for later use.
        bsl::array<bsl::uint8, TLS_T_RESERVED2_SIZE.get()> reserved2;
    };

    /// @brief make sure the tls_t is the size of a page
    static_assert(sizeof(tls_t) == TLS_T_SIZE);
}

#pragma pack(pop)

#endif
