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

#ifndef STATE_SAVE_T_HPP
#define STATE_SAVE_T_HPP

#include <global_descriptor_table_register_t.hpp>
#include <interrupt_descriptor_table_register_t.hpp>
#include <tss_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/details/carray.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace loader
{
    /// @brief the size of reserved #0 in the state_save_t
    constexpr auto SS_PAD_SIZE{0x6_umax};
    /// @brief the size of reserved #0 in the state_save_t
    constexpr auto SS_RESERVED0_SIZE{0xB_umax};
    /// @brief the size of reserved #1 in the state_save_t
    constexpr auto SS_RESERVED1_SIZE{0x6_umax};
    /// @brief the size of reserved #2 in the state_save_t
    constexpr auto SS_RESERVED2_SIZE{0x8_umax};
    /// @brief the size of reserved #3 in the state_save_t
    constexpr auto SS_RESERVED3_SIZE{0x7_umax};

    /// @struct loader::state_save_t
    ///
    /// <!-- description -->
    ///   @brief Stores the registers and processor state that is used by the
    ///     microkernel that must be restored in the event of an error or the
    ///     successful launch of the hypervisor.
    ///
    struct state_save_t final
    {
        /// --------------------------------------------------------------------
        /// General Purpose Registers
        /// --------------------------------------------------------------------

        /// @brief stores the value of rax (0x000)
        bsl::uint64 rax;
        /// @brief stores the value of rbx (0x008)
        bsl::uint64 rbx;
        /// @brief stores the value of rcx (0x010)
        bsl::uint64 rcx;
        /// @brief stores the value of rdx (0x018)
        bsl::uint64 rdx;
        /// @brief stores the value of rbp (0x020)
        bsl::uint64 rbp;
        /// @brief stores the value of rsi (0x028)
        bsl::uint64 rsi;
        /// @brief stores the value of rdi (0x030)
        bsl::uint64 rdi;
        /// @brief stores the value of r8 (0x038)
        bsl::uint64 r8;
        /// @brief stores the value of r9 (0x040)
        bsl::uint64 r9;
        /// @brief stores the value of r10 (0x048)
        bsl::uint64 r10;
        /// @brief stores the value of r11 (0x050)
        bsl::uint64 r11;
        /// @brief stores the value of r12 (0x058)
        bsl::uint64 r12;
        /// @brief stores the value of r13 (0x060)
        bsl::uint64 r13;
        /// @brief stores the value of r14 (0x068)
        bsl::uint64 r14;
        /// @brief stores the value of r15 (0x070)
        bsl::uint64 r15;
        /// @brief stores the value of rip (0x078)
        bsl::uint64 rip;
        /// @brief stores the value of rsp (0x080)
        bsl::uint64 rsp;

        /// --------------------------------------------------------------------
        /// Flags
        /// --------------------------------------------------------------------

        /// @brief stores the value of rflags (0x088)
        bsl::uint64 rflags;

        /// --------------------------------------------------------------------
        /// Task-State Segment
        /// --------------------------------------------------------------------

        /// @brief stores a pointer to the tss (0x090)
        tss_t *tss;

        /// @brief stores a pointer to the ist #1
        void *ist;

        /// --------------------------------------------------------------------
        /// Descriptor Table Information
        /// --------------------------------------------------------------------

        /// @brief stores the value of the GDTR (0x0A0)
        global_descriptor_table_register_t gdtr;

        /// @brief added padding for alignment (0x0AA)
        bsl::details::carray<bsl::uint8, SS_PAD_SIZE.get()> pad1;

        /// @brief stores the value of the IDTR (0x0B0)
        interrupt_descriptor_table_register_t idtr;

        /// @brief added padding for alignment (0x0BA)
        bsl::details::carray<bsl::uint8, SS_PAD_SIZE.get()> pad2;

        /// @brief stores the value of the ES segment selector (0x0C0)
        bsl::uint16 es_selector;
        /// @brief stores the value of the ES segment attributes (0x0C2)
        bsl::uint16 es_attrib;
        /// @brief stores the value of the ES segment limit (0x0C4)
        bsl::uint32 es_limit;
        /// @brief stores the value of the ES segment base (0x0C8)
        bsl::uint64 es_base;

        /// @brief stores the value of the CS segment selector (0x0D0)
        bsl::uint16 cs_selector;
        /// @brief stores the value of the CS segment attributes (0x0D2)
        bsl::uint16 cs_attrib;
        /// @brief stores the value of the CS segment limit (0x0D4)
        bsl::uint32 cs_limit;
        /// @brief stores the value of the CS segment base (0x0D8)
        bsl::uint64 cs_base;

        /// @brief stores the value of the SS segment selector (0x0E0)
        bsl::uint16 ss_selector;
        /// @brief stores the value of the SS segment attributes (0x0E2)
        bsl::uint16 ss_attrib;
        /// @brief stores the value of the SS segment limit (0x0E4)
        bsl::uint32 ss_limit;
        /// @brief stores the value of the SS segment base (0x0E8)
        bsl::uint64 ss_base;

        /// @brief stores the value of the DS segment selector (0x0F0)
        bsl::uint16 ds_selector;
        /// @brief stores the value of the DS segment attributes (0x0F2)
        bsl::uint16 ds_attrib;
        /// @brief stores the value of the DS segment limit (0x0F4)
        bsl::uint32 ds_limit;
        /// @brief stores the value of the DS segment base (0x0F8)
        bsl::uint64 ds_base;

        /// @brief stores the value of the FS segment selector (0x100)
        bsl::uint16 fs_selector;
        /// @brief stores the value of the FS segment attributes (0x102)
        bsl::uint16 fs_attrib;
        /// @brief stores the value of the FS segment limit (0x104)
        bsl::uint32 fs_limit;
        /// @brief stores the value of the FS segment base (0x108)
        bsl::uint64 fs_base;

        /// @brief stores the value of the GS segment selector (0x110)
        bsl::uint16 gs_selector;
        /// @brief stores the value of the GS segment attributes (0x112)
        bsl::uint16 gs_attrib;
        /// @brief stores the value of the GS segment limit (0x114)
        bsl::uint32 gs_limit;
        /// @brief stores the value of the GS segment base (0x118)
        bsl::uint64 gs_base;

        /// @brief stores the value of the LDTR segment selector (0x120)
        bsl::uint16 ldtr_selector;
        /// @brief stores the value of the LDTR segment attributes (0x122)
        bsl::uint16 ldtr_attrib;
        /// @brief stores the value of the LDTR segment limit (0x124)
        bsl::uint32 ldtr_limit;
        /// @brief stores the value of the LDTR segment base (0x128)
        bsl::uint64 ldtr_base;

        /// @brief stores the value of the TR segment selector (0x130)
        bsl::uint16 tr_selector;
        /// @brief stores the value of the TR segment attributes (0x132)
        bsl::uint16 tr_attrib;
        /// @brief stores the value of the TR segment limit (0x134)
        bsl::uint32 tr_limit;
        /// @brief stores the value of the TR segment base (0x138)
        bsl::uint64 tr_base;

        /// --------------------------------------------------------------------
        /// Control Registers
        /// --------------------------------------------------------------------

        /// @brief stores the value of the CR0 control register (0x140)
        bsl::uint64 cr0;
        /// @brief reserved (0x148)
        bsl::uint64 reserved;
        /// @brief stores the value of the CR2 control register (0x150)
        bsl::uint64 cr2;
        /// @brief stores the value of the CR3 control register (0x158)
        bsl::uint64 cr3;
        /// @brief stores the value of the CR4 control register (0x160)
        bsl::uint64 cr4;

        /// @brief reserved for future use (0x168)
        bsl::details::carray<bsl::uint64, SS_RESERVED0_SIZE.get()> reserved0;

        /// --------------------------------------------------------------------
        /// Debug Registers
        /// --------------------------------------------------------------------

        /// @brief reserved for future use (0x1C0)
        bsl::details::carray<bsl::uint64, SS_RESERVED1_SIZE.get()> reserved1;

        /// @brief stores the value of DR6 debug register (0x1F0)
        bsl::uint64 dr6;
        /// @brief stores the value of DR7 debug register (0x1F8)
        bsl::uint64 dr7;

        /// @brief reserved for future use (0x200)
        bsl::details::carray<bsl::uint64, SS_RESERVED2_SIZE.get()> reserved2;

        /// --------------------------------------------------------------------
        /// MSRs
        /// --------------------------------------------------------------------

        /// @brief stores the value of the IA32_EFER MSR (0x240)
        bsl::uint64 ia32_efer;
        /// @brief stores the value of the IA32_STAR MSR (0x248)
        bsl::uint64 ia32_star;
        /// @brief stores the value of the IA32_LSTAR MSR (0x250)
        bsl::uint64 ia32_lstar;
        /// @brief stores the value of the IA32_CSTAR MSR (0x258)
        bsl::uint64 ia32_cstar;
        /// @brief stores the value of the IA32_FMASK MSR (0x260)
        bsl::uint64 ia32_fmask;
        /// @brief stores the value of the IA32_FS_BASE MSR (0x268)
        bsl::uint64 ia32_fs_base;
        /// @brief stores the value of the IA32_GS_BASE MSR (0x270)
        bsl::uint64 ia32_gs_base;
        /// @brief stores the value of the IA32_KERNEL_GS_BASE MSR (0x278)
        bsl::uint64 ia32_kernel_gs_base;
        /// @brief stores the value of the IA32_SYSENTER_CS MSR (0x280)
        bsl::uint64 ia32_sysenter_cs;
        /// @brief stores the value of the IA32_SYSENTER_ESP MSR (0x288)
        bsl::uint64 ia32_sysenter_esp;
        /// @brief stores the value of the IA32_SYSENTER_EIP MSR (0x290)
        bsl::uint64 ia32_sysenter_eip;
        /// @brief stores the value of the IA32_PAT MSR (0x298)
        bsl::uint64 ia32_pat;
        /// @brief stores the value of the IA32_DEBUGCTL MSR (0x2A0)
        bsl::uint64 ia32_debugctl;

        /// @brief reserved for future use (0x2A8)
        bsl::details::carray<bsl::uint64, SS_RESERVED3_SIZE.get()> reserved3;

        /// --------------------------------------------------------------------
        /// HVE Page
        /// --------------------------------------------------------------------

        /// @brief stores a pointer to the hve page (0x2E0)
        void *hve_page;

        /// --------------------------------------------------------------------
        /// Handlers
        /// --------------------------------------------------------------------

        /// @brief stores the promote handler (0x2E8)
        void *promote_handler;
        /// @brief stores the esr default handler (0x2F0)
        void *esr_default_handler;
        /// @brief stores the esr df handler (0x2F8)
        void *esr_df_handler;
        /// @brief stores the esr gpf handler (0x300)
        void *esr_gpf_handler;
        /// @brief stores the esr nmi handler (0x308)
        void *esr_nmi_handler;
        /// @brief stores the esr pf handler (0x310)
        void *esr_pf_handler;

        /// --------------------------------------------------------------------
        /// NMI
        /// --------------------------------------------------------------------

        /// @brief stores whether or not an NMI fired (0x318)
        bsl::uint64 nmi;
    };
}

#pragma pack(pop)

#endif
