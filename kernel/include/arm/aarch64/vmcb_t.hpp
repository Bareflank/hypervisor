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

#ifndef VMCB_HPP
#define VMCB_HPP

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace mk
{
    /// @brief defines the size of the reserved1 field in the VMCB
    constexpr auto VMCB_RESERVED1_SIZE{0x24_umx};
    /// @brief defines the size of the reserved2 field in the VMCB
    constexpr auto VMCB_RESERVED2_SIZE{0x3_umx};
    /// @brief defines the size of the reserved3 field in the VMCB
    constexpr auto VMCB_RESERVED3_SIZE{0x4_umx};
    /// @brief defines the size of the reserved4 field in the VMCB
    constexpr auto VMCB_RESERVED4_SIZE{0x8_umx};
    /// @brief defines the size of the reserved5 field in the VMCB
    constexpr auto VMCB_RESERVED5_SIZE{0x8_umx};
    /// @brief defines the size of the reserved6 field in the VMCB
    constexpr auto VMCB_RESERVED6_SIZE{0x2F0_umx};
    /// @brief defines the size of the reserved7 field in the VMCB
    constexpr auto VMCB_RESERVED7_SIZE{0x2B_umx};
    /// @brief defines the size of the reserved8 field in the VMCB
    constexpr auto VMCB_RESERVED8_SIZE{0x4_umx};
    /// @brief defines the size of the reserved9 field in the VMCB
    constexpr auto VMCB_RESERVED9_SIZE{0x70_umx};
    /// @brief defines the size of the reserved10 field in the VMCB
    constexpr auto VMCB_RESERVED10_SIZE{0x58_umx};
    /// @brief defines the size of the reserved11 field in the VMCB
    constexpr auto VMCB_RESERVED11_SIZE{0x18_umx};
    /// @brief defines the size of the reserved12 field in the VMCB
    constexpr auto VMCB_RESERVED12_SIZE{0x20_umx};
    /// @brief defines the size of the reserved13 field in the VMCB
    constexpr auto VMCB_RESERVED13_SIZE{0x968_umx};
    /// @brief defines the size of the reserved13 field in the VMCB
    constexpr auto VMCB_GIB_SIZE{0xF_umx};

    /// <!-- description -->
    ///   @brief The following defines the structure of the VMCB used by AMD's
    ///     hypervisor extensions.
    ///
    struct vmcb_t final
    {
        // -------------------------------------------------------------------------
        // Control Area
        // -------------------------------------------------------------------------

        /// @brief stores the VMCB field at offset (0x0000)
        bsl::uint16 intercept_cr_read;
        /// @brief stores the VMCB field at offset (0x0002)
        bsl::uint16 intercept_cr_write;
        /// @brief stores the VMCB field at offset (0x0004)
        bsl::uint16 intercept_dr_read;
        /// @brief stores the VMCB field at offset (0x0006)
        bsl::uint16 intercept_dr_write;
        /// @brief stores the VMCB field at offset (0x0008)
        bsl::uint32 intercept_exception;
        /// @brief stores the VMCB field at offset (0x000C)
        bsl::uint32 intercept_instruction1;
        /// @brief stores the VMCB field at offset (0x0010)
        bsl::uint32 intercept_instruction2;
        /// @brief stores the VMCB field at offset (0x0014)
        bsl::uint32 intercept_instruction3;
        /// @brief stores the VMCB field at offset (0x0018)
        bsl::array<bsl::uint8, VMCB_RESERVED1_SIZE.get()> reserved1;
        /// @brief stores the VMCB field at offset (0x003C)
        bsl::uint16 pause_filter_threshold;
        /// @brief stores the VMCB field at offset (0x003E)
        bsl::uint16 pause_filter_count;
        /// @brief stores the VMCB field at offset (0x0040)
        bsl::uint64 iopm_base_pa;
        /// @brief stores the VMCB field at offset (0x0048)
        bsl::uint64 msrpm_base_pa;
        /// @brief stores the VMCB field at offset (0x0050)
        bsl::uint64 tsc_offset;
        /// @brief stores the VMCB field at offset (0x0058)
        bsl::uint32 guest_asid;
        /// @brief stores the VMCB field at offset (0x005C)
        bsl::uint8 tlb_control;
        /// @brief stores the VMCB field at offset (0x005D)
        bsl::array<bsl::uint8, VMCB_RESERVED2_SIZE.get()> reserved2;
        /// @brief stores the VMCB field at offset (0x0060)
        bsl::uint64 virtual_interrupt_a;
        /// @brief stores the VMCB field at offset (0x0068)
        bsl::uint64 virtual_interrupt_b;
        /// @brief stores the VMCB field at offset (0x0070)
        bsl::uint64 exitcode;
        /// @brief stores the VMCB field at offset (0x0078)
        bsl::uint64 exitinfo1;
        /// @brief stores the VMCB field at offset (0x0080)
        bsl::uint64 exitinfo2;
        /// @brief stores the VMCB field at offset (0x0088)
        bsl::uint64 exitininfo;
        /// @brief stores the VMCB field at offset (0x0090)
        bsl::uint64 ctls1;
        /// @brief stores the VMCB field at offset (0x0098)
        bsl::uint64 avic_apic_bar;
        /// @brief stores the VMCB field at offset (0x00A0)
        bsl::uint64 guest_pa_of_ghcb;
        /// @brief stores the VMCB field at offset (0x00A8)
        bsl::uint64 eventinj;
        /// @brief stores the VMCB field at offset (0x00B0)
        bsl::uint64 n_cr3;
        /// @brief stores the VMCB field at offset (0x00B8)
        bsl::uint64 ctls2;
        /// @brief stores the VMCB field at offset (0x00C0)
        bsl::uint32 vmcb_clean_bits;
        /// @brief stores the VMCB field at offset (0x00C4)
        bsl::array<bsl::uint8, VMCB_RESERVED3_SIZE.get()> reserved3;
        /// @brief stores the VMCB field at offset (0x00C8)
        bsl::uint64 nrip;
        /// @brief stores the VMCB field at offset (0x00D0)
        bsl::uint8 number_of_bytes_fetched;
        /// @brief stores the VMCB field at offset (0x00D1)
        bsl::array<bsl::uint8, VMCB_GIB_SIZE.get()> guest_instruction_bytes;
        /// @brief stores the VMCB field at offset (0x00E0)
        bsl::uint64 avic_apic_backing_page_ptr;
        /// @brief stores the VMCB field at offset (0x00E8)
        bsl::array<bsl::uint8, VMCB_RESERVED4_SIZE.get()> reserved4;
        /// @brief stores the VMCB field at offset (0x00F0)
        bsl::uint64 avic_logical_table_ptr;
        /// @brief stores the VMCB field at offset (0x00F8)
        bsl::uint64 avic_physical_table_ptr;
        /// @brief stores the VMCB field at offset (0x0100)
        bsl::array<bsl::uint8, VMCB_RESERVED5_SIZE.get()> reserved5;
        /// @brief stores the VMCB field at offset (0x0108)
        bsl::uint64 vmsa_ptr;
        /// @brief stores the VMCB field at offset (0x0110)
        bsl::array<bsl::uint8, VMCB_RESERVED6_SIZE.get()> reserved6;

        // -------------------------------------------------------------------------
        // State Save Area
        // -------------------------------------------------------------------------

        /// @brief stores the VMCB field at offset (0x0400)
        bsl::uint16 es_selector;
        /// @brief stores the VMCB field at offset (0x0402)
        bsl::uint16 es_attrib;
        /// @brief stores the VMCB field at offset (0x0404)
        bsl::uint32 es_limit;
        /// @brief stores the VMCB field at offset (0x0408)
        bsl::uint64 es_base;
        /// @brief stores the VMCB field at offset (0x0410)
        bsl::uint16 cs_selector;
        /// @brief stores the VMCB field at offset (0x0412)
        bsl::uint16 cs_attrib;
        /// @brief stores the VMCB field at offset (0x0414)
        bsl::uint32 cs_limit;
        /// @brief stores the VMCB field at offset (0x0418)
        bsl::uint64 cs_base;
        /// @brief stores the VMCB field at offset (0x0420)
        bsl::uint16 ss_selector;
        /// @brief stores the VMCB field at offset (0x0422)
        bsl::uint16 ss_attrib;
        /// @brief stores the VMCB field at offset (0x0424)
        bsl::uint32 ss_limit;
        /// @brief stores the VMCB field at offset (0x0428)
        bsl::uint64 ss_base;
        /// @brief stores the VMCB field at offset (0x0430)
        bsl::uint16 ds_selector;
        /// @brief stores the VMCB field at offset (0x0432)
        bsl::uint16 ds_attrib;
        /// @brief stores the VMCB field at offset (0x0434)
        bsl::uint32 ds_limit;
        /// @brief stores the VMCB field at offset (0x0438)
        bsl::uint64 ds_base;
        /// @brief stores the VMCB field at offset (0x0440)
        bsl::uint16 fs_selector;
        /// @brief stores the VMCB field at offset (0x0442)
        bsl::uint16 fs_attrib;
        /// @brief stores the VMCB field at offset (0x0444)
        bsl::uint32 fs_limit;
        /// @brief stores the VMCB field at offset (0x0448)
        bsl::uint64 fs_base;
        /// @brief stores the VMCB field at offset (0x0450)
        bsl::uint16 gs_selector;
        /// @brief stores the VMCB field at offset (0x0452)
        bsl::uint16 gs_attrib;
        /// @brief stores the VMCB field at offset (0x0454)
        bsl::uint32 gs_limit;
        /// @brief stores the VMCB field at offset (0x0458)
        bsl::uint64 gs_base;
        /// @brief stores the VMCB field at offset (0x0460)
        bsl::uint16 gdtr_selector;
        /// @brief stores the VMCB field at offset (0x0462)
        bsl::uint16 gdtr_attrib;
        /// @brief stores the VMCB field at offset (0x0464)
        bsl::uint32 gdtr_limit;
        /// @brief stores the VMCB field at offset (0x0468)
        bsl::uint64 gdtr_base;
        /// @brief stores the VMCB field at offset (0x0470)
        bsl::uint16 ldtr_selector;
        /// @brief stores the VMCB field at offset (0x0472)
        bsl::uint16 ldtr_attrib;
        /// @brief stores the VMCB field at offset (0x0474)
        bsl::uint32 ldtr_limit;
        /// @brief stores the VMCB field at offset (0x0478)
        bsl::uint64 ldtr_base;
        /// @brief stores the VMCB field at offset (0x0480)
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bsl::uint16 idtr_selector;
        /// @brief stores the VMCB field at offset (0x0482)
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bsl::uint16 idtr_attrib;
        /// @brief stores the VMCB field at offset (0x0484)
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bsl::uint32 idtr_limit;
        /// @brief stores the VMCB field at offset (0x0488)
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        bsl::uint64 idtr_base;
        /// @brief stores the VMCB field at offset (0x0490)
        bsl::uint16 tr_selector;
        /// @brief stores the VMCB field at offset (0x0492)
        bsl::uint16 tr_attrib;
        /// @brief stores the VMCB field at offset (0x0494)
        bsl::uint32 tr_limit;
        /// @brief stores the VMCB field at offset (0x0498)
        bsl::uint64 tr_base;
        /// @brief stores the VMCB field at offset (0x04A0)
        bsl::array<bsl::uint8, VMCB_RESERVED7_SIZE.get()> reserved7;
        /// @brief stores the VMCB field at offset (0x04CB)
        bsl::uint8 cpl;
        /// @brief stores the VMCB field at offset (0x04CC)
        bsl::array<bsl::uint8, VMCB_RESERVED8_SIZE.get()> reserved8;
        /// @brief stores the VMCB field at offset (0x04D0)
        bsl::uint64 efer;
        /// @brief stores the VMCB field at offset (0x04D8)
        bsl::array<bsl::uint8, VMCB_RESERVED9_SIZE.get()> reserved9;
        /// @brief stores the VMCB field at offset (0x0548)
        bsl::uint64 cr4;
        /// @brief stores the VMCB field at offset (0x0550)
        bsl::uint64 cr3;
        /// @brief stores the VMCB field at offset (0x0558)
        bsl::uint64 cr0;
        /// @brief stores the VMCB field at offset (0x0560)
        bsl::uint64 dr7;
        /// @brief stores the VMCB field at offset (0x0568)
        bsl::uint64 dr6;
        /// @brief stores the VMCB field at offset (0x0570)
        bsl::uint64 rflags;
        /// @brief stores the VMCB field at offset (0x0578)
        bsl::uint64 rip;
        /// @brief stores the VMCB field at offset (0x0580)
        bsl::array<bsl::uint8, VMCB_RESERVED10_SIZE.get()> reserved10;
        /// @brief stores the VMCB field at offset (0x05D8)
        bsl::uint64 rsp;
        /// @brief stores the VMCB field at offset (0x05E0)
        bsl::array<bsl::uint8, VMCB_RESERVED11_SIZE.get()> reserved11;
        /// @brief stores the VMCB field at offset (0x05F8)
        bsl::uint64 rax;
        /// @brief stores the VMCB field at offset (0x0600)
        bsl::uint64 star;
        /// @brief stores the VMCB field at offset (0x0608)
        bsl::uint64 lstar;
        /// @brief stores the VMCB field at offset (0x0610)
        bsl::uint64 cstar;
        /// @brief stores the VMCB field at offset (0x0618)
        bsl::uint64 sfmask;
        /// @brief stores the VMCB field at offset (0x0620)
        bsl::uint64 kernel_gs_base;
        /// @brief stores the VMCB field at offset (0x0628)
        bsl::uint64 sysenter_cs;
        /// @brief stores the VMCB field at offset (0x0630)
        bsl::uint64 sysenter_esp;
        /// @brief stores the VMCB field at offset (0x0638)
        bsl::uint64 sysenter_eip;
        /// @brief stores the VMCB field at offset (0x0640)
        bsl::uint64 cr2;
        /// @brief stores the VMCB field at offset (0x0648)
        bsl::array<bsl::uint8, VMCB_RESERVED12_SIZE.get()> reserved12;
        /// @brief stores the VMCB field at offset (0x0668)
        bsl::uint64 g_pat;
        /// @brief stores the VMCB field at offset (0x0670)
        bsl::uint64 dbgctl;
        /// @brief stores the VMCB field at offset (0x0678)
        bsl::uint64 br_from;
        /// @brief stores the VMCB field at offset (0x0680)
        bsl::uint64 br_to;
        /// @brief stores the VMCB field at offset (0x0688)
        bsl::uint64 lastexcpfrom;
        /// @brief stores the VMCB field at offset (0x0690)
        bsl::uint64 lastexcpto;
        /// @brief stores the VMCB field at offset (0x0698)
        bsl::array<bsl::uint8, VMCB_RESERVED13_SIZE.get()> reserved13;
    };
}

#pragma pack(pop)

#endif
