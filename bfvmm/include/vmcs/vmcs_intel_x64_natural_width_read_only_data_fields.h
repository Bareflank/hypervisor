//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef VMCS_INTEL_X64_16BIT_NATURAL_WIDTH_READ_ONLY_DATA_FIELDS_H
#define VMCS_INTEL_X64_16BIT_NATURAL_WIDTH_READ_ONLY_DATA_FIELDS_H

#include <vmcs/vmcs_intel_x64.h>

/// Intel x86_64 VMCS Natural-Width Read-Only Data Fields
///
/// The following provides the interface for the natural-width read-only VMCS
/// data fields as defined in Appendix B.4.2, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace exit_qualification
{
    constexpr const auto addr = 0x0000000000006400UL;
    constexpr const auto name = "exit_qualification";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    namespace debug_exception
    {
        constexpr const auto name = "debug_exception";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace b0
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "b0";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        namespace b1
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "b1";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        namespace b2
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "b2";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        namespace b3
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 3;
            constexpr const auto name = "b3";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFF9FF0UL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace bd
        {
            constexpr const auto mask = 0x0000000000002000UL;
            constexpr const auto from = 13;
            constexpr const auto name = "bd";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        namespace bs
        {
            constexpr const auto mask = 0x0000000000004000UL;
            constexpr const auto from = 14;
            constexpr const auto name = "bs";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }
    }

    namespace page_fault_exception
    {
        constexpr const auto name = "page_fault_exception";

        inline auto get_name()
        { return name; }

        inline auto address()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto address_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace sipi
    {
        constexpr const auto name = "sipi";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace vector
        {
            constexpr const auto mask = 0x00000000000000FFUL;
            constexpr const auto from = 0;
            constexpr const auto name = "vector";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace task_switch
    {
        constexpr const auto name = "task_switch";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace tss_selector
        {
            constexpr const auto mask = 0x000000000000FFFFUL;
            constexpr const auto from = 0;
            constexpr const auto name = "tss_selector";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFF3FFF0000UL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace source_of_task_switch_init
        {
            constexpr const auto mask = 0x00000000C0000000UL;
            constexpr const auto from = 30;
            constexpr const auto name = "task_switch_init_source";

            constexpr const auto call_instruction = 0U;
            constexpr const auto iret_instruction = 1U;
            constexpr const auto jmp_instruction = 2U;
            constexpr const auto task_gate_in_idt = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace invept
    {
        constexpr const auto name = "invept";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace invpcid
    {
        constexpr const auto name = "invpcid";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace invvpid
    {
        constexpr const auto name = "invvpid";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace lgdt
    {
        constexpr const auto name = "lgdt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace lidt
    {
        constexpr const auto name = "lidt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace lldt
    {
        constexpr const auto name = "lldt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace ltr
    {
        constexpr const auto name = "ltr";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace sgdt
    {
        constexpr const auto name = "sgdt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace sidt
    {
        constexpr const auto name = "sidt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace sldt
    {
        constexpr const auto name = "sldt";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace str
    {
        constexpr const auto name = "str";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace vmclear
    {
        constexpr const auto name = "vmclear";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace vmptrld
    {
        constexpr const auto name = "vmptrld";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace vmptrst
    {
        constexpr const auto name = "vmptrst";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace vmread
    {
        constexpr const auto name = "vmread";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace vmwrite
    {
        constexpr const auto name = "vmwrite";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace vmxon
    {
        constexpr const auto name = "vmxon";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace xrstors
    {
        constexpr const auto name = "xrstors";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace xsaves
    {
        constexpr const auto name = "xsaves";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace control_register_access
    {
        constexpr const auto name = "control_register_access";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace control_register_number
        {
            constexpr const auto mask = 0x000000000000000FUL;
            constexpr const auto from = 0;
            constexpr const auto name = "control_register_number";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace access_type
        {
            constexpr const auto mask = 0x0000000000000030UL;
            constexpr const auto from = 4;
            constexpr const auto name = "access_type";

            constexpr const auto mov_to_cr = 0U;
            constexpr const auto mov_from_cr = 1U;
            constexpr const auto clts = 2U;
            constexpr const auto lmsw = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace lmsw_operand_type
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "lmsw_operand_type";

            constexpr const auto reg = 0U;
            constexpr const auto mem = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFF0000F080UL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace general_purpose_register
        {
            constexpr const auto mask = 0x0000000000000F00UL;
            constexpr const auto from = 8;
            constexpr const auto name = "general_purpose_register";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace source_data
        {
            constexpr const auto mask = 0x00000000FFFF0000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "source_data";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        }
    }

    namespace mov_dr
    {
        constexpr const auto name = "mov_dr";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace debug_register_number
        {
            constexpr const auto mask = 0x0000000000000007UL;
            constexpr const auto from = 0;
            constexpr const auto name = "debug_register_number";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFF0E8UL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace direction_of_access
        {
            constexpr const auto mask = 0x0000000000000010UL;
            constexpr const auto from = 4;
            constexpr const auto name = "direction_of_access";

            constexpr const auto to_dr = 0U;
            constexpr const auto from_dr = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace general_purpose_register
        {
            constexpr const auto mask = 0x0000000000000F00UL;
            constexpr const auto from = 8;
            constexpr const auto name = "general_purpose_register";

            constexpr const auto rax = 0U;
            constexpr const auto rcx = 1U;
            constexpr const auto rdx = 2U;
            constexpr const auto rbx = 3U;
            constexpr const auto rsp = 4U;
            constexpr const auto rbp = 5U;
            constexpr const auto rsi = 6U;
            constexpr const auto rdi = 7U;
            constexpr const auto r8 = 8U;
            constexpr const auto r9 = 9U;
            constexpr const auto r10 = 10U;
            constexpr const auto r11 = 11U;
            constexpr const auto r12 = 12U;
            constexpr const auto r13 = 13U;
            constexpr const auto r14 = 14U;
            constexpr const auto r15 = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace io_instruction
    {
        constexpr const auto name = "io_instruction";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace size_of_access
        {
            constexpr const auto mask = 0x0000000000000007UL;
            constexpr const auto from = 0;
            constexpr const auto name = "size_of_access";

            constexpr const auto one_byte = 0U;
            constexpr const auto two_byte = 1U;
            constexpr const auto four_byte = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace direction_of_access
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 3;
            constexpr const auto name = "direction_of_access";

            constexpr const auto out = 0U;
            constexpr const auto in = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace string_instruction
        {
            constexpr const auto mask = 0x0000000000000010UL;
            constexpr const auto from = 4;
            constexpr const auto name = "string_instruction";

            constexpr const auto not_string = 0U;
            constexpr const auto string = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace rep_prefixed
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "rep_prefixed";

            constexpr const auto not_rep = 0U;
            constexpr const auto rep = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace operand_encoding
        {
            constexpr const auto mask = 0x0000000000000040UL;
            constexpr const auto from = 6;
            constexpr const auto name = "operand_encoding";

            constexpr const auto dx = 0U;
            constexpr const auto immediate = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFF0000FF80UL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace port_number
        {
            constexpr const auto mask = 0x00000000FFFF0000UL;
            constexpr const auto from = 16;
            constexpr const auto name = "port_number";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace mwait
    {
        constexpr const auto name = "mwait";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
    }

    namespace linear_apic_access
    {
        constexpr const auto name = "linear_apic_access";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace offset
        {
            constexpr const auto mask = 0x0000000000000FFFUL;
            constexpr const auto from = 0;
            constexpr const auto name = "offset";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace access_type
        {
            constexpr const auto mask = 0x000000000000F000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "access_type";

            constexpr const auto read_during_instruction_execution = 0U;
            constexpr const auto write_during_instruction_execution = 1U;
            constexpr const auto instruction_fetch = 2U;
            constexpr const auto event_delivery = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFF0000UL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace guest_physical_apic_access
    {
        constexpr const auto name = "guest_physical_apic_access";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace access_type
        {
            constexpr const auto mask = 0x000000000000F000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "access_type";

            constexpr const auto event_delivery = 10U;
            constexpr const auto instruction_fetch_or_execution = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFF0000UL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace ept_violation
    {
        constexpr const auto name = "ept_violation";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace data_read
        {
            constexpr const auto mask = 0x0000000000000001UL;
            constexpr const auto from = 0;
            constexpr const auto name = "data_read";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        namespace data_write
        {
            constexpr const auto mask = 0x0000000000000002UL;
            constexpr const auto from = 1;
            constexpr const auto name = "data_write";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        namespace instruction_fetch
        {
            constexpr const auto mask = 0x0000000000000004UL;
            constexpr const auto from = 2;
            constexpr const auto name = "instruction_fetch";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        namespace readable
        {
            constexpr const auto mask = 0x0000000000000008UL;
            constexpr const auto from = 3;
            constexpr const auto name = "readable";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        namespace writeable
        {
            constexpr const auto mask = 0x0000000000000010UL;
            constexpr const auto from = 4;
            constexpr const auto name = "writeable";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        namespace executable
        {
            constexpr const auto mask = 0x0000000000000020UL;
            constexpr const auto from = 5;
            constexpr const auto name = "executable";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        // bit 8 may be reserved to 0 if bit 7 is 0
        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFEE40UL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }

        namespace valid_guest_linear_address
        {
            constexpr const auto mask = 0x0000000000000080UL;
            constexpr const auto from = 7;
            constexpr const auto name = "valid_guest_linear_address";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }

        // intentionally left bit 8 out

        namespace nmi_unblocking_due_to_iret
        {
            constexpr const auto mask = 0x0000000000001000UL;
            constexpr const auto from = 12;
            constexpr const auto name = "nmi_unblocking_due_to_iret";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }
        }
    }

    namespace eoi_virtualization
    {
        constexpr const auto name = "eoi_virtualization";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace vector
        {
            constexpr const auto mask = 0x00000000000000FFUL;
            constexpr const auto from = 0;
            constexpr const auto name = "vector";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }

    namespace apic_write
    {
        constexpr const auto name = "apic_write";

        inline auto get_name()
        { return name; }

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false) noexcept
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace offset
        {
            constexpr const auto mask = 0x0000000000000FFFUL;
            constexpr const auto from = 0;
            constexpr const auto name = "offset";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get_if_exists(bool verbose = false) noexcept
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }
        }
    }
}

namespace io_rcx
{
    constexpr const auto addr = 0x0000000000006402UL;
    constexpr const auto name = "io_rcx";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
}

namespace io_rsi
{
    constexpr const auto addr = 0x0000000000006404UL;
    constexpr const auto name = "io_rsi";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
}

namespace io_rdi
{
    constexpr const auto addr = 0x0000000000006406UL;
    constexpr const auto name = "io_rdi";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
}

namespace io_rip
{
    constexpr const auto addr = 0x0000000000006408UL;
    constexpr const auto name = "io_rip";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
}

namespace guest_linear_address
{
    constexpr const auto addr = 0x000000000000640AUL;
    constexpr const auto name = "guest_linear_address";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
}

}
}

// *INDENT-ON*

#endif
