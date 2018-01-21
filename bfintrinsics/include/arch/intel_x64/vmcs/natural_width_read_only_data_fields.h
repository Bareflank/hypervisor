//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef VMCS_INTEL_X64_NATURAL_WIDTH_READ_ONLY_DATA_FIELDS_H
#define VMCS_INTEL_X64_NATURAL_WIDTH_READ_ONLY_DATA_FIELDS_H

#include <arch/intel_x64/vmcs/helpers.h>

/// Intel x86_64 VMCS Natural-Width Read-Only Data Fields
///
/// The following provides the interface for the natural-width read-only data VMCS
/// fields as defined in Appendix B.4.2, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace exit_qualification
{
    constexpr const auto addr = 0x0000000000006400ULL;
    constexpr const auto name = "exit_qualification";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }

    namespace debug_exception
    {
        constexpr const auto name = "debug_exception";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace b0
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "b0";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace b1
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "b1";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace b2
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "b2";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace b3
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "b3";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFF9FF0ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace bd
        {
            constexpr const auto mask = 0x0000000000002000ULL;
            constexpr const auto from = 13ULL;
            constexpr const auto name = "bd";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace bs
        {
            constexpr const auto mask = 0x0000000000004000ULL;
            constexpr const auto from = 14ULL;
            constexpr const auto name = "bs";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            b0::dump(level, msg);
            b1::dump(level, msg);
            b2::dump(level, msg);
            b3::dump(level, msg);
            reserved::dump(level, msg);
            bd::dump(level, msg);
            bs::dump(level, msg);
        }
    }

    namespace page_fault_exception
    {
        constexpr const auto name = "page_fault_exception";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace sipi
    {
        constexpr const auto name = "sipi";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace vector
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "vector";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            vector::dump(level, msg);
        }
    }

    namespace task_switch
    {
        constexpr const auto name = "task_switch";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace tss_selector
        {
            constexpr const auto mask = 0x000000000000FFFFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "tss_selector";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFF3FFF0000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace source_of_task_switch_init
        {
            constexpr const auto mask = 0x00000000C0000000ULL;
            constexpr const auto from = 30ULL;
            constexpr const auto name = "task_switch_init_source";

            constexpr const auto call_instruction = 0U;
            constexpr const auto iret_instruction = 1U;
            constexpr const auto jmp_instruction = 2U;
            constexpr const auto task_gate_in_idt = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            tss_selector::dump(level, msg);
            reserved::dump(level, msg);
            source_of_task_switch_init::dump(level, msg);
        }
    }

    namespace invept
    {
        constexpr const auto name = "invept";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace invpcid
    {
        constexpr const auto name = "invpcid";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace invvpid
    {
        constexpr const auto name = "invvpid";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace lgdt
    {
        constexpr const auto name = "lgdt";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace lidt
    {
        constexpr const auto name = "lidt";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace lldt
    {
        constexpr const auto name = "lldt";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace ltr
    {
        constexpr const auto name = "ltr";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace sgdt
    {
        constexpr const auto name = "sgdt";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace sidt
    {
        constexpr const auto name = "sidt";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace sldt
    {
        constexpr const auto name = "sldt";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace str
    {
        constexpr const auto name = "str";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace vmclear
    {
        constexpr const auto name = "vmclear";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace vmptrld
    {
        constexpr const auto name = "vmptrld";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace vmptrst
    {
        constexpr const auto name = "vmptrst";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace vmread
    {
        constexpr const auto name = "vmread";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace vmwrite
    {
        constexpr const auto name = "vmwrite";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace vmxon
    {
        constexpr const auto name = "vmxon";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace xrstors
    {
        constexpr const auto name = "xrstors";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace xsaves
    {
        constexpr const auto name = "xsaves";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace control_register_access
    {
        constexpr const auto name = "control_register_access";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace control_register_number
        {
            constexpr const auto mask = 0x000000000000000FULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "control_register_number";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace access_type
        {
            constexpr const auto mask = 0x0000000000000030ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "access_type";

            constexpr const auto mov_to_cr = 0U;
            constexpr const auto mov_from_cr = 1U;
            constexpr const auto clts = 2U;
            constexpr const auto lmsw = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace lmsw_operand_type
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "lmsw_operand_type";

            constexpr const auto reg = 0U;
            constexpr const auto mem = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFF0000F080ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace general_purpose_register
        {
            constexpr const auto mask = 0x0000000000000F00ULL;
            constexpr const auto from = 8ULL;
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

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace source_data
        {
            constexpr const auto mask = 0x00000000FFFF0000ULL;
            constexpr const auto from = 16ULL;
            constexpr const auto name = "source_data";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }

        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            control_register_number::dump(level, msg);
            access_type::dump(level, msg);
            lmsw_operand_type::dump(level, msg);
            reserved::dump(level, msg);
            general_purpose_register::dump(level, msg);
            source_data::dump(level, msg);
        }
    }

    namespace mov_dr
    {
        constexpr const auto name = "mov_dr";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace debug_register_number
        {
            constexpr const auto mask = 0x0000000000000007ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "debug_register_number";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFF0E8ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace direction_of_access
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "direction_of_access";

            constexpr const auto to_dr = 0U;
            constexpr const auto from_dr = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace general_purpose_register
        {
            constexpr const auto mask = 0x0000000000000F00ULL;
            constexpr const auto from = 8ULL;
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

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            debug_register_number::dump(level, msg);
            reserved::dump(level, msg);
            direction_of_access::dump(level, msg);
            general_purpose_register::dump(level, msg);
        }
    }

    namespace io_instruction
    {
        constexpr const auto name = "io_instruction";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace size_of_access
        {
            constexpr const auto mask = 0x0000000000000007ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "size_of_access";

            constexpr const auto one_byte = 0U;
            constexpr const auto two_byte = 1U;
            constexpr const auto four_byte = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace direction_of_access
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "direction_of_access";

            constexpr const auto out = 0U;
            constexpr const auto in = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace string_instruction
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "string_instruction";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace rep_prefixed
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "rep_prefixed";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace operand_encoding
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "operand_encoding";

            constexpr const auto dx = 0U;
            constexpr const auto immediate = 1U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFF0000FF80ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace port_number
        {
            constexpr const auto mask = 0x00000000FFFF0000ULL;
            constexpr const auto from = 16ULL;
            constexpr const auto name = "port_number";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            size_of_access::dump(level, msg);
            direction_of_access::dump(level, msg);
            string_instruction::dump(level, msg);
            rep_prefixed::dump(level, msg);
            operand_encoding::dump(level, msg);
            reserved::dump(level, msg);
            port_number::dump(level, msg);
        }
    }

    namespace mwait
    {
        constexpr const auto name = "mwait";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        inline void dump(int level, std::string *msg = nullptr)
        { dump_vmcs_nhex(level, msg); }
    }

    namespace linear_apic_access
    {
        constexpr const auto name = "linear_apic_access";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace offset
        {
            constexpr const auto mask = 0x0000000000000FFFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "offset";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace access_type
        {
            constexpr const auto mask = 0x000000000000F000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "access_type";

            constexpr const auto read_during_instruction_execution = 0U;
            constexpr const auto write_during_instruction_execution = 1U;
            constexpr const auto instruction_fetch = 2U;
            constexpr const auto event_delivery = 3U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFF0000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            offset::dump(level, msg);
            access_type::dump(level, msg);
            reserved::dump(level, msg);
        }
    }

    namespace guest_physical_apic_access
    {
        constexpr const auto name = "guest_physical_apic_access";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace access_type
        {
            constexpr const auto mask = 0x000000000000F000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "access_type";

            constexpr const auto event_delivery = 10U;
            constexpr const auto instruction_fetch_or_execution = 15U;

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFF0000ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            access_type::dump(level, msg);
            reserved::dump(level, msg);
        }
    }

    namespace ept_violation
    {
        constexpr const auto name = "ept_violation";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace data_read
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "data_read";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace data_write
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "data_write";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace instruction_fetch
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "instruction_fetch";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace readable
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "readable";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace writeable
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "writeable";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace executable
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "executable";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFEE40ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        namespace valid_guest_linear_address
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7ULL;
            constexpr const auto name = "valid_guest_linear_address";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        namespace nmi_unblocking_due_to_iret
        {
            constexpr const auto mask = 0x0000000000001000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "nmi_unblocking_due_to_iret";

            inline auto is_enabled()
            { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_enabled(value_type field)
            { return is_bit_set(field, from); }

            inline auto is_enabled_if_exists(bool verbose = false)
            { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline auto is_disabled()
            { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

            inline auto is_disabled(value_type field)
            { return is_bit_cleared(field, from); }

            inline auto is_disabled_if_exists(bool verbose = false)
            { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subbool(level, msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            data_read::dump(level, msg);
            data_write::dump(level, msg);
            instruction_fetch::dump(level, msg);
            readable::dump(level, msg);
            writeable::dump(level, msg);
            executable::dump(level, msg);
            reserved::dump(level, msg);
            valid_guest_linear_address::dump(level, msg);
            nmi_unblocking_due_to_iret::dump(level, msg);
        }
    }

    namespace eoi_virtualization
    {
        constexpr const auto name = "eoi_virtualization";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace vector
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "vector";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            vector::dump(level, msg);
        }
    }

    namespace apic_write
    {
        constexpr const auto name = "apic_write";

        inline auto get()
        { return get_vmcs_field(addr, name, exists()); }

        inline auto get_if_exists(bool verbose = false)
        { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

        namespace offset
        {
            constexpr const auto mask = 0x0000000000000FFFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "offset";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { dump_vmcs_subnhex(level, msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            dump_vmcs_nhex(level, msg);
            offset::dump(level, msg);
        }
    }
}

namespace io_rcx
{
    constexpr const auto addr = 0x0000000000006402ULL;
    constexpr const auto name = "io_rcx";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace io_rsi
{
    constexpr const auto addr = 0x0000000000006404ULL;
    constexpr const auto name = "io_rsi";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace io_rdi
{
    constexpr const auto addr = 0x0000000000006406ULL;
    constexpr const auto name = "io_rdi";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace io_rip
{
    constexpr const auto addr = 0x0000000000006408ULL;
    constexpr const auto name = "io_rip";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace guest_linear_address
{
    constexpr const auto addr = 0x000000000000640AULL;
    constexpr const auto name = "guest_linear_address";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

}
}

// *INDENT-ON*

#endif
