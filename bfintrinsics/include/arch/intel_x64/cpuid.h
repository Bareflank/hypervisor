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

#ifndef CPUID_INTEL_X64_H
#define CPUID_INTEL_X64_H

#include <arch/x64/cpuid.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace cpuid
{

using field_type = x64::cpuid::field_type;
using value_type = x64::cpuid::value_type;

namespace feature_information
{
    constexpr const auto addr = 0x00000001ULL;

    namespace eax
    {
        constexpr const auto name = "feature_information_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace stepping_id
        {
            constexpr const auto mask = 0x0000000FULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "stepping_id";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace model
        {
            constexpr const auto mask = 0x000000F0ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "model";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace family_id
        {
            constexpr const auto mask = 0x00000F00ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "family_id";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace processor_type
        {
            constexpr const auto mask = 0x00003000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "processor_type";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace extended_model_id
        {
            constexpr const auto mask = 0x000F0000ULL;
            constexpr const auto from = 16ULL;
            constexpr const auto name = "extended_model_id";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace extended_family_id
        {
            constexpr const auto mask = 0x0FF00000ULL;
            constexpr const auto from = 20ULL;
            constexpr const auto name = "extended_family_id";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            stepping_id::dump(level, msg);
            model::dump(level, msg);
            family_id::dump(level, msg);
            processor_type::dump(level, msg);
            extended_model_id::dump(level, msg);
            extended_family_id::dump(level, msg);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "feature_information_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace brand_index
        {
            constexpr const auto mask = 0x000000FFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "brand_index";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace clflush_line_size
        {
            constexpr const auto mask = 0x0000FF00ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "clflush_line_size";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace max_addressable_ids
        {
            constexpr const auto mask = 0x00FF0000ULL;
            constexpr const auto from = 16ULL;
            constexpr const auto name = "max_addressable_ids";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace initial_apic_id
        {
            constexpr const auto mask = 0xFF000000ULL;
            constexpr const auto from = 24ULL;
            constexpr const auto name = "initial_apic_id";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            brand_index::dump(level, msg);
            clflush_line_size::dump(level, msg);
            max_addressable_ids::dump(level, msg);
            initial_apic_id::dump(level, msg);
        }
    }

    namespace ecx
    {
        constexpr const auto name = "feature_information_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace sse3
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "sse3";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pclmulqdq
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "pclmulqdq";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace dtes64
        {
            constexpr const auto mask = 0x00000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "dtes64";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace monitor
        {
            constexpr const auto mask = 0x00000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "monitor";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace ds_cpl
        {
            constexpr const auto mask = 0x00000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "ds_cpl";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace vmx
        {
            constexpr const auto mask = 0x00000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "vmx";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace smx
        {
            constexpr const auto mask = 0x00000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "smx";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace eist
        {
            constexpr const auto mask = 0x00000080ULL;
            constexpr const auto from = 7ULL;
            constexpr const auto name = "eist";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace tm2
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "tm2";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace ssse3
        {
            constexpr const auto mask = 0x00000200ULL;
            constexpr const auto from = 9ULL;
            constexpr const auto name = "ssse3";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace cnxt_id
        {
            constexpr const auto mask = 0x00000400ULL;
            constexpr const auto from = 10ULL;
            constexpr const auto name = "cnxt_id";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace sdbg
        {
            constexpr const auto mask = 0x00000800ULL;
            constexpr const auto from = 11ULL;
            constexpr const auto name = "sdbg";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace fma
        {
            constexpr const auto mask = 0x00001000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "fma";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace cmpxchg16b
        {
            constexpr const auto mask = 0x00002000ULL;
            constexpr const auto from = 13ULL;
            constexpr const auto name = "cmpxchg16b";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace xtpr_update_control
        {
            constexpr const auto mask = 0x00004000ULL;
            constexpr const auto from = 14ULL;
            constexpr const auto name = "xtpr_update_control";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pdcm
        {
            constexpr const auto mask = 0x00008000ULL;
            constexpr const auto from = 15ULL;
            constexpr const auto name = "pdcm";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pcid
        {
            constexpr const auto mask = 0x00020000ULL;
            constexpr const auto from = 17ULL;
            constexpr const auto name = "pcid";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace dca
        {
            constexpr const auto mask = 0x00040000ULL;
            constexpr const auto from = 18ULL;
            constexpr const auto name = "dca";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace sse41
        {
            constexpr const auto mask = 0x00080000ULL;
            constexpr const auto from = 19ULL;
            constexpr const auto name = "sse41";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace sse42
        {
            constexpr const auto mask = 0x00100000ULL;
            constexpr const auto from = 20ULL;
            constexpr const auto name = "sse42";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace x2apic
        {
            constexpr const auto mask = 0x00200000ULL;
            constexpr const auto from = 21ULL;
            constexpr const auto name = "x2apic";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace movbe
        {
            constexpr const auto mask = 0x00400000ULL;
            constexpr const auto from = 22ULL;
            constexpr const auto name = "movbe";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace popcnt
        {
            constexpr const auto mask = 0x00800000ULL;
            constexpr const auto from = 23ULL;
            constexpr const auto name = "popcnt";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace tsc_deadline
        {
            constexpr const auto mask = 0x01000000ULL;
            constexpr const auto from = 24ULL;
            constexpr const auto name = "tsc_deadline";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace aesni
        {
            constexpr const auto mask = 0x02000000ULL;
            constexpr const auto from = 25ULL;
            constexpr const auto name = "aesni";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace xsave
        {
            constexpr const auto mask = 0x04000000ULL;
            constexpr const auto from = 26ULL;
            constexpr const auto name = "xsave";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace osxsave
        {
            constexpr const auto mask = 0x08000000ULL;
            constexpr const auto from = 27ULL;
            constexpr const auto name = "osxsave";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace avx
        {
            constexpr const auto mask = 0x10000000ULL;
            constexpr const auto from = 28ULL;
            constexpr const auto name = "avx";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace f16c
        {
            constexpr const auto mask = 0x20000000ULL;
            constexpr const auto from = 29ULL;
            constexpr const auto name = "f16c";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace rdrand
        {
            constexpr const auto mask = 0x40000000ULL;
            constexpr const auto from = 30ULL;
            constexpr const auto name = "rdrand";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            sse3::dump(level, msg);
            pclmulqdq::dump(level, msg);
            dtes64::dump(level, msg);
            monitor::dump(level, msg);
            ds_cpl::dump(level, msg);
            vmx::dump(level, msg);
            smx::dump(level, msg);
            eist::dump(level, msg);
            tm2::dump(level, msg);
            ssse3::dump(level, msg);
            cnxt_id::dump(level, msg);
            sdbg::dump(level, msg);
            fma::dump(level, msg);
            cmpxchg16b::dump(level, msg);
            xtpr_update_control::dump(level, msg);
            pdcm::dump(level, msg);
            pcid::dump(level, msg);
            dca::dump(level, msg);
            sse41::dump(level, msg);
            sse42::dump(level, msg);
            x2apic::dump(level, msg);
            movbe::dump(level, msg);
            popcnt::dump(level, msg);
            tsc_deadline::dump(level, msg);
            aesni::dump(level, msg);
            xsave::dump(level, msg);
            osxsave::dump(level, msg);
            avx::dump(level, msg);
            f16c::dump(level, msg);
            rdrand::dump(level, msg);
        }
    }

    namespace edx
    {
        constexpr const auto name = "feature_information_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace fpu
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "fpu";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace vme
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "vme";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace de
        {
            constexpr const auto mask = 0x00000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "de";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pse
        {
            constexpr const auto mask = 0x00000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "pse";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace tsc
        {
            constexpr const auto mask = 0x00000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "tsc";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace msr
        {
            constexpr const auto mask = 0x00000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "msr";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pae
        {
            constexpr const auto mask = 0x00000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "pae";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace mce
        {
            constexpr const auto mask = 0x00000080ULL;
            constexpr const auto from = 7ULL;
            constexpr const auto name = "mce";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace cx8
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "cx8";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace apic
        {
            constexpr const auto mask = 0x00000200ULL;
            constexpr const auto from = 9ULL;
            constexpr const auto name = "apic";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace sep
        {
            constexpr const auto mask = 0x00000800ULL;
            constexpr const auto from = 11ULL;
            constexpr const auto name = "sep";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace mtrr
        {
            constexpr const auto mask = 0x00001000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "mtrr";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pge
        {
            constexpr const auto mask = 0x00002000ULL;
            constexpr const auto from = 13ULL;
            constexpr const auto name = "pge";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace mca
        {
            constexpr const auto mask = 0x00004000ULL;
            constexpr const auto from = 14ULL;
            constexpr const auto name = "mca";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace cmov
        {
            constexpr const auto mask = 0x00008000ULL;
            constexpr const auto from = 15ULL;
            constexpr const auto name = "cmov";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pat
        {
            constexpr const auto mask = 0x00010000ULL;
            constexpr const auto from = 16ULL;
            constexpr const auto name = "pat";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pse_36
        {
            constexpr const auto mask = 0x00020000ULL;
            constexpr const auto from = 17ULL;
            constexpr const auto name = "pse_36";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace psn
        {
            constexpr const auto mask = 0x00040000ULL;
            constexpr const auto from = 18ULL;
            constexpr const auto name = "psn";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace clfsh
        {
            constexpr const auto mask = 0x00080000ULL;
            constexpr const auto from = 19ULL;
            constexpr const auto name = "clfsh";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace ds
        {
            constexpr const auto mask = 0x00200000ULL;
            constexpr const auto from = 21ULL;
            constexpr const auto name = "ds";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace acpi
        {
            constexpr const auto mask = 0x00400000ULL;
            constexpr const auto from = 22ULL;
            constexpr const auto name = "acpi";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace mmx
        {
            constexpr const auto mask = 0x00800000ULL;
            constexpr const auto from = 23ULL;
            constexpr const auto name = "mmx";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace fxsr
        {
            constexpr const auto mask = 0x01000000ULL;
            constexpr const auto from = 24ULL;
            constexpr const auto name = "fxsr";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace sse
        {
            constexpr const auto mask = 0x02000000ULL;
            constexpr const auto from = 25ULL;
            constexpr const auto name = "sse";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace sse2
        {
            constexpr const auto mask = 0x04000000ULL;
            constexpr const auto from = 26ULL;
            constexpr const auto name = "sse2";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace ss
        {
            constexpr const auto mask = 0x08000000ULL;
            constexpr const auto from = 27ULL;
            constexpr const auto name = "ss";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace htt
        {
            constexpr const auto mask = 0x10000000ULL;
            constexpr const auto from = 28ULL;
            constexpr const auto name = "htt";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace tm
        {
            constexpr const auto mask = 0x20000000ULL;
            constexpr const auto from = 29ULL;
            constexpr const auto name = "tm";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pbe
        {
            constexpr const auto mask = 0x80000000ULL;
            constexpr const auto from = 31ULL;
            constexpr const auto name = "pbe";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            fpu::dump(level, msg);
            vme::dump(level, msg);
            de::dump(level, msg);
            pse::dump(level, msg);
            tsc::dump(level, msg);
            msr::dump(level, msg);
            pae::dump(level, msg);
            mce::dump(level, msg);
            cx8::dump(level, msg);
            apic::dump(level, msg);
            sep::dump(level, msg);
            mtrr::dump(level, msg);
            pge::dump(level, msg);
            mca::dump(level, msg);
            cmov::dump(level, msg);
            pat::dump(level, msg);
            pse_36::dump(level, msg);
            psn::dump(level, msg);
            clfsh::dump(level, msg);
            ds::dump(level, msg);
            acpi::dump(level, msg);
            mmx::dump(level, msg);
            fxsr::dump(level, msg);
            sse::dump(level, msg);
            sse2::dump(level, msg);
            ss::dump(level, msg);
            htt::dump(level, msg);
            tm::dump(level, msg);
            pbe::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        eax::dump(level, msg);
        ebx::dump(level, msg);
        ecx::dump(level, msg);
        edx::dump(level, msg);
    }
}

namespace extended_feature_flags
{
    constexpr const auto addr = 0x00000007ULL;

    namespace subleaf0
    {
        constexpr const auto leaf = 0x0UL;

        namespace eax
        {
            constexpr const auto name = "extended_feature_flags_subleaf0_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace max_input
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "max_input";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                max_input::dump(level, msg);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "extended_feature_flags_subleaf0_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace fsgsbase
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "fsgsbase";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace ia32_tsc_adjust
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1ULL;
                constexpr const auto name = "ia32_tsc_adjust";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace sgx
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2ULL;
                constexpr const auto name = "sgx";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace bmi1
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3ULL;
                constexpr const auto name = "bmi1";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace hle
            {
                constexpr const auto mask = 0x00000010ULL;
                constexpr const auto from = 4ULL;
                constexpr const auto name = "hle";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace avx2
            {
                constexpr const auto mask = 0x00000020ULL;
                constexpr const auto from = 5ULL;
                constexpr const auto name = "avx2";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace fdp_excptn_only
            {
                constexpr const auto mask = 0x00000040ULL;
                constexpr const auto from = 6ULL;
                constexpr const auto name = "fdb_excptn_only";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace smep
            {
                constexpr const auto mask = 0x00000080ULL;
                constexpr const auto from = 7ULL;
                constexpr const auto name = "smep";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace bmi2
            {
                constexpr const auto mask = 0x00000100ULL;
                constexpr const auto from = 8ULL;
                constexpr const auto name = "bmi2";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace movsb
            {
                constexpr const auto mask = 0x00000200ULL;
                constexpr const auto from = 9ULL;
                constexpr const auto name = "movsb";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace invpcid
            {
                constexpr const auto mask = 0x00000400ULL;
                constexpr const auto from = 10ULL;
                constexpr const auto name = "invpcid";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace rtm
            {
                constexpr const auto mask = 0x00000800ULL;
                constexpr const auto from = 11ULL;
                constexpr const auto name = "rtm";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace rtm_m
            {
                constexpr const auto mask = 0x00001000ULL;
                constexpr const auto from = 12ULL;
                constexpr const auto name = "rtm_m";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace fpucs_fpuds
            {
                constexpr const auto mask = 0x00002000ULL;
                constexpr const auto from = 13ULL;
                constexpr const auto name = "fpucs_fpuds";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace mpx
            {
                constexpr const auto mask = 0x00004000ULL;
                constexpr const auto from = 14ULL;
                constexpr const auto name = "mpx";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace rdt_a
            {
                constexpr const auto mask = 0x00008000ULL;
                constexpr const auto from = 15ULL;
                constexpr const auto name = "rdt_a";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace rdseed
            {
                constexpr const auto mask = 0x00040000ULL;
                constexpr const auto from = 18ULL;
                constexpr const auto name = "rdseed";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace adx
            {
                constexpr const auto mask = 0x00080000ULL;
                constexpr const auto from = 19ULL;
                constexpr const auto name = "adx";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace smap
            {
                constexpr const auto mask = 0x00100000ULL;
                constexpr const auto from = 20ULL;
                constexpr const auto name = "smap";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace clflushopt
            {
                constexpr const auto mask = 0x00800000ULL;
                constexpr const auto from = 23ULL;
                constexpr const auto name = "clflushopt";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace clwb
            {
                constexpr const auto mask = 0x01000000ULL;
                constexpr const auto from = 24ULL;
                constexpr const auto name = "clwb";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace trace
            {
                constexpr const auto mask = 0x02000000ULL;
                constexpr const auto from = 25ULL;
                constexpr const auto name = "trace";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace sha
            {
                constexpr const auto mask = 0x20000000ULL;
                constexpr const auto from = 29ULL;
                constexpr const auto name = "sha";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                fsgsbase::dump(level, msg);
                ia32_tsc_adjust::dump(level, msg);
                sgx::dump(level, msg);
                bmi1::dump(level, msg);
                hle::dump(level, msg);
                avx2::dump(level, msg);
                fdp_excptn_only::dump(level, msg);
                smep::dump(level, msg);
                bmi2::dump(level, msg);
                movsb::dump(level, msg);
                invpcid::dump(level, msg);
                rtm::dump(level, msg);
                rtm_m::dump(level, msg);
                fpucs_fpuds::dump(level, msg);
                mpx::dump(level, msg);
                rdt_a::dump(level, msg);
                rdseed::dump(level, msg);
                adx::dump(level, msg);
                smap::dump(level, msg);
                clflushopt::dump(level, msg);
                clwb::dump(level, msg);
                trace::dump(level, msg);
                sha::dump(level, msg);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "extended_feature_flags_subleaf0_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace prefetchwt1
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "prefetchwt1";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace umip
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2ULL;
                constexpr const auto name = "umip";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace pku
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3ULL;
                constexpr const auto name = "pku";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace ospke
            {
                constexpr const auto mask = 0x00000010ULL;
                constexpr const auto from = 4ULL;
                constexpr const auto name = "ospke";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace mawau
            {
                constexpr const auto mask = 0x003E0000ULL;
                constexpr const auto from = 17ULL;
                constexpr const auto name = "mawau";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            namespace rdpid
            {
                constexpr const auto mask = 0x00400000ULL;
                constexpr const auto from = 22ULL;
                constexpr const auto name = "rdpid";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace sgx_lc
            {
                constexpr const auto mask = 0x40000000ULL;
                constexpr const auto from = 30ULL;
                constexpr const auto name = "sgx_lc";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                prefetchwt1::dump(level, msg);
                umip::dump(level, msg);
                pku::dump(level, msg);
                ospke::dump(level, msg);
                mawau::dump(level, msg);
                rdpid::dump(level, msg);
                sgx_lc::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            ecx::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        subleaf0::dump(level, msg);
    }
}

namespace arch_perf_monitoring
{
    constexpr const auto addr = 0x0000000AULL;

    namespace eax
    {
        constexpr const auto name = "arch_perf_monitoring_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace version_id
        {
            constexpr const auto mask = 0x000000FFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "version_id";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace gppmc_count
        {
            constexpr const auto mask = 0x0000FF00ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "gppmc_count";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace gppmc_bit_width
        {
            constexpr const auto mask = 0x00FF0000ULL;
            constexpr const auto from = 16ULL;
            constexpr const auto name = "gppmc_bit_width";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace ebx_enumeration_length
        {
            constexpr const auto mask = 0xFF000000ULL;
            constexpr const auto from = 24ULL;
            constexpr const auto name = "ebx_enumeration_length";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            version_id::dump(level, msg);
            gppmc_count::dump(level, msg);
            gppmc_bit_width::dump(level, msg);
            ebx_enumeration_length::dump(level, msg);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "arch_perf_monitoring_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace core_cycle_event
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "core_cycle_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace instr_retired_event
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "instr_retired_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace reference_cycles_event
        {
            constexpr const auto mask = 0x00000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "reference_cycles_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace llc_reference_event
        {
            constexpr const auto mask = 0x00000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "llc_reference_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace llc_misses_event
        {
            constexpr const auto mask = 0x00000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "llc_misses_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace branch_instr_retired_event
        {
            constexpr const auto mask = 0x00000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "branch_instr_retired_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace branch_mispredict_retired_event
        {
            constexpr const auto mask = 0x00000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "branch_mispredict_retired_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            core_cycle_event::dump(level, msg);
            instr_retired_event::dump(level, msg);
            reference_cycles_event::dump(level, msg);
            llc_reference_event::dump(level, msg);
            llc_misses_event::dump(level, msg);
            branch_instr_retired_event::dump(level, msg);
            branch_mispredict_retired_event::dump(level, msg);
        }
    }

    namespace edx
    {
        constexpr const auto name = "arch_perf_monitoring_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace ffpmc_count
        {
            constexpr const auto mask = 0x0000001FULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "ffpmc_count";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace ffpmc_bit_width
        {
            constexpr const auto mask = 0x00001FE0ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "ffpmc_bit_width";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            ffpmc_count::dump(level, msg);
            ffpmc_bit_width::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        eax::dump(level, msg);
        ebx::dump(level, msg);
        edx::dump(level, msg);
    }
}

namespace cache_tlb_info
{
    constexpr const auto addr = 0x00000002ULL;

    namespace eax
    {
        constexpr const auto name = "cache_tlb_info_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ebx
    {
        constexpr const auto name = "cache_tlb_info_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ecx
    {
        constexpr const auto name = "cache_tlb_info_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace edx
    {
        constexpr const auto name = "cache_tlb_info_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        eax::dump(level, msg);
        ebx::dump(level, msg);
        ecx::dump(level, msg);
        edx::dump(level, msg);
    }
}

namespace serial_num
{
    constexpr const auto addr = 0x00000003ULL;

    namespace ecx
    {
        constexpr const auto name = "cache_tlb_info_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace edx
    {
        constexpr const auto name = "cache_tlb_info_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        ecx::dump(level, msg);
        edx::dump(level, msg);
    }
}

namespace cache_parameters
{
    constexpr const auto addr = 0x00000004ULL;

    namespace eax
    {
        constexpr const auto name = "cache_parameters_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace cache_type
        {
            constexpr const auto mask = 0x0000001FULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "cache_type";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace cache_level
        {
            constexpr const auto mask = 0x000000E0ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "cache_level";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace self_init_level
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "self_init_level";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace fully_associative
        {
            constexpr const auto mask = 0x00000200ULL;
            constexpr const auto from = 9ULL;
            constexpr const auto name = "fully_associative";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace max_ids_logical
        {
            constexpr const auto mask = 0x03FFC000ULL;
            constexpr const auto from = 14ULL;
            constexpr const auto name = "max_ids_logical";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace max_ids_physical
        {
            constexpr const auto mask = 0xFC000000ULL;
            constexpr const auto from = 26ULL;
            constexpr const auto name = "max_ids_physical";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            cache_type::dump(level, msg);
            cache_level::dump(level, msg);
            self_init_level::dump(level, msg);
            fully_associative::dump(level, msg);
            max_ids_logical::dump(level, msg);
            max_ids_physical::dump(level, msg);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "cache_parameters_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace l
        {
            constexpr const auto mask = 0x00000FFFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "l";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace p
        {
            constexpr const auto mask = 0x003FF000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "p";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace w
        {
            constexpr const auto mask = 0xFFC00000ULL;
            constexpr const auto from = 22ULL;
            constexpr const auto name = "w";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            l::dump(level, msg);
            p::dump(level, msg);
            w::dump(level, msg);
        }
    }

    namespace ecx
    {
        constexpr const auto name = "cache_parameters_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace num_sets
        {
            constexpr const auto mask = 0xFFFFFFFFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "num_sets";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            num_sets::dump(level, msg);
        }
    }

    namespace edx
    {
        constexpr const auto name = "cache_parameters_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace wbinvd_invd
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "wbinvd_invd";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace cache_inclusiveness
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "cache_inclusiveness";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace complex_cache_indexing
        {
            constexpr const auto mask = 0x00000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "complex_cache_indexing";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            wbinvd_invd::dump(level, msg);
            cache_inclusiveness::dump(level, msg);
            complex_cache_indexing::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        eax::dump(level, msg);
        ebx::dump(level, msg);
        ecx::dump(level, msg);
        edx::dump(level, msg);
    }
}

namespace monitor_mwait
{
    constexpr const auto addr = 0x00000005ULL;

    namespace eax
    {
        constexpr const auto name = "monitor_mwait_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace min_line_size
        {
            constexpr const auto mask = 0x0000FFFFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "min_line_size";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            min_line_size::dump(level, msg);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "monitor_mwait_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace max_line_size
        {
            constexpr const auto mask = 0x0000FFFFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "max_line_size";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            max_line_size::dump(level, msg);
        }
    }

    namespace ecx
    {
        constexpr const auto name = "monitor_mwait_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace enum_mwait_extensions
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "enum_mwait_extensions";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace interrupt_break_event
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "interrupt_break_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            enum_mwait_extensions::dump(level, msg);
            interrupt_break_event::dump(level, msg);
        }
    }

    namespace edx
    {
        constexpr const auto name = "monitor_mwait_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace num_c0
        {
            constexpr const auto mask = 0x0000000FULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "num_c0";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace num_c1
        {
            constexpr const auto mask = 0x000000F0ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "num_c1";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace num_c2
        {
            constexpr const auto mask = 0x00000F00ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "num_c2";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace num_c3
        {
            constexpr const auto mask = 0x0000F000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "num_c3";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace num_c4
        {
            constexpr const auto mask = 0x000F0000ULL;
            constexpr const auto from = 16ULL;
            constexpr const auto name = "num_c4";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace num_c5
        {
            constexpr const auto mask = 0x00F00000ULL;
            constexpr const auto from = 20ULL;
            constexpr const auto name = "num_c5";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace num_c6
        {
            constexpr const auto mask = 0x0F000000ULL;
            constexpr const auto from = 24ULL;
            constexpr const auto name = "num_c6";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace num_c7
        {
            constexpr const auto mask = 0xF0000000ULL;
            constexpr const auto from = 28ULL;
            constexpr const auto name = "num_c7";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            num_c0::dump(level, msg);
            num_c1::dump(level, msg);
            num_c2::dump(level, msg);
            num_c3::dump(level, msg);
            num_c4::dump(level, msg);
            num_c5::dump(level, msg);
            num_c6::dump(level, msg);
            num_c7::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        eax::dump(level, msg);
        ebx::dump(level, msg);
        ecx::dump(level, msg);
        edx::dump(level, msg);
    }
}

namespace therm_power_management
{
    constexpr const auto addr = 0x00000006ULL;

    namespace eax
    {
        constexpr const auto name = "therm_power_management_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace temp_sensor
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "temp_sensor";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace intel_turbo
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "intel_turbo";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace arat
        {
            constexpr const auto mask = 0x00000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "arat";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pln
        {
            constexpr const auto mask = 0x00000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "pln";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace ecmd
        {
            constexpr const auto mask = 0x00000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "ecmd";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace ptm
        {
            constexpr const auto mask = 0x00000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "ptm";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace hwp
        {
            constexpr const auto mask = 0x00000080ULL;
            constexpr const auto from = 7ULL;
            constexpr const auto name = "hwp";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace hwp_notification
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "hwp_notification";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace hwp_activity_window
        {
            constexpr const auto mask = 0x00000200ULL;
            constexpr const auto from = 9ULL;
            constexpr const auto name = "hwp_activity_window";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace hwp_energy_perf
        {
            constexpr const auto mask = 0x00000400ULL;
            constexpr const auto from = 10ULL;
            constexpr const auto name = "hwp_energy_perf";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace hwp_package_request
        {
            constexpr const auto mask = 0x00000800ULL;
            constexpr const auto from = 11ULL;
            constexpr const auto name = "hwp_package_request";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace hdc
        {
            constexpr const auto mask = 0x00002000ULL;
            constexpr const auto from = 13ULL;
            constexpr const auto name = "hdc";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            temp_sensor::dump(level, msg);
            intel_turbo::dump(level, msg);
            arat::dump(level, msg);
            pln::dump(level, msg);
            ecmd::dump(level, msg);
            ptm::dump(level, msg);
            hwp::dump(level, msg);
            hwp_notification::dump(level, msg);
            hwp_activity_window::dump(level, msg);
            hwp_energy_perf::dump(level, msg);
            hwp_package_request::dump(level, msg);
            hdc::dump(level, msg);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "therm_power_management_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace num_interrupts
        {
            constexpr const auto mask = 0x0000000FULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "num_interrupts";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            num_interrupts::dump(level, msg);
        }
    }

    namespace ecx
    {
        constexpr const auto name = "therm_power_management_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace hardware_feedback
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "hardware_feedback";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace energy_perf_bias
        {
            constexpr const auto mask = 0x00000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "energy_perf_bias";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            hardware_feedback::dump(level, msg);
            energy_perf_bias::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        eax::dump(level, msg);
        ebx::dump(level, msg);
        ecx::dump(level, msg);
    }
}

namespace access_cache
{
    constexpr const auto addr = 0x00000009ULL;

    namespace eax
    {
        constexpr const auto name = "access_cache_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        eax::dump(level, msg);
    }
}

namespace topology_enumeration
{
    constexpr const auto addr = 0x0000000BULL;

    namespace eax
    {
        constexpr const auto name = "topology_enumeration_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace x2apic_shift
        {
            constexpr const auto mask = 0x0000001FULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "x2apic_shift";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            x2apic_shift::dump(level, msg);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "topology_enumeration_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace num_processors
        {
            constexpr const auto mask = 0x0000FFFFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "num_processors";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            num_processors::dump(level, msg);
        }
    }

    namespace ecx
    {
        constexpr const auto name = "topology_enumeration_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace level_number
        {
            constexpr const auto mask = 0x000000FFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "level_number";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace level_type
        {
            constexpr const auto mask = 0x0000FF00ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "level_type";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            level_number::dump(level, msg);
            level_type::dump(level, msg);
        }
    }

    namespace edx
    {
        constexpr const auto name = "topology_enumeration_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace x2apic_id
        {
            constexpr const auto mask = 0xFFFFFFFFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "x2apic_id";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            x2apic_id::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        eax::dump(level, msg);
        ebx::dump(level, msg);
        ecx::dump(level, msg);
        edx::dump(level, msg);
    }
}

namespace extended_state_enum
{
    constexpr const auto addr = 0x0000000DULL;

    namespace mainleaf
    {
        constexpr const auto leaf = 0UL;

        namespace eax
        {
            constexpr const auto name = "extended_state_enum_mainleaf_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        namespace ebx
        {
            constexpr const auto name = "extended_state_enum_mainleaf_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        namespace ecx
        {
            constexpr const auto name = "extended_state_enum_mainleaf_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        namespace edx
        {
            constexpr const auto name = "extended_state_enum_mainleaf_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            ecx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace eax
        {
            constexpr const auto name = "extended_state_enum_subleaf1_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace xsaveopt
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "xsaveopt";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace xsavec
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1ULL;
                constexpr const auto name = "xsavec";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace xgetbv
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2ULL;
                constexpr const auto name = "xgetbv";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace xsaves_xrstors
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3ULL;
                constexpr const auto name = "xsaves_xrstors";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                xsaveopt::dump(level, msg);
                xsavec::dump(level, msg);
                xgetbv::dump(level, msg);
                xsaves_xrstors::dump(level, msg);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "extended_state_enum_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace xsave_size
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "xsave_size";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                xsave_size::dump(level, msg);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "extended_state_enum_subleaf1_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace supported_bits
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "supported_bits";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                supported_bits::dump(level, msg);
            }
        }

        namespace edx
        {
            constexpr const auto name = "extended_state_enum_subleaf1_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace supported_bits
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "supported_bits";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                supported_bits::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            ecx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        mainleaf::dump(level, msg);
        subleaf1::dump(level, msg);
    }
}

namespace intel_rdt
{
    constexpr const auto addr = 0x0000000FULL;

    namespace subleaf0
    {
        constexpr const auto leaf = 0UL;

        namespace ebx
        {
            constexpr const auto name = "intel_rdt_subleaf0_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace rmid_max_range
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "rmid_max_range";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                rmid_max_range::dump(level, msg);
            }
        }

        namespace edx
        {
            constexpr const auto name = "intel_rdt_subleaf0_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace l3_rdt
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1ULL;
                constexpr const auto name = "l3_rdt";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subedx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subedx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                l3_rdt::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            ebx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace ebx
        {
            constexpr const auto name = "intel_rdt_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace conversion_factor
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "conversion_factor";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                conversion_factor::dump(level, msg);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "intel_rdt_subleaf1_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace rmid_max_range
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "rmid_max_range";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                rmid_max_range::dump(level, msg);
            }
        }

        namespace edx
        {
            constexpr const auto name = "intel_rdt_subleaf1_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace l3_occupancy
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "l3_occupancy";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subedx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subedx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace l3_total_bandwith
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1ULL;
                constexpr const auto name = "l3_total_bandwith";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subedx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subedx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace l3_local_bandwith
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2ULL;
                constexpr const auto name = "l3_local_bandwith";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subedx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subedx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                l3_occupancy::dump(level, msg);
                l3_total_bandwith::dump(level, msg);
                l3_local_bandwith::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            ebx::dump(level, msg);
            ecx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        subleaf0::dump(level, msg);
        subleaf1::dump(level, msg);
    }
}

namespace allocation_enumeration
{
    constexpr const auto addr = 0x00000010ULL;

    namespace subleaf0
    {
        constexpr const auto leaf = 0UL;

        namespace ebx
        {
            constexpr const auto name = "allocation_enumeration_subleaf0_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace l3_cache
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1ULL;
                constexpr const auto name = "l3_cache";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace l2_cache
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2ULL;
                constexpr const auto name = "l2_cache";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace mem_bandwidth
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3ULL;
                constexpr const auto name = "mem_bandwidth";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                l3_cache::dump(level, msg);
                l2_cache::dump(level, msg);
                mem_bandwidth::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            ebx::dump(level, msg);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace eax
        {
            constexpr const auto name = "allocation_enumeration_subleaf1_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace mask_length
            {
                constexpr const auto mask = 0x0000001FULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "mask_length";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                mask_length::dump(level, msg);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "allocation_enumeration_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace map
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "map";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                map::dump(level, msg);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "allocation_enumeration_subleaf1_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace data_prio
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2ULL;
                constexpr const auto name = "data_prio";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                data_prio::dump(level, msg);
            }
        }

        namespace edx
        {
            constexpr const auto name = "allocation_enumeration_subleaf1_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace max_cos
            {
                constexpr const auto mask = 0x0000FFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "max_cos";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                max_cos::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            ecx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    namespace subleaf2
    {
        constexpr const auto leaf = 2UL;

        namespace eax
        {
            constexpr const auto name = "allocation_enumeration_subleaf2_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace mask_length
            {
                constexpr const auto mask = 0x0000001FULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "mask_length";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                mask_length::dump(level, msg);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "allocation_enumeration_subleaf2_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace map
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "map";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                map::dump(level, msg);
            }
        }

        namespace edx
        {
            constexpr const auto name = "allocation_enumeration_subleaf2_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace max_cos
            {
                constexpr const auto mask = 0x0000FFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "max_cos";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                max_cos::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    namespace subleaf3
    {
        constexpr const auto leaf = 3UL;

        namespace eax
        {
            constexpr const auto name = "allocation_enumeration_subleaf3_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace max_throttle
            {
                constexpr const auto mask = 0x00000FFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "max_throttle";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                max_throttle::dump(level, msg);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "allocation_enumeration_subleaf3_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace linear
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2ULL;
                constexpr const auto name = "linear";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                linear::dump(level, msg);
            }
        }

        namespace edx
        {
            constexpr const auto name = "allocation_enumeration_subleaf3_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace max_cos
            {
                constexpr const auto mask = 0x0000FFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "max_cos";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                max_cos::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ecx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        subleaf0::dump(level, msg);
        subleaf1::dump(level, msg);
        subleaf2::dump(level, msg);
        subleaf3::dump(level, msg);
    }
}

namespace intel_sgx
{
    constexpr const auto addr = 0x00000012ULL;

    namespace subleaf0
    {
        constexpr const auto leaf = 0UL;

        namespace eax
        {
            constexpr const auto name = "intel_sgx_subleaf0_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace sgx1
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "sgx1";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace sgx2
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1ULL;
                constexpr const auto name = "sgx2";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                sgx1::dump(level, msg);
                sgx2::dump(level, msg);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "intel_sgx_subleaf0_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace miscselect
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "miscselect";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                miscselect::dump(level, msg);
            }
        }

        namespace edx
        {
            constexpr const auto name = "intel_sgx_subleaf0_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace mes_not64
            {
                constexpr const auto mask = 0x000000FFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "mes_not64";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            namespace mes_64
            {
                constexpr const auto mask = 0x0000FF00ULL;
                constexpr const auto from = 8ULL;
                constexpr const auto name = "mes_64";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                mes_not64::dump(level, msg);
                mes_64::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace eax
        {
            constexpr const auto name = "intel_sgx_subleaf1_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        namespace ebx
        {
            constexpr const auto name = "intel_sgx_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        namespace ecx
        {
            constexpr const auto name = "intel_sgx_subleaf1_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        namespace edx
        {
            constexpr const auto name = "intel_sgx_subleaf1_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            ecx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    namespace subleaf2
    {
        constexpr const auto leaf = 2UL;

        namespace eax
        {
            constexpr const auto name = "intel_sgx_subleaf2_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace subleaf_type
            {
                constexpr const auto mask = 0x0000000FULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "subleaf_type";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            namespace address
            {
                constexpr const auto mask = 0xFFFFF000ULL;
                constexpr const auto from = 12ULL;
                constexpr const auto name = "address";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                subleaf_type::dump(level, msg);
                address::dump(level, msg);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "intel_sgx_subleaf2_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace address
            {
                constexpr const auto mask = 0x000FFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "address";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                address::dump(level, msg);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "intel_sgx_subleaf2_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace epc_property
            {
                constexpr const auto mask = 0x0000000FULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "epc_property";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            namespace epc_size
            {
                constexpr const auto mask = 0xFFFFF000ULL;
                constexpr const auto from = 12ULL;
                constexpr const auto name = "epc_size";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                epc_property::dump(level, msg);
                epc_size::dump(level, msg);
            }
        }

        namespace edx
        {
            constexpr const auto name = "intel_sgx_subleaf2_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace epc_size
            {
                constexpr const auto mask = 0x000FFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "epc_size";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                epc_size::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            ecx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        subleaf0::dump(level, msg);
        subleaf1::dump(level, msg);
        subleaf2::dump(level, msg);
    }
}

namespace trace_enumeration
{
    constexpr const auto addr = 0x00000014ULL;

    namespace mainleaf
    {
        constexpr const auto leaf = 0UL;

        namespace eax
        {
            constexpr const auto name = "trace_enumeration_mainleaf_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace max_subleaf
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "max_subleaf";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                max_subleaf::dump(level, msg);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "trace_enumeration_mainleaf_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace ia32_rtit_ctlcr3filter
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "ia32_rtit_ctlcr3filter";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace configurable_psb
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1ULL;
                constexpr const auto name = "configurable_psb";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace ip_filtering
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2ULL;
                constexpr const auto name = "ip_filtering";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace mtc_timing_packet
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3ULL;
                constexpr const auto name = "mtc_timing_packet";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace ptwrite
            {
                constexpr const auto mask = 0x00000010ULL;
                constexpr const auto from = 4ULL;
                constexpr const auto name = "ptwrite";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace power_event_trace
            {
                constexpr const auto mask = 0x00000020ULL;
                constexpr const auto from = 5ULL;
                constexpr const auto name = "power_event_trace";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                ia32_rtit_ctlcr3filter::dump(level, msg);
                configurable_psb::dump(level, msg);
                ip_filtering::dump(level, msg);
                mtc_timing_packet::dump(level, msg);
                ptwrite::dump(level, msg);
                power_event_trace::dump(level, msg);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "trace_enumeration_mainleaf_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace trading_enabled
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "trading_enabled";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace topa_entry
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1ULL;
                constexpr const auto name = "topa_entry";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace single_range_output
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2ULL;
                constexpr const auto name = "single_range_output";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace trace_transport
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3ULL;
                constexpr const auto name = "trace_transport";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            namespace lip_values
            {
                constexpr const auto mask = 0x80000000ULL;
                constexpr const auto from = 31ULL;
                constexpr const auto name = "lip_values";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                trading_enabled::dump(level, msg);
                topa_entry::dump(level, msg);
                single_range_output::dump(level, msg);
                trace_transport::dump(level, msg);
                lip_values::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            ecx::dump(level, msg);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace eax
        {
            constexpr const auto name = "trace_enumeration_subleaf1_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace num_address_ranges
            {
                constexpr const auto mask = 0x00000007ULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "num_address_ranges";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            namespace bitmap_mtc
            {
                constexpr const auto mask = 0xFFFF0000ULL;
                constexpr const auto from = 16ULL;
                constexpr const auto name = "bitmap_mtc";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                num_address_ranges::dump(level, msg);
                bitmap_mtc::dump(level, msg);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "trace_enumeration_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace bitmap_cycle_threshold
            {
                constexpr const auto mask = 0x0000FFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "bitmap_cycle_threshold";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            namespace bitmap_psb
            {
                constexpr const auto mask = 0xFFFF0000ULL;
                constexpr const auto from = 16ULL;
                constexpr const auto name = "bitmap_psb";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                bitmap_cycle_threshold::dump(level, msg);
                bitmap_psb::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        mainleaf::dump(level, msg);
        subleaf1::dump(level, msg);
    }
}

namespace time_stamp_count
{
    constexpr const auto addr = 0x00000015ULL;

    namespace eax
    {
        constexpr const auto name = "time_stamp_count_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ebx
    {
        constexpr const auto name = "time_stamp_count_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ecx
    {
        constexpr const auto name = "time_stamp_count_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        eax::dump(level, msg);
        ebx::dump(level, msg);
        ecx::dump(level, msg);
    }
}

namespace processor_freq
{
    constexpr const auto addr = 0x00000016ULL;

    namespace eax
    {
        constexpr const auto name = "processor_freq_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ebx
    {
        constexpr const auto name = "processor_freq_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    namespace ecx
    {
        constexpr const auto name = "processor_freq_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_nhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        eax::dump(level, msg);
        ebx::dump(level, msg);
        ecx::dump(level, msg);
    }
}

namespace vendor_attribute
{
    constexpr const auto addr = 0x00000017ULL;

    namespace mainleaf
    {
        constexpr const auto leaf = 0UL;

        namespace eax
        {
            constexpr const auto name = "vendor_attribute_mainleaf_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace max_socid
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "max_socid";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                max_socid::dump(level, msg);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "vendor_attribute_mainleaf_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace soc_vendor
            {
                constexpr const auto mask = 0x0000FFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "soc_vendor";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            namespace is_vendor_scheme
            {
                constexpr const auto mask = 0x00010000ULL;
                constexpr const auto from = 16ULL;
                constexpr const auto name = "is_vendor_scheme";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subbool(level, name, is_enabled(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                soc_vendor::dump(level, msg);
                is_vendor_scheme::dump(level, msg);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "vendor_attribute_mainleaf_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace project_id
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "project_id";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                project_id::dump(level, msg);
            }
        }

        namespace edx
        {
            constexpr const auto name = "vendor_attribute_mainleaf_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace stepping_id
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "stepping_id";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level, std::string *msg = nullptr)
                { bfdebug_subnhex(level, name, get(), msg); }
            }

            inline void dump(int level, std::string *msg = nullptr)
            {
                bfdebug_nhex(level, name, get(), msg);
                stepping_id::dump(level, msg);
            }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            ecx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace eax
        {
            constexpr const auto name = "vendor_attribute_subleaf1_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        namespace ebx
        {
            constexpr const auto name = "vendor_attribute_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        namespace ecx
        {
            constexpr const auto name = "vendor_attribute_subleaf1_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        namespace edx
        {
            constexpr const auto name = "vendor_attribute_subleaf1_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_nhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            eax::dump(level, msg);
            ebx::dump(level, msg);
            ecx::dump(level, msg);
            edx::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        mainleaf::dump(level, msg);
        subleaf1::dump(level, msg);
    }
}

namespace ext_feature_info
{
    constexpr const auto addr = 0x80000001ULL;

    namespace ecx
    {
        constexpr const auto name = "ext_feature_info_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace lahf_sahf
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "lahf_sahf";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace lzcnt
        {
            constexpr const auto mask = 0x00000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "lzcnt";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace prefetchw
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "prefetchw";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            lahf_sahf::dump(level, msg);
            lzcnt::dump(level, msg);
            prefetchw::dump(level, msg);
        }
    }

    namespace edx
    {
        constexpr const auto name = "ext_feature_info_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace syscall_sysret
        {
            constexpr const auto mask = 0x00000800ULL;
            constexpr const auto from = 11ULL;
            constexpr const auto name = "syscall_sysret";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace execute_disable_bit
        {
            constexpr const auto mask = 0x00100000ULL;
            constexpr const auto from = 20ULL;
            constexpr const auto name = "execute_disable_bit";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace pages_avail
        {
            constexpr const auto mask = 0x04000000ULL;
            constexpr const auto from = 26ULL;
            constexpr const auto name = "pages_avail";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace rdtscp
        {
            constexpr const auto mask = 0x08000000ULL;
            constexpr const auto from = 27ULL;
            constexpr const auto name = "rdtscp";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        namespace intel_64
        {
            constexpr const auto mask = 0x20000000ULL;
            constexpr const auto from = 29ULL;
            constexpr const auto name = "intel_64";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            syscall_sysret::dump(level, msg);
            execute_disable_bit::dump(level, msg);
            pages_avail::dump(level, msg);
            rdtscp::dump(level, msg);
            intel_64::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        ecx::dump(level, msg);
        edx::dump(level, msg);
    }
}

namespace l2_info
{
    constexpr const auto addr = 0x80000006ULL;

    namespace ecx
    {
        constexpr const auto name = "l2_info_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace line_size
        {
            constexpr const auto mask = 0x000000FFULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "line_size";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace l2_associativity
        {
            constexpr const auto mask = 0x0000F000ULL;
            constexpr const auto from = 12ULL;
            constexpr const auto name = "l2_associativity";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        namespace cache_size
        {
            constexpr const auto mask = 0xFFFF0000ULL;
            constexpr const auto from = 16ULL;
            constexpr const auto name = "cache_size";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subnhex(level, name, get(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            line_size::dump(level, msg);
            l2_associativity::dump(level, msg);
            cache_size::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        ecx::dump(level, msg);
    }
}

namespace invariant_tsc
{
    constexpr const auto addr = 0x80000007ULL;

    namespace edx
    {
        constexpr const auto name = "invariant_tsc_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace available
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8ULL;
            constexpr const auto name = "available";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level, std::string *msg = nullptr)
            { bfdebug_subbool(level, name, is_enabled(), msg); }
        }

        inline void dump(int level, std::string *msg = nullptr)
        {
            bfdebug_nhex(level, name, get(), msg);
            available::dump(level, msg);
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        edx::dump(level, msg);
    }
}

}
}

// *INDENT-ON*

#endif
