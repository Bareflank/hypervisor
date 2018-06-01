//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
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

#ifndef MTRR_INTEL_X64_H
#define MTRR_INTEL_X64_H

#include "msrs.h"
#include "cpuid.h"

// *INDENT-OFF*

namespace intel_x64
{
namespace mtrr
{

using value_type = ::intel_x64::msrs::value_type;

constexpr const auto uncacheable = 0x00ULL;
constexpr const auto write_combining = 0x01ULL;
constexpr const auto write_through = 0x04ULL;
constexpr const auto write_protected = 0x05ULL;
constexpr const auto write_back = 0x06ULL;

constexpr const auto uncacheable_mask = 1ULL << uncacheable;
constexpr const auto write_combining_mask = 1ULL << write_combining;
constexpr const auto write_through_mask = 1ULL << write_through;
constexpr const auto write_protected_mask = 1ULL << write_protected;
constexpr const auto write_back_mask = 1ULL << write_back;

constexpr const auto valid_type_mask = uncacheable_mask |
    write_combining_mask | write_through_mask |
    write_protected_mask | write_back_mask;

inline const char *type_to_cstr(uint64_t type)
{
    switch (type) {
        case uncacheable: return "uncacheable";
        case write_combining: return "write_combining";
        case write_through: return "write_through";
        case write_protected: return "write_protected";
        case write_back: return "write_back";
        default: return "invalid";
    }
}

inline bool valid_type(uint64_t type)
{
    switch (type) {
        case uncacheable:
        case write_combining:
        case write_through:
        case write_protected:
        case write_back:
            return true;
        default:
            return false;
    }
}

inline bool is_supported()
{ return cpuid::feature_information::edx::mtrr::is_enabled(); }

namespace ia32_mtrrcap
{
    constexpr const auto addr = 0x000000FEU;
    constexpr const auto name = "ia32_mtrrcap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace vcnt
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vcnt";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace fixed_support
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "fixed_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace wc_support
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "wc_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace smrr_support
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "smrr_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        vcnt::dump(level, msg);
        fixed_support::dump(level, msg);
        wc_support::dump(level, msg);
        smrr_support::dump(level, msg);
    }
}

namespace ia32_mtrr_def_type
{
    constexpr const auto addr = 0x000002FFU;
    constexpr const auto name = "ia32_mtrr_def_type";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }

    namespace type
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "type";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace fe
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "fe";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace e
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "e";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        fe::dump(level, msg);
        e::dump(level, msg);
    }
}

namespace ia32_physbase
{
    constexpr const auto start_addr = 0x00000200U;

    namespace type
    {
        constexpr const uint64_t mask = 0x00000000000000FFULL;
        constexpr const uint64_t from = 0ULL;
        constexpr const auto name = "type";

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline auto set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, value_type msr, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(msr), msg); }
    }

    /// The 'mask' variable of this namespace depends on the physical address
    /// size (pas) returned by cpuid.
    namespace physbase
    {
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto mask(value_type pas) noexcept
        { return ((1ULL << pas) - 1U) & ~(0x1000ULL - 1U); }

        inline auto get(value_type msr, value_type pas) noexcept
        { return get_bits(msr, mask(pas)) >> from; }

        inline auto set(value_type &msr, value_type val, value_type pas) noexcept
        { msr = set_bits(msr, mask(pas), val << from); }

        inline void dump(int level, value_type msr, value_type pas, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(msr, pas), msg); }
    }

    inline void dump(int level, value_type msr, value_type pas, std::string *msg = nullptr)
    {
        type::dump(level, msr, msg);
        physbase::dump(level, msr, pas, msg);
    }
}

namespace ia32_physmask
{
    constexpr const auto start_addr = 0x00000201U;

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto enable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline auto disable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, value_type msr, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(msr), msg); }

    }

    /// The 'mask' variable of this namespace depends on the physical address
    /// size (pas) returned by cpuid.
    namespace physmask
    {
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto mask(value_type pas) noexcept
        { return ((1ULL << pas) - 1U) & ~(0x1000ULL - 1U); }

        inline auto get(value_type msr, value_type pas) noexcept
        { return get_bits(msr, mask(pas)) >> from; }

        inline auto set(value_type &msr, value_type val, value_type pas) noexcept
        { msr = set_bits(msr, mask(pas), val << from); }

        inline void dump(int level, value_type msr, value_type pas, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(msr, pas), msg); }
    }

    inline void dump(int level, value_type msr, value_type pas, std::string *msg = nullptr)
    {
        valid::dump(level, msr, msg);
        physmask::dump(level, msr, pas, msg);
    }
}

namespace fixed_range
{
    /// Return the value of the subrange'th byte from the given
    /// Note that this value may or may not be a valid memory type so
    /// the caller should check it against valid type values
    inline auto type(value_type fixed_msr, value_type subrange) noexcept
    {
        const auto mask = 0xFFULL << (subrange << 3U);
        return fixed_msr & mask;
    }
}

namespace fix64k_00000
{
    constexpr const auto addr = 0x00000250U;
    constexpr const auto name = "fix64k_00000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

namespace fix16k_80000
{
    constexpr const auto addr = 0x00000258U;
    constexpr const auto name = "fix16k_80000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

namespace fix16k_A0000
{
    constexpr const auto addr = 0x00000259U;
    constexpr const auto name = "fix16k_A0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

namespace fix4k_C0000
{
    constexpr const auto addr = 0x00000268U;
    constexpr const auto name = "fix4k_C0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

namespace fix4k_C8000
{
    constexpr const auto addr = 0x00000269U;
    constexpr const auto name = "fix4k_C8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

namespace fix4k_D0000
{
    constexpr const auto addr = 0x0000026AU;
    constexpr const auto name = "fix4k_D0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

namespace fix4k_D8000
{
    constexpr const auto addr = 0x0000026BU;
    constexpr const auto name = "fix4k_D8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

namespace fix4k_E0000
{
    constexpr const auto addr = 0x0000026CU;
    constexpr const auto name = "fix4k_E0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

namespace fix4k_E8000
{
    constexpr const auto addr = 0x0000026DU;
    constexpr const auto name = "fix4k_E8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

namespace fix4k_F0000
{
    constexpr const auto addr = 0x0000026EU;
    constexpr const auto name = "fix4k_F0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

namespace fix4k_F8000
{
    constexpr const auto addr = 0x0000026FU;
    constexpr const auto name = "fix4k_F8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type &val) noexcept
    { _write_msr(addr, val); }
}

}
}

// *INDENT-ON*

#endif
