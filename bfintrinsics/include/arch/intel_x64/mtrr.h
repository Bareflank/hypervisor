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

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

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

namespace physbase0
{
    constexpr const auto addr = 0x00000200U;
    constexpr const auto name = "physbase0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace physmask0
{
    constexpr const auto addr = 0x00000201U;
    constexpr const auto name = "physmask0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace physmask
    {
        constexpr const auto mask = 0x000000FFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace physbase1
{
    constexpr const auto addr = 0x00000202U;
    constexpr const auto name = "physbase1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace physmask1
{
    constexpr const auto addr = 0x00000203U;
    constexpr const auto name = "physmask1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace physmask
    {
        constexpr const auto mask = 0x000000FFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace physbase2
{
    constexpr const auto addr = 0x00000204U;
    constexpr const auto name = "physbase2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace physmask2
{
    constexpr const auto addr = 0x00000205U;
    constexpr const auto name = "physmask2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace physmask
    {
        constexpr const auto mask = 0x000000FFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace physbase3
{
    constexpr const auto addr = 0x00000206U;
    constexpr const auto name = "physbase3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace physmask3
{
    constexpr const auto addr = 0x00000207U;
    constexpr const auto name = "physmask3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace physmask
    {
        constexpr const auto mask = 0x000000FFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace physbase4
{
    constexpr const auto addr = 0x00000208U;
    constexpr const auto name = "physbase4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace physmask4
{
    constexpr const auto addr = 0x00000209U;
    constexpr const auto name = "physmask4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace physmask
    {
        constexpr const auto mask = 0x000000FFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace physbase5
{
    constexpr const auto addr = 0x0000020AU;
    constexpr const auto name = "physbase5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace physmask5
{
    constexpr const auto addr = 0x0000020BU;
    constexpr const auto name = "physmask5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace physmask
    {
        constexpr const auto mask = 0x000000FFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace physbase6
{
    constexpr const auto addr = 0x0000020CU;
    constexpr const auto name = "physbase6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace physmask6
{
    constexpr const auto addr = 0x0000020DU;
    constexpr const auto name = "physmask6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace physmask
    {
        constexpr const auto mask = 0x000000FFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace physbase7
{
    constexpr const auto addr = 0x0000020EU;
    constexpr const auto name = "physbase7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace physmask7
{
    constexpr const auto addr = 0x0000020FU;
    constexpr const auto name = "physmask7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace physmask
    {
        constexpr const auto mask = 0x000000FFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace physbase8
{
    constexpr const auto addr = 0x00000210U;
    constexpr const auto name = "physbase8";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace physmask8
{
    constexpr const auto addr = 0x00000211U;
    constexpr const auto name = "physmask8";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace physmask
    {
        constexpr const auto mask = 0x000000FFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace physbase9
{
    constexpr const auto addr = 0x00000212U;
    constexpr const auto name = "physbase9";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
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

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        type::dump(level, msg);
        physbase::dump(level, msg);
    }
}

namespace physmask9
{
    constexpr const auto addr = 0x00000213U;
    constexpr const auto name = "physmask9";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "valid";

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

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }

    }

    namespace physmask
    {
        constexpr const auto mask = 0x000000FFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        valid::dump(level, msg);
        physmask::dump(level, msg);
    }
}

namespace fix64k_00000
{
    constexpr const auto addr = 0x00000250U;
    constexpr const auto name = "fix64k_00000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix16k_80000
{
    constexpr const auto addr = 0x00000258U;
    constexpr const auto name = "fix16k_80000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix16k_A0000
{
    constexpr const auto addr = 0x00000259U;
    constexpr const auto name = "fix16k_A0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_C0000
{
    constexpr const auto addr = 0x00000268U;
    constexpr const auto name = "fix4k_C0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_C8000
{
    constexpr const auto addr = 0x00000269U;
    constexpr const auto name = "fix4k_C8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_D0000
{
    constexpr const auto addr = 0x0000026AU;
    constexpr const auto name = "fix4k_D0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_D8000
{
    constexpr const auto addr = 0x0000026BU;
    constexpr const auto name = "fix4k_D8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_E0000
{
    constexpr const auto addr = 0x0000026CU;
    constexpr const auto name = "fix4k_E0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_E8000
{
    constexpr const auto addr = 0x0000026DU;
    constexpr const auto name = "fix4k_E8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_F0000
{
    constexpr const auto addr = 0x0000026EU;
    constexpr const auto name = "fix4k_F0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

namespace fix4k_F8000
{
    constexpr const auto addr = 0x0000026FU;
    constexpr const auto name = "fix4k_F8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline auto set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace range0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "range0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "range1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "range2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "range3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "range4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "range5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "range6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    namespace range7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "range7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subndec(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        range0::dump(level, msg);
        range1::dump(level, msg);
        range2::dump(level, msg);
        range3::dump(level, msg);
        range4::dump(level, msg);
        range5::dump(level, msg);
        range6::dump(level, msg);
        range7::dump(level, msg);
    }
}

}
}

// *INDENT-ON*

#endif
