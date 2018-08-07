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

#ifndef MSRS_X64_H
#define MSRS_X64_H

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfbitmanip.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_INTRINSICS
#ifdef SHARED_INTRINSICS
#define EXPORT_INTRINSICS EXPORT_SYM
#else
#define EXPORT_INTRINSICS IMPORT_SYM
#endif
#else
#define EXPORT_INTRINSICS
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" uint64_t _read_msr(uint32_t addr) noexcept;
extern "C" void _write_msr(uint32_t addr, uint64_t val) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace msrs
{

using field_type = uint32_t;
using value_type = uint64_t;

inline auto get(field_type addr) noexcept
{ return _read_msr(addr); }

inline void set(field_type addr, value_type val) noexcept
{ _write_msr(addr, val); }

namespace ia32_p5_mc_addr
{
    constexpr const auto addr = 0x00000000U;
    constexpr const auto name = "ia32_p5_mc_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_p5_mc_type
{
    constexpr const auto addr = 0x00000001U;
    constexpr const auto name = "ia32_p5_mc_type";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_tsc
{
    constexpr const auto addr = 0x00000010U;
    constexpr const auto name = "ia32_tsc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mperf
{
    constexpr const auto addr = 0x000000E7U;
    constexpr const auto name = "ia32_mperf";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace tsc_freq_clock_count
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "tsc_freq_clock_count";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        tsc_freq_clock_count::dump(level, msg);
    }
}

namespace ia32_aperf
{
    constexpr const auto addr = 0x000000E8U;
    constexpr const auto name = "ia32_aperf";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace actual_freq_clock_count
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "actual_freq_clock_count";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        actual_freq_clock_count::dump(level, msg);
    }
}

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

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace fixed_range_mtrr
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "fixed_range_mtrr";

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

    namespace wc
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "wc";

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

    namespace smrr
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "smrr";

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
        bfdebug_nhex(level, name, get(), msg);
        vcnt::dump(level, msg);
        fixed_range_mtrr::dump(level, msg);
        wc::dump(level, msg);
        smrr::dump(level, msg);
    }
}

namespace ia32_sysenter_cs
{
    constexpr const auto addr = 0x00000174U;
    constexpr const auto name = "ia32_sysenter_cs";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace cs_selector
    {
        constexpr const auto mask = 0x000000000000FFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "cs_selector";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        cs_selector::dump(level, msg);
    }
}

namespace ia32_sysenter_esp
{
    constexpr const auto addr = 0x00000175U;
    constexpr const auto name = "ia32_sysenter_esp";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_sysenter_eip
{
    constexpr const auto addr = 0x00000176U;
    constexpr const auto name = "ia32_sysenter_eip";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mcg_cap
{
    constexpr const auto addr = 0x00000179U;
    constexpr const auto name = "ia32_mcg_cap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace count
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "count";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace mcg_ctl
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "mcg_ctl";

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

    namespace mcg_ext
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "mcg_ext";

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

    namespace mcg_cmci
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "mcg_cmci";

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

    namespace mcg_tes
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "mcg_tes";

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

    namespace mcg_ext_cnt
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mcg_ext_cnt";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace mcg_ser
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "mcg_ser";

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

    namespace mcg_elog
    {
        constexpr const auto mask = 0x0000000004000000ULL;
        constexpr const auto from = 26ULL;
        constexpr const auto name = "mcg_elog";

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

    namespace mcg_lmce
    {
        constexpr const auto mask = 0x0000000008000000ULL;
        constexpr const auto from = 27ULL;
        constexpr const auto name = "mcg_lmce";

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
        bfdebug_nhex(level, name, get(), msg);
        count::dump(level, msg);
        mcg_ctl::dump(level, msg);
        mcg_ext::dump(level, msg);
        mcg_cmci::dump(level, msg);
        mcg_tes::dump(level, msg);
        mcg_ext_cnt::dump(level, msg);
        mcg_ser::dump(level, msg);
        mcg_elog::dump(level, msg);
        mcg_lmce::dump(level, msg);
    }
}

namespace ia32_mcg_status
{
    constexpr const auto addr = 0x0000017AU;
    constexpr const auto name = "ia32_mcg_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace ripv
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "ripv";

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

    namespace eipv
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1ULL;
        constexpr const auto name = "eipv";

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

    namespace mcip
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "mcip";

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

    namespace lmce_s
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "lmce_s";

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
        bfdebug_nhex(level, name, get(), msg);
        ripv::dump(level, msg);
        eipv::dump(level, msg);
        mcip::dump(level, msg);
        lmce_s::dump(level, msg);
    }
}

namespace ia32_mcg_ctl
{
    constexpr const auto addr = 0x0000017BU;
    constexpr const auto name = "ia32_mcg_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_pat
{
    constexpr const auto addr = 0x00000277U;
    constexpr const auto name = "ia32_pat";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace pa0
    {
        constexpr const auto mask = 0x0000000000000007ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "pa0";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace pa1
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "pa1";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace pa2
    {
        constexpr const auto mask = 0x0000000000070000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "pa2";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace pa3
    {
        constexpr const auto mask = 0x0000000007000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "pa3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace pa4
    {
        constexpr const auto mask = 0x0000000700000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "pa4";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace pa5
    {
        constexpr const auto mask = 0x0000070000000000ULL;
        constexpr const auto from = 40ULL;
        constexpr const auto name = "pa5";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace pa6
    {
        constexpr const auto mask = 0x0007000000000000ULL;
        constexpr const auto from = 48ULL;
        constexpr const auto name = "pa6";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace pa7
    {
        constexpr const auto mask = 0x0700000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "pa7";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline auto pa(value_type index)
    {
        switch(index) {
            case 0: return pa0::get();
            case 1: return pa1::get();
            case 2: return pa2::get();
            case 3: return pa3::get();
            case 4: return pa4::get();
            case 5: return pa5::get();
            case 6: return pa6::get();
            case 7: return pa7::get();
            default:
                throw std::runtime_error("unknown pat index");
        }
    }

    inline auto pa(value_type value, value_type index)
    {
        switch(index)
        {
            case 0: return pa0::get(value);
            case 1: return pa1::get(value);
            case 2: return pa2::get(value);
            case 3: return pa3::get(value);
            case 4: return pa4::get(value);
            case 5: return pa5::get(value);
            case 6: return pa6::get(value);
            case 7: return pa7::get(value);
            default:
                throw std::runtime_error("unknown pat index");
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        pa0::dump(level, msg);
        pa1::dump(level, msg);
        pa2::dump(level, msg);
        pa3::dump(level, msg);
        pa4::dump(level, msg);
        pa5::dump(level, msg);
        pa6::dump(level, msg);
        pa7::dump(level, msg);
    }
}

namespace ia32_mc0_ctl
{
    constexpr const auto addr = 0x00000400U;
    constexpr const auto name = "ia32_mc0_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc0_status
{
    constexpr const auto addr = 0x00000401U;
    constexpr const auto name = "ia32_mc0_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc0_addr
{
    constexpr const auto addr = 0x00000402U;
    constexpr const auto name = "ia32_mc0_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc0_misc
{
    constexpr const auto addr = 0x00000403U;
    constexpr const auto name = "ia32_mc0_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc1_ctl
{
    constexpr const auto addr = 0x00000404U;
    constexpr const auto name = "ia32_mc1_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc1_status
{
    constexpr const auto addr = 0x00000405U;
    constexpr const auto name = "ia32_mc1_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc1_addr
{
    constexpr const auto addr = 0x00000406U;
    constexpr const auto name = "ia32_mc1_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc1_misc
{
    constexpr const auto addr = 0x00000407U;
    constexpr const auto name = "ia32_mc1_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc2_ctl
{
    constexpr const auto addr = 0x00000408U;
    constexpr const auto name = "ia32_mc2_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc2_status
{
    constexpr const auto addr = 0x00000409U;
    constexpr const auto name = "ia32_mc2_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc2_addr
{
    constexpr const auto addr = 0x0000040AU;
    constexpr const auto name = "ia32_mc2_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc2_misc
{
    constexpr const auto addr = 0x0000040BU;
    constexpr const auto name = "ia32_mc2_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc3_ctl
{
    constexpr const auto addr = 0x0000040CU;
    constexpr const auto name = "ia32_mc3_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc3_status
{
    constexpr const auto addr = 0x0000040DU;
    constexpr const auto name = "ia32_mc3_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc3_addr
{
    constexpr const auto addr = 0x0000040EU;
    constexpr const auto name = "ia32_mc3_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc3_misc
{
    constexpr const auto addr = 0x0000040FU;
    constexpr const auto name = "ia32_mc3_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc4_ctl
{
    constexpr const auto addr = 0x00000410U;
    constexpr const auto name = "ia32_mc4_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc4_status
{
    constexpr const auto addr = 0x00000411U;
    constexpr const auto name = "ia32_mc4_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc4_addr
{
    constexpr const auto addr = 0x00000412U;
    constexpr const auto name = "ia32_mc4_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc4_misc
{
    constexpr const auto addr = 0x00000413U;
    constexpr const auto name = "ia32_mc4_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc5_ctl
{
    constexpr const auto addr = 0x00000414U;
    constexpr const auto name = "ia32_mc5_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc5_status
{
    constexpr const auto addr = 0x00000415U;
    constexpr const auto name = "ia32_mc5_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc5_addr
{
    constexpr const auto addr = 0x00000416U;
    constexpr const auto name = "ia32_mc5_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_mc5_misc
{
    constexpr const auto addr = 0x00000417U;
    constexpr const auto name = "ia32_mc5_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_star
{
    constexpr const auto addr = 0xC0000081U;
    constexpr const auto name = "ia32_fs_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_lstar
{
    constexpr const auto addr = 0xC0000082U;
    constexpr const auto name = "ia32_lstar";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_fmask
{
    constexpr const auto addr = 0xC0000084U;
    constexpr const auto name = "ia32_fmask";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_kernel_gs_base
{
    constexpr const auto addr = 0xC0000102U;
    constexpr const auto name = "ia32_kernel_gs_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_tsc_aux
{
    constexpr const auto addr = 0xC0000103U;
    constexpr const auto name = "ia32_tsc_aux";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace aux
    {
        constexpr const auto mask = 0x00000000FFFFFFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "aux";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        aux::dump(level, msg);
    }
}

}
}

// *INDENT-ON*

#endif
