//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifndef SRS_X64_H
#define SRS_X64_H

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

extern "C" EXPORT_INTRINSICS uint16_t _read_es(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_es(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_cs(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_cs(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_ss(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_ss(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_ds(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_ds(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_fs(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_fs(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_gs(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_gs(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_ldtr(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_ldtr(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_tr(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_tr(uint16_t val) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace segment_register
{

using value_type = uint16_t;

namespace es
{
    constexpr const auto name = "es";

    inline auto get() noexcept
    { return gsl::narrow_cast<value_type>(_read_es()); }

    inline void set(value_type val) noexcept
    { _write_es(val); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_es(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_es(gsl::narrow_cast<value_type>(set_bits(_read_es(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_es(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(_read_es(), from); }

        inline auto is_enabled(value_type sr)
        { return is_bit_set(sr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_es(), from); }

        inline auto is_disabled(value_type sr)
        { return is_bit_cleared(sr, from); }

        inline void enable()
        { _write_es(gsl::narrow_cast<value_type>(set_bit(_read_es(), from))); }

        inline auto enable(value_type sr)
        { _write_es(gsl::narrow_cast<value_type>(set_bit(sr, from))); }

        inline void disable()
        { _write_es(gsl::narrow_cast<value_type>(clear_bit(_read_es(), from))); }

        inline auto disable(value_type sr)
        { _write_es(gsl::narrow_cast<value_type>(clear_bit(sr, from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_es(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_es(gsl::narrow_cast<value_type>(set_bits(_read_es(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_es(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace cs
{
    constexpr const auto name = "cs";

    inline auto get() noexcept
    { return gsl::narrow_cast<value_type>(_read_cs()); }

    inline void set(value_type val) noexcept
    { _write_cs(val); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_cs(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_cs(gsl::narrow_cast<value_type>(set_bits(_read_cs(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_cs(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(_read_cs(), from); }

        inline auto is_enabled(value_type sr)
        { return is_bit_set(sr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cs(), from); }

        inline auto is_disabled(value_type sr)
        { return is_bit_cleared(sr, from); }

        inline void enable()
        { _write_cs(gsl::narrow_cast<value_type>(set_bit(_read_cs(), from))); }

        inline auto enable(value_type sr)
        { _write_cs(gsl::narrow_cast<value_type>(set_bit(sr, from))); }

        inline void disable()
        { _write_cs(gsl::narrow_cast<value_type>(clear_bit(_read_cs(), from))); }

        inline auto disable(value_type sr)
        { _write_cs(gsl::narrow_cast<value_type>(clear_bit(sr, from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_cs(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_cs(gsl::narrow_cast<value_type>(set_bits(_read_cs(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_cs(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace ss
{
    constexpr const auto name = "ss";

    inline auto get() noexcept
    { return gsl::narrow_cast<value_type>(_read_ss()); }

    inline void set(value_type val) noexcept
    { _write_ss(val); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_ss(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_ss(gsl::narrow_cast<value_type>(set_bits(_read_ss(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_ss(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(_read_ss(), from); }

        inline auto is_enabled(value_type sr)
        { return is_bit_set(sr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_ss(), from); }

        inline auto is_disabled(value_type sr)
        { return is_bit_cleared(sr, from); }

        inline void enable()
        { _write_ss(gsl::narrow_cast<value_type>(set_bit(_read_ss(), from))); }

        inline auto enable(value_type sr)
        { _write_ss(gsl::narrow_cast<value_type>(set_bit(sr, from))); }

        inline void disable()
        { _write_ss(gsl::narrow_cast<value_type>(clear_bit(_read_ss(), from))); }

        inline auto disable(value_type sr)
        { _write_ss(gsl::narrow_cast<value_type>(clear_bit(sr, from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_ss(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_ss(gsl::narrow_cast<value_type>(set_bits(_read_ss(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_ss(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace ds
{
    constexpr const auto name = "ds";

    inline auto get() noexcept
    { return gsl::narrow_cast<value_type>(_read_ds()); }

    inline void set(value_type val) noexcept
    { _write_ds(val); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_ds(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_ds(gsl::narrow_cast<value_type>(set_bits(_read_ds(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_ds(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(_read_ds(), from); }

        inline auto is_enabled(value_type sr)
        { return is_bit_set(sr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_ds(), from); }

        inline auto is_disabled(value_type sr)
        { return is_bit_cleared(sr, from); }

        inline void enable()
        { _write_ds(gsl::narrow_cast<value_type>(set_bit(_read_ds(), from))); }

        inline auto enable(value_type sr)
        { _write_ds(gsl::narrow_cast<value_type>(set_bit(sr, from))); }

        inline void disable()
        { _write_ds(gsl::narrow_cast<value_type>(clear_bit(_read_ds(), from))); }

        inline auto disable(value_type sr)
        { _write_ds(gsl::narrow_cast<value_type>(clear_bit(sr, from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_ds(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_ds(gsl::narrow_cast<value_type>(set_bits(_read_ds(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_ds(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace fs
{
    constexpr const auto name = "fs";

    inline auto get() noexcept
    { return gsl::narrow_cast<value_type>(_read_fs()); }

    inline void set(value_type val) noexcept
    { _write_fs(val); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_fs(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_fs(gsl::narrow_cast<value_type>(set_bits(_read_fs(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_fs(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(_read_fs(), from); }

        inline auto is_enabled(value_type sr)
        { return is_bit_set(sr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_fs(), from); }

        inline auto is_disabled(value_type sr)
        { return is_bit_cleared(sr, from); }

        inline void enable()
        { _write_fs(gsl::narrow_cast<value_type>(set_bit(_read_fs(), from))); }

        inline auto enable(value_type sr)
        { _write_fs(gsl::narrow_cast<value_type>(set_bit(sr, from))); }

        inline void disable()
        { _write_fs(gsl::narrow_cast<value_type>(clear_bit(_read_fs(), from))); }

        inline auto disable(value_type sr)
        { _write_fs(gsl::narrow_cast<value_type>(clear_bit(sr, from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_fs(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_fs(gsl::narrow_cast<value_type>(set_bits(_read_fs(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_fs(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace gs
{
    constexpr const auto name = "gs";

    inline auto get() noexcept
    { return gsl::narrow_cast<value_type>(_read_gs()); }

    inline void set(value_type val) noexcept
    { _write_gs(val); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_gs(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_gs(gsl::narrow_cast<value_type>(set_bits(_read_gs(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_gs(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(_read_gs(), from); }

        inline auto is_enabled(value_type sr)
        { return is_bit_set(sr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_gs(), from); }

        inline auto is_disabled(value_type sr)
        { return is_bit_cleared(sr, from); }

        inline void enable()
        { _write_gs(gsl::narrow_cast<value_type>(set_bit(_read_gs(), from))); }

        inline auto enable(value_type sr)
        { _write_gs(gsl::narrow_cast<value_type>(set_bit(sr, from))); }

        inline void disable()
        { _write_gs(gsl::narrow_cast<value_type>(clear_bit(_read_gs(), from))); }

        inline auto disable(value_type sr)
        { _write_gs(gsl::narrow_cast<value_type>(clear_bit(sr, from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_gs(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_gs(gsl::narrow_cast<value_type>(set_bits(_read_gs(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_gs(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace ldtr
{
    constexpr const auto name = "ldtr";

    inline auto get() noexcept
    { return gsl::narrow_cast<value_type>(_read_ldtr()); }

    inline void set(value_type val) noexcept
    { _write_ldtr(val); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_ldtr(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_ldtr(gsl::narrow_cast<value_type>(set_bits(_read_ldtr(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_ldtr(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(_read_ldtr(), from); }

        inline auto is_enabled(value_type sr)
        { return is_bit_set(sr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_ldtr(), from); }

        inline auto is_disabled(value_type sr)
        { return is_bit_cleared(sr, from); }

        inline void enable()
        { _write_ldtr(gsl::narrow_cast<value_type>(set_bit(_read_ldtr(), from))); }

        inline auto enable(value_type sr)
        { _write_ldtr(gsl::narrow_cast<value_type>(set_bit(sr, from))); }

        inline void disable()
        { _write_ldtr(gsl::narrow_cast<value_type>(clear_bit(_read_ldtr(), from))); }

        inline auto disable(value_type sr)
        { _write_ldtr(gsl::narrow_cast<value_type>(clear_bit(sr, from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_ldtr(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_ldtr(gsl::narrow_cast<value_type>(set_bits(_read_ldtr(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_ldtr(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

namespace tr
{
    constexpr const auto name = "tr";

    inline auto get() noexcept
    { return gsl::narrow_cast<value_type>(_read_tr()); }

    inline void set(value_type val) noexcept
    { _write_tr(val); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "rpl";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_tr(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_tr(gsl::narrow_cast<value_type>(set_bits(_read_tr(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_tr(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2ULL;
        constexpr const auto name = "ti";

        inline auto is_enabled()
        { return is_bit_set(_read_tr(), from); }

        inline auto is_enabled(value_type sr)
        { return is_bit_set(sr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_tr(), from); }

        inline auto is_disabled(value_type sr)
        { return is_bit_cleared(sr, from); }

        inline void enable()
        { _write_tr(gsl::narrow_cast<value_type>(set_bit(_read_tr(), from))); }

        inline auto enable(value_type sr)
        { _write_tr(gsl::narrow_cast<value_type>(set_bit(sr, from))); }

        inline void disable()
        { _write_tr(gsl::narrow_cast<value_type>(clear_bit(_read_tr(), from))); }

        inline auto disable(value_type sr)
        { _write_tr(gsl::narrow_cast<value_type>(clear_bit(sr, from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "index";

        inline auto get()
        { return gsl::narrow_cast<value_type>(get_bits(_read_tr(), mask) >> from); }

        inline auto get(value_type sr)
        { return gsl::narrow_cast<value_type>(get_bits(sr, mask) >> from); }

        inline void set(value_type val)
        { _write_tr(gsl::narrow_cast<value_type>(set_bits(_read_tr(), mask, val << from))); }

        inline auto set(value_type sr, value_type val)
        { _write_tr(gsl::narrow_cast<value_type>(set_bits(sr, mask, val << from))); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        rpl::dump(level, msg);
        ti::dump(level, msg);
        index::dump(level, msg);
    }
}

inline void dump(int level, std::string *msg = nullptr)
{
    es::dump(level, msg);
    cs::dump(level, msg);
    ss::dump(level, msg);
    ds::dump(level, msg);
    fs::dump(level, msg);
    gs::dump(level, msg);
    ldtr::dump(level, msg);
    tr::dump(level, msg);
}

}
}

// *INDENT-ON*

#endif
