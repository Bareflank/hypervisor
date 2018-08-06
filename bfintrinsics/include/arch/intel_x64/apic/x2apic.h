//
// Bareflank Hypervisor
// Copyright (C) 2017 Assured Information Security, Inc.
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

#ifndef INTRINSICS_X2APIC_INTEL_X64_H
#define INTRINSICS_X2APIC_INTEL_X64_H

#include <set>
#include <array>

#include <arch/intel_x64/cpuid.h>
#include <arch/intel_x64/apic/lapic.h>

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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// *INDENT-OFF*

namespace intel_x64
{
namespace msrs
{
namespace ia32_x2apic_apicid
{
    constexpr const auto addr = 0x00000802U;
    constexpr const auto name = "ia32_x2apic_apicid";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_version
{
    constexpr const auto addr = 0x00000803U;
    constexpr const auto name = "ia32_x2apic_version";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_tpr
{
    constexpr const auto addr = 0x00000808U;
    constexpr const auto name = "ia32_x2apic_tpr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_ppr
{
    constexpr const auto addr = 0x0000080AU;
    constexpr const auto name = "ia32_x2apic_ppr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_eoi
{
    constexpr const auto addr = 0x0000080BU;
    constexpr const auto name = "ia32_x2apic_eoi";

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }
}

namespace ia32_x2apic_ldr
{
    constexpr const auto addr = 0x0000080DU;
    constexpr const auto name = "ia32_x2apic_ldr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace logical_id
    {
        constexpr const auto mask = 0x000000000000FFFFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "logical_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace cluster_id
    {
        constexpr const auto mask = 0x00000000FFFF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "cluster_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        logical_id::dump(level, msg);
        cluster_id::dump(level, msg);
    }
}

namespace ia32_x2apic_svr
{
    constexpr const auto addr = 0x0000080FU;
    constexpr const auto name = "ia32_x2apic_svr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

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

    namespace apic_enable_bit
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "apic_enable_bit";

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

    namespace focus_checking
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "focus_checking";

        inline auto is_disabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_enabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void disable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline void disable(value_type &msr)
        { msr = set_bit(msr, from); }

        inline void enable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline void enable(value_type &msr)
        { msr = clear_bit(msr, from); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subbool(level, name, is_enabled(), msg); }
    }

    namespace suppress_eoi_broadcast
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "suppress_eoi_broadcast";

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
        vector::dump(level, msg);
        apic_enable_bit::dump(level, msg);
        focus_checking::dump(level, msg);
        suppress_eoi_broadcast::dump(level, msg);
    }
}

namespace ia32_x2apic_isr0
{
    constexpr const auto addr = 0x00000810U;
    constexpr const auto name = "ia32_x2apic_isr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_isr1
{
    constexpr const auto addr = 0x00000811U;
    constexpr const auto name = "ia32_x2apic_isr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_isr2
{
    constexpr const auto addr = 0x00000812U;
    constexpr const auto name = "ia32_x2apic_isr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_isr3
{
    constexpr const auto addr = 0x00000813U;
    constexpr const auto name = "ia32_x2apic_isr3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_isr4
{
    constexpr const auto addr = 0x00000814U;
    constexpr const auto name = "ia32_x2apic_isr4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_isr5
{
    constexpr const auto addr = 0x00000815U;
    constexpr const auto name = "ia32_x2apic_isr5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_isr6
{
    constexpr const auto addr = 0x00000816U;
    constexpr const auto name = "ia32_x2apic_isr6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_isr7
{
    constexpr const auto addr = 0x00000817U;
    constexpr const auto name = "ia32_x2apic_isr7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_tmr0
{
    constexpr const auto addr = 0x00000818U;
    constexpr const auto name = "ia32_x2apic_tmr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_tmr1
{
    constexpr const auto addr = 0x00000819U;
    constexpr const auto name = "ia32_x2apic_tmr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_tmr2
{
    constexpr const auto addr = 0x0000081AU;
    constexpr const auto name = "ia32_x2apic_tmr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_tmr3
{
    constexpr const auto addr = 0x0000081BU;
    constexpr const auto name = "ia32_x2apic_tmr3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_tmr4
{
    constexpr const auto addr = 0x0000081CU;
    constexpr const auto name = "ia32_x2apic_tmr4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_tmr5
{
    constexpr const auto addr = 0x0000081DU;
    constexpr const auto name = "ia32_x2apic_tmr5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_tmr6
{
    constexpr const auto addr = 0x0000081EU;
    constexpr const auto name = "ia32_x2apic_tmr6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_tmr7
{
    constexpr const auto addr = 0x0000081FU;
    constexpr const auto name = "ia32_x2apic_tmr7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_irr0
{
    constexpr const auto addr = 0x00000820U;
    constexpr const auto name = "ia32_x2apic_irr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_irr1
{
    constexpr const auto addr = 0x00000821U;
    constexpr const auto name = "ia32_x2apic_irr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_irr2
{
    constexpr const auto addr = 0x00000822U;
    constexpr const auto name = "ia32_x2apic_irr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_irr3
{
    constexpr const auto addr = 0x00000823U;
    constexpr const auto name = "ia32_x2apic_irr3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_irr4
{
    constexpr const auto addr = 0x00000824U;
    constexpr const auto name = "ia32_x2apic_irr4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_irr5
{
    constexpr const auto addr = 0x00000825U;
    constexpr const auto name = "ia32_x2apic_irr5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_irr6
{
    constexpr const auto addr = 0x00000826U;
    constexpr const auto name = "ia32_x2apic_irr6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_irr7
{
    constexpr const auto addr = 0x00000827U;
    constexpr const auto name = "ia32_x2apic_irr7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_esr
{
    constexpr const auto addr = 0x00000828U;
    constexpr const auto name = "ia32_x2apic_esr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_lvt_cmci
{
    constexpr const auto addr = 0x0000082FU;
    constexpr const auto name = "ia32_x2apic_lvt_cmci";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

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

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_mode::dump(level, msg);
        delivery_status::dump(level, msg);
        mask_bit::dump(level, msg);
    }
}

namespace ia32_x2apic_icr
{
    constexpr const auto addr = 0x00000830U;
    constexpr const auto name = "ia32_x2apic_icr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

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

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace destination_mode
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "destination_mode";

        constexpr const auto physical = 0U;
        constexpr const auto logical = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case physical: bfdebug_subtext(level, name, "physical", msg); break;
                case logical: bfdebug_subtext(level, name, "logical", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
            }
        }
    }

    namespace level
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "level";

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

    namespace trigger_mode
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "trigger_mode";

        constexpr const auto edge_mode = 0U;
        constexpr const auto level_mode = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case edge_mode: bfdebug_subtext(level, name, "edge", msg); break;
                case level_mode: bfdebug_subtext(level, name, "level", msg); break;
            }
        }
    }

    namespace destination_shorthand
    {
        constexpr const auto mask = 0x00000000000C0000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "destination_shorthand";

        constexpr const auto no_shorthand = 0U;
        constexpr const auto self = 1U;
        constexpr const auto all_including_self = 2U;
        constexpr const auto all_excluding_self = 3U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int lev, std::string *msg = nullptr)
        {
            switch (get()) {
                case no_shorthand: bfdebug_subtext(lev, name, "no_shorthand", msg); break;
                case self: bfdebug_subtext(lev, name, "self", msg); break;
                case all_including_self: bfdebug_subtext(lev, name, "all_including_self", msg); break;
                case all_excluding_self: bfdebug_subtext(lev, name, "all_excluding_self", msg); break;
            }
        }
    }

    namespace destination_field
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "destination_field";

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
        vector::dump(level, msg);
        delivery_mode::dump(level, msg);
        destination_mode::dump(level, msg);
        level::dump(level, msg);
        trigger_mode::dump(level, msg);
        destination_shorthand::dump(level, msg);
        destination_field::dump(level, msg);
    }
}

namespace ia32_x2apic_lvt_timer
{
    constexpr const auto addr = 0x00000832U;
    constexpr const auto name = "ia32_x2apic_lvt_timer";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

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

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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

    namespace timer_mode
    {
        constexpr const auto mask = 0x0000000000060000ULL;
        constexpr const auto from = 17ULL;
        constexpr const auto name = "timer_mode";

        constexpr const auto one_shot = 0U;
        constexpr const auto periodic = 1U;
        constexpr const auto tsc_deadline = 2U;

        inline auto get()
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr)
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val)
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val)
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case one_shot: bfdebug_subtext(level, name, "one-shot", msg); break;
                case periodic: bfdebug_subtext(level, name, "periodic", msg); break;
                case tsc_deadline: bfdebug_subtext(level, name, "TSC-deadline", msg); break;
                default: bferror_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        vector::dump(level, msg);
        delivery_status::dump(level, msg);
        mask_bit::dump(level, msg);
        timer_mode::dump(level, msg);
    }
}

namespace ia32_x2apic_lvt_thermal
{
    constexpr const auto addr = 0x00000833U;
    constexpr const auto name = "ia32_x2apic_lvt_thermal";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

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

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_mode::dump(level, msg);
        delivery_status::dump(level, msg);
        mask_bit::dump(level, msg);
    }
}

namespace ia32_x2apic_lvt_pmi
{
    constexpr const auto addr = 0x00000834U;
    constexpr const auto name = "ia32_x2apic_lvt_pmi";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

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

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_mode::dump(level, msg);
        delivery_status::dump(level, msg);
        mask_bit::dump(level, msg);
    }
}

namespace ia32_x2apic_lvt_lint0
{
    constexpr const auto addr = 0x00000835U;
    constexpr const auto name = "ia32_x2apic_lvt_lint0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

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

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
            }
        }
    }

    namespace polarity
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "polarity";

        constexpr const auto active_high = 0U;
        constexpr const auto active_low = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case active_high: bfdebug_subtext(level, name, "active_high", msg); break;
                case active_low: bfdebug_subtext(level, name, "active_low", msg); break;
            }
        }
    }

    namespace remote_irr
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "remote_irr";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace trigger_mode
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "trigger_mode";

        constexpr const auto edge_mode = 0U;
        constexpr const auto level_mode = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case edge_mode: bfdebug_subtext(level, name, "edge", msg); break;
                case level_mode: bfdebug_subtext(level, name, "level", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_status::dump(level, msg);
        polarity::dump(level, msg);
        remote_irr::dump(level, msg);
        trigger_mode::dump(level, msg);
        mask_bit::dump(level, msg);
    }
}

namespace ia32_x2apic_lvt_lint1
{
    constexpr const auto addr = 0x00000836U;
    constexpr const auto name = "ia32_x2apic_lvt_lint1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

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

    namespace delivery_mode
    {
        constexpr const auto mask = 0x0000000000000700ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "delivery_mode";

        constexpr const auto fixed = 0U;
        constexpr const auto smi = 2U;
        constexpr const auto nmi = 4U;
        constexpr const auto init = 5U;
        constexpr const auto extint = 7U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case fixed: bfdebug_subtext(level, name, "fixed", msg); break;
                case smi: bfdebug_subtext(level, name, "smi", msg); break;
                case nmi: bfdebug_subtext(level, name, "nmi", msg); break;
                case init: bfdebug_subtext(level, name, "init", msg); break;
                case extint: bfdebug_subtext(level, name, "extint", msg); break;
                default: bfalert_subtext(level, name, "RESERVED", msg); break;
            }
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
            }
        }
    }

    namespace polarity
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "polarity";

        constexpr const auto active_high = 0U;
        constexpr const auto active_low = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case active_high: bfdebug_subtext(level, name, "active_high", msg); break;
                case active_low: bfdebug_subtext(level, name, "active_low", msg); break;
            }
        }
    }

    namespace remote_irr
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "remote_irr";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace trigger_mode
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "trigger_mode";

        constexpr const auto edge_mode = 0U;
        constexpr const auto level_mode = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case edge_mode: bfdebug_subtext(level, name, "edge", msg); break;
                case level_mode: bfdebug_subtext(level, name, "level", msg); break;
            }
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

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
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_status::dump(level, msg);
        polarity::dump(level, msg);
        remote_irr::dump(level, msg);
        trigger_mode::dump(level, msg);
        mask_bit::dump(level, msg);
    }
}

namespace ia32_x2apic_lvt_error
{
    constexpr const auto addr = 0x00000837U;
    constexpr const auto name = "ia32_x2apic_lvt_error";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

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

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case idle: bfdebug_subtext(level, name, "idle", msg); break;
                case send_pending: bfdebug_subtext(level, name, "send pending", msg); break;
            }
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(),  msg);
        vector::dump(level, msg);
        delivery_status::dump(level, msg);
    }
}

namespace ia32_x2apic_init_count
{
    constexpr const auto addr = 0x00000838U;
    constexpr const auto name = "ia32_x2apic_init_count";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_cur_count
{
    constexpr const auto addr = 0x00000839U;
    constexpr const auto name = "ia32_x2apic_cur_count";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level, std::string *msg = nullptr)
    { bfdebug_nhex(level, name, get(), msg); }
}

namespace ia32_x2apic_dcr
{
    constexpr const auto addr = 0x0000083EU;
    constexpr const auto name = "ia32_x2apic_dcr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace div_val
    {
        constexpr const auto mask = 0x000000000000000BULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "div_val";

        constexpr const auto div_by_2 = 0ULL;
        constexpr const auto div_by_4 = 1ULL;
        constexpr const auto div_by_8 = 2ULL;
        constexpr const auto div_by_16 = 3ULL;
        constexpr const auto div_by_32 = 8ULL;
        constexpr const auto div_by_64 = 9ULL;
        constexpr const auto div_by_128 = 10ULL;
        constexpr const auto div_by_1 = 11ULL;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case div_by_2: bfdebug_subtext(level, name, "div_by_2", msg); break;
                case div_by_4: bfdebug_subtext(level, name, "div_by_4", msg); break;
                case div_by_8: bfdebug_subtext(level, name, "div_by_8", msg); break;
                case div_by_16: bfdebug_subtext(level, name, "div_by_16", msg); break;
                case div_by_32: bfdebug_subtext(level, name, "div_by_32", msg); break;
                case div_by_64: bfdebug_subtext(level, name, "div_by_64", msg); break;
                case div_by_128: bfdebug_subtext(level, name, "div_by_128", msg); break;
                case div_by_1: bfdebug_subtext(level, name, "div_by_1", msg); break;
            }
        }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        div_val::dump(level, msg);
    }
}

namespace ia32_x2apic_self_ipi
{
    constexpr const auto addr = 0x0000083FU;
    constexpr const auto name = "ia32_x2apic_self_ipi";

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }
    }
}
}

namespace lapic
{
    inline auto x2apic_supported() noexcept
    {
        return cpuid::feature_information::ecx::x2apic::is_enabled();
    }
}
}

// *INDENT-ON*

#endif
