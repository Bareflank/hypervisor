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

#ifndef INTRINSICS_LAPIC_INTEL_X64_H
#define INTRINSICS_LAPIC_INTEL_X64_H

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>
#include <arch/x64/misc.h>
#include <arch/intel_x64/msrs.h>
#include <arch/intel_x64/cpuid.h>
#include <arch/intel_x64/apic/x2apic.h>

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

using value_type = ::x64::msrs::value_type;

namespace msrs
{

namespace ia32_apic_base
{
    constexpr const auto addr = 0x0000001BU;
    constexpr const auto name = "ia32_apic_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace bsp
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "bsp";

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

    namespace extd
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "extd";

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

    namespace en
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "en";

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

    ///
    /// NOTE: `state` is a combination field of `extd` and `en` to facilitate
    /// atomic apic state changes and to provide a simplified interface
    ///
    namespace state
    {
        constexpr const auto mask = 0xC00ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "state";

        constexpr const auto disabled = 0x0ULL;
        constexpr const auto invalid = 0x1ULL;
        constexpr const auto xapic = 0x2ULL;
        constexpr const auto x2apic = 0x3ULL;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val << from); }

        inline void enable_x2apic() noexcept
        { set(x2apic); }

        inline void enable_x2apic(value_type &msr) noexcept
        { msr = set_bits(msr, mask, x2apic << from); }

        inline void enable_xapic() noexcept
        { set(xapic); }

        inline void enable_xapic(value_type &msr) noexcept
        { msr = set_bits(msr, mask, xapic << from); }

        inline void disable() noexcept
        { set(disabled); }

        inline void disable(value_type &msr) noexcept
        { msr = set_bits(msr, mask, disabled << from); }

        inline void dump(int level, std::string *msg = nullptr)
        {
            switch (get()) {
                case x2apic:
                    bfdebug_subtext(level, name, "x2apic", msg);
                    return;
                case xapic:
                    bfdebug_subtext(level, name, "xapic", msg);
                    return;
                case disabled:
                    bfdebug_subtext(level, name, "disabled", msg);
                    return;
                case invalid:
                    bfdebug_subtext(level, name, "invalid", msg);
                    return;
            }
        }
    }

    namespace apic_base
    {
        constexpr const auto mask = 0x0000000FFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "apic_base";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask); }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask); }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val)); }

        inline void set(value_type &msr, value_type val) noexcept
        { msr = set_bits(msr, mask, val); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    inline void dump(int level, std::string *msg = nullptr)
    {
        bfdebug_nhex(level, name, get(), msg);
        bsp::dump(level, msg);
        extd::dump(level, msg);
        en::dump(level, msg);
        apic_base::dump(level, msg);
    }
}
}

namespace lapic
{

inline void dump_delivery_status(
    int lev, value_type val, std::string *msg = nullptr);
inline void dump_delivery_mode(
    int lev, value_type val, std::string *msg = nullptr);

///
/// x2APIC MSR address space bounds
///
constexpr const auto x2apic_base = 0x800U;
constexpr const auto x2apic_last = 0xBFFU;

constexpr const auto xapic_default_base = 0xFEE00000U;

/// Is present
///
/// @expects
/// @ensures
///
/// @return true if a LAPIC is available on the platform
/// @return false if a LAPIC is not available on the platform
///
inline auto is_present() noexcept
{ return ::intel_x64::cpuid::feature_information::edx::apic::is_enabled(); }

/// LAPIC Registers
///
/// Defines the "canonical" offset of each LAPIC register along
/// with the set of valid operations in xAPIC and x2APIC mode. Each
/// canonical offset may be derived from an MSR address:
///
///     canonical offset = (msr_addr & ~0x800)
///
/// or from a memory address:
///
///     canonical offset = (mem_addr & (0x1000 - 1)) >> 4
///
/// Note that this mapping is _not_ invertible, meaning that in
/// general you cannot always reconstruct a valid x2APIC (MSR) or
/// xAPIC (MMIO) register address given a canonical offset.
/// Users should always check the valid operations before
/// accessing the APIC with it.
///

/// Lapic register attribute type
using attr_t = uint64_t;

/// Lapic register canonical offset type
using offset_t = uint64_t;

/// Total number of (x2)apic registers
constexpr const auto count = (x2apic_last - x2apic_base) + 1U;

/// Lapic register attributes
extern std::array<attr_t, count> attributes;

/// Mem addr to offset
///
/// Convert an integer interpreted as equal to (xapic_base | mmio_offset)
/// to a canonical offset.
///
/// @expects
/// @ensures
///
/// @param mem_addr the address to convert to a canonical offset
/// @return may or may not be a valid offset. Always check
///         before using to access the apic
///
constexpr inline auto mem_addr_to_offset(uint64_t mem_addr)
{ return (mem_addr & (::x64::page_size - 1U)) >> 4U; }

/// Msr addr to offset
///
/// Convert an integer interpreted as equal to (x2apic_base | msr_offset)
/// to a canonical offset.
///
/// @expects
/// @ensures
///
/// @param msr_addr the address to convert to a canonical offset
/// @return may or may not be a valid offset. Always check
///         before using to access the apic
///
constexpr inline auto msr_addr_to_offset(uint64_t msr_addr)
{ return (msr_addr & ~x2apic_base); }

/// Offset to memory address
///
/// Convert an offset to the corresponding xAPIC MMIO address
///
/// @expects
/// @ensures
///
/// @param offset the offset to convert
/// @param base the base MMIO address of the xAPIC. Equals
///        0xFEE00000 by default
/// @return may or may not be a valid xAPIC register address. Check
///         before using to access the apic
///
constexpr inline auto offset_to_mem_addr(
    offset_t offset, uintptr_t base = xapic_default_base)
{ return base | (offset << 4U); }

/// Offset to msr address
///
/// Convert an offset to the corresponding x2APIC MSR address
///
/// @expects
/// @ensures
///
/// @param offset the offset to convert
/// @return may or may not be a valid x2APIC register address. Check
///         before using to access the apic
///
constexpr inline auto offset_to_msr_addr(offset_t offset)
{ return x2apic_base | offset; }

/// A register is 'unstable' if its value cannot be reliably read
/// even when interrupts are disabled (e.g. IRR)
namespace xapic_unstable
{
    constexpr const auto mask = 0x20U;
    constexpr const auto from = 5U;
    constexpr const auto name = "xapic_unstable";

    constexpr inline auto is_enabled(attr_t attr) noexcept
    { return is_bit_set(attr, from); }

    constexpr inline auto is_disabled(attr_t attr) noexcept
    { return is_bit_cleared(attr, from); }

    constexpr inline void enable(attr_t &attr) noexcept
    { attr = set_bit(attr, from); }

    constexpr inline void disable(attr_t &attr) noexcept
    { attr = clear_bit(attr, from); }

    inline void dump(int level, attr_t attr, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(attr), msg); }
}

namespace x2apic_unstable
{
    constexpr const auto mask = 0x10U;
    constexpr const auto from = 4U;
    constexpr const auto name = "x2apic_unstable";

    constexpr inline auto is_enabled(attr_t attr) noexcept
    { return is_bit_set(attr, from); }

    constexpr inline auto is_disabled(attr_t attr) noexcept
    { return is_bit_cleared(attr, from); }

    constexpr inline void enable(attr_t &attr) noexcept
    { attr = set_bit(attr, from); }

    constexpr inline void disable(attr_t &attr) noexcept
    { attr = clear_bit(attr, from); }

    inline void dump(int level, attr_t attr, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(attr), msg); }
}

namespace xapic_readable
{
    constexpr const auto mask = 0x08U;
    constexpr const auto from = 3U;
    constexpr const auto name = "xapic_readable";

    constexpr inline auto is_enabled(attr_t attr) noexcept
    { return is_bit_set(attr, from); }

    constexpr inline auto is_disabled(attr_t attr) noexcept
    { return is_bit_cleared(attr, from); }

    constexpr inline void enable(attr_t &attr) noexcept
    { attr = set_bit(attr, from); }

    constexpr inline void disable(attr_t &attr) noexcept
    { attr = clear_bit(attr, from); }

    inline void dump(int level, attr_t attr, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(attr), msg); }
}

namespace xapic_writable
{
    constexpr const auto mask = 0x04U;
    constexpr const auto from = 2U;
    constexpr const auto name = "xapic_writable";

    constexpr inline auto is_enabled(attr_t attr) noexcept
    { return is_bit_set(attr, from); }

    constexpr inline auto is_disabled(attr_t attr) noexcept
    { return is_bit_cleared(attr, from); }

    constexpr inline void enable(attr_t &attr) noexcept
    { attr = set_bit(attr, from); }

    constexpr inline void disable(attr_t &attr) noexcept
    { attr = clear_bit(attr, from); }

    inline void dump(int level, attr_t attr, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(attr), msg); }
}

namespace x2apic_readable
{
    constexpr const auto mask = 0x02U;
    constexpr const auto from = 1U;
    constexpr const auto name = "x2apic_readable";

    constexpr inline auto is_enabled(attr_t attr) noexcept
    { return is_bit_set(attr, from); }

    constexpr inline auto is_disabled(attr_t attr) noexcept
    { return is_bit_cleared(attr, from); }

    constexpr inline void enable(attr_t &attr) noexcept
    { attr = set_bit(attr, from); }

    constexpr inline void disable(attr_t &attr) noexcept
    { attr = clear_bit(attr, from); }

    inline void dump(int level, attr_t attr, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(attr), msg); }
}

namespace x2apic_writable
{
    constexpr const auto mask = 0x01U;
    constexpr const auto from = 0U;
    constexpr const auto name = "x2apic_writable";

    constexpr inline auto is_enabled(attr_t attr) noexcept
    { return is_bit_set(attr, from); }

    constexpr inline auto is_disabled(attr_t attr) noexcept
    { return is_bit_cleared(attr, from); }

    constexpr inline void enable(attr_t &attr) noexcept
    { attr = set_bit(attr, from); }

    constexpr inline void disable(attr_t &attr) noexcept
    { attr = clear_bit(attr, from); }

    inline void dump(int level, attr_t attr, std::string *msg = nullptr)
    { bfdebug_subbool(level, name, is_enabled(attr), msg); }
}

inline auto exists_in_x2apic(offset_t offset)
{
    const auto attr = attributes.at(offset);
    return x2apic_readable::is_enabled(attr) ||
           x2apic_writable::is_enabled(attr);
}

inline auto readable_in_x2apic(offset_t offset)
{
    const auto attr = attributes.at(offset);
    return x2apic_readable::is_enabled(attr);
}

inline auto writable_in_x2apic(offset_t offset)
{
    const auto attr = attributes.at(offset);
    return x2apic_writable::is_enabled(attr);
}

inline auto stable_in_x2apic(offset_t offset)
{
    const auto attr = attributes.at(offset);
    return x2apic_unstable::is_disabled(attr);
}

inline auto exists_in_xapic(offset_t offset)
{
    const auto attr = attributes.at(offset);

    return xapic_readable::is_enabled(attr) ||
           xapic_writable::is_enabled(attr);
}

inline auto readable_in_xapic(offset_t offset)
{
    const auto attr = attributes.at(offset);
    return xapic_readable::is_enabled(attr);
}

inline auto writable_in_xapic(offset_t offset)
{
    const auto attr = attributes.at(offset);
    return xapic_writable::is_enabled(attr);
}

inline auto stable_in_xapic(offset_t offset)
{
    const auto attr = attributes.at(offset);
    return xapic_unstable::is_disabled(attr);
}

namespace lvt
{

constexpr const auto reset_value = (1ULL << 16U);
constexpr const auto default_size = 0x7ULL;

namespace cmci
{
    constexpr const auto name = "cmci";

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
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

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_mode(lev, get(val), msg); }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_status(lev, get(val), msg); }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val,  msg);
        vector::dump(lev, val, msg);
        delivery_mode::dump(lev, val, msg);
        delivery_status::dump(lev, val, msg);
        mask_bit::dump(lev, val, msg);
    }
}

namespace timer
{
    constexpr const auto name = "timer";

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_status(lev, get(val), msg); }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    namespace timer_mode
    {
        constexpr const auto mask = 0x0000000000060000ULL;
        constexpr const auto from = 17ULL;
        constexpr const auto name = "timer_mode";

        constexpr const auto one_shot = 0U;
        constexpr const auto periodic = 1U;
        constexpr const auto tsc_deadline = 2U;

        inline auto get(value_type val)
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val)
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        {
            switch (get(val)) {
                case one_shot: bfdebug_subtext(lev, name, "one-shot", msg);
                    break;
                case periodic: bfdebug_subtext(lev, name, "periodic", msg);
                    break;
                case tsc_deadline: bfdebug_subtext(lev, name, "TSC-deadline", msg);
                    break;
                default:
                    bferror_subtext(lev, name, "reserved", msg);
                    bferror_subnhex(lev, "value", val, msg);
                    throw std::invalid_argument("reserved timer_mode: " + std::to_string(val));
            }
        }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val, msg);
        vector::dump(lev, val, msg);
        delivery_status::dump(lev, val, msg);
        mask_bit::dump(lev, val, msg);
        timer_mode::dump(lev, val, msg);
    }
}

namespace thermal
{
    constexpr const auto name = "thermal";

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
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

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_mode(lev, get(val), msg); }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_status(lev, get(val), msg); }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val,  msg);
        vector::dump(lev, val, msg);
        delivery_mode::dump(lev, val, msg);
        delivery_status::dump(lev, val, msg);
        mask_bit::dump(lev, val, msg);
    }
}

namespace pmi
{
    constexpr const auto name = "pmi";

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
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

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_mode(lev, get(val), msg); }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_status(lev, get(val), msg); }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val,  msg);
        vector::dump(lev, val, msg);
        delivery_mode::dump(lev, val, msg);
        delivery_status::dump(lev, val, msg);
        mask_bit::dump(lev, val, msg);
    }
}

namespace lint0
{
    constexpr const auto name = "lint0";

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
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

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_mode(lev, get(val), msg); }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_status(lev, get(val), msg); }
    }

    namespace polarity
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "polarity";

        constexpr const auto active_high = 0U;
        constexpr const auto active_low = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        {
            if (get(val) == active_high) {
                bfdebug_subtext(lev, name, "active_high", msg);
                return;
            }

            bfdebug_subtext(lev, name, "active_low", msg);
        }
    }

    namespace remote_irr
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "remote_irr";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    namespace trigger_mode
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "trigger_mode";

        constexpr const auto edge = 0U;
        constexpr const auto level = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        {
            if (get(val) == edge) {
                bfdebug_subtext(lev, name, "edge", msg);
                return;
            }

            bfdebug_subtext(lev, name, "level", msg);
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val,  msg);
        vector::dump(lev, val, msg);
        delivery_status::dump(lev, val, msg);
        polarity::dump(lev, val, msg);
        remote_irr::dump(lev, val, msg);
        trigger_mode::dump(lev, val, msg);
        mask_bit::dump(lev, val, msg);
    }
}

namespace lint1
{
    constexpr const auto name = "lint1";

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
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

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_mode(lev, get(val), msg); }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_status(lev, get(val), msg); }
    }

    namespace polarity
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13ULL;
        constexpr const auto name = "polarity";

        constexpr const auto active_high = 0U;
        constexpr const auto active_low = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        {
            if (get(val) == active_high) {
                bfdebug_subtext(lev, name, "active_high", msg);
                return;
            }

            bfdebug_subtext(lev, name, "active_low", msg);
        }
    }

    namespace remote_irr
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "remote_irr";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    namespace trigger_mode
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "trigger_mode";

        constexpr const auto edge = 0U;
        constexpr const auto level = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        {
            if (get(val) == edge) {
                bfdebug_subtext(lev, name, "edge", msg);
                return;
            }

            bfdebug_subtext(lev, name, "level", msg);
        }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val,  msg);
        vector::dump(lev, val, msg);
        delivery_status::dump(lev, val, msg);
        polarity::dump(lev, val, msg);
        remote_irr::dump(lev, val, msg);
        trigger_mode::dump(lev, val, msg);
        mask_bit::dump(lev, val, msg);
    }
}

namespace error
{
    constexpr const auto name = "error";

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;


        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_status(lev, get(val), msg); }
    }

    namespace mask_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "mask_bit";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val,  msg);
        vector::dump(lev, val, msg);
        delivery_status::dump(lev, val, msg);
        mask_bit::dump(lev, val, msg);
    }
}

}

namespace icr
{
    constexpr const auto name = "icr";

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
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

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_mode(lev, get(val), msg); }
    }

    namespace destination_mode
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11ULL;
        constexpr const auto name = "destination_mode";

        constexpr const auto physical = 0U;
        constexpr const auto logical = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        {
            if (get(val) == physical) {
                bfdebug_subtext(lev, name, "physical", msg);
                return;
            }

            bfdebug_subtext(lev, name, "logical", msg);
        }
    }

    namespace delivery_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "delivery_status";

        constexpr const auto idle = 0U;
        constexpr const auto send_pending = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { dump_delivery_status(lev, get(val), msg); }
    }

    namespace level
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14ULL;
        constexpr const auto name = "level";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, val, msg); }
    }

    namespace trigger_mode
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15ULL;
        constexpr const auto name = "trigger_mode";

        constexpr const auto edge = 0U;
        constexpr const auto level = 1U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        {
            if (get(val) == edge) {
                bfdebug_subtext(lev, name, "edge", msg);
                return;
            }

            bfdebug_subtext(lev, name, "level", msg);
        }
    }

    namespace destination_shorthand
    {
        constexpr const auto mask = 0x00000000000C0000ULL;
        constexpr const auto from = 18ULL;
        constexpr const auto name = "destination_shorthand";

        constexpr const auto none = 0U;
        constexpr const auto self = 1U;
        constexpr const auto all_incl_self = 2U;
        constexpr const auto all_excl_self = 3U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        {
            if (get(val) == none) {
                bfdebug_subtext(lev, name, "none", msg);
                return;
            }

            if (get(val) == self) {
                bfdebug_subtext(lev, name, "self", msg);
                return;
            }

            if (get(val) == all_incl_self) {
                bfdebug_subtext(lev, name, "all_incl_self", msg);
                return;
            }

            if (get(val) == all_excl_self) {
                bfdebug_subtext(lev, name, "all_excl_self", msg);
                return;
            }
        }
    }

    namespace x2apic_destination
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32ULL;
        constexpr const auto name = "x2apic_destination";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    namespace xapic_destination
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56ULL;
        constexpr const auto name = "xapic_destination";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val, msg);
        vector::dump(lev, val, msg);
        delivery_mode::dump(lev, val, msg);
        destination_mode::dump(lev, val, msg);
        level::dump(lev, val, msg);
        trigger_mode::dump(lev, val, msg);
        destination_shorthand::dump(lev, val, msg);
        x2apic_destination::dump(lev, val, msg);
        xapic_destination::dump(lev, val, msg);
    }
}

namespace self_ipi
{
    constexpr const auto name = "self_ipi";

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val, msg);
        vector::dump(lev, val, msg);
    }
}

namespace version
{
    constexpr const auto name = "version";

    namespace version
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "version";

        constexpr const auto reset_value = 0x10U;

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    namespace max_lvt_entry_minus_one
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16ULL;
        constexpr const auto name = "max_lvt_entry_minus_one";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    namespace suppress_eoi_broadcast_supported
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24ULL;
        constexpr const auto name = "suppress_eoi_broadcast_supported";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val, msg);
        version::dump(lev, val, msg);
        max_lvt_entry_minus_one::dump(lev, val, msg);
        suppress_eoi_broadcast_supported::dump(lev, val, msg);
    }
}

namespace svr
{
    constexpr const auto name = "svr";
    constexpr const auto reset_value = 0x000000FFULL;

    namespace vector
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "vector";

        inline auto get(value_type val) noexcept
        { return get_bits(val, mask) >> from; }

        inline void set(value_type &reg, value_type val) noexcept
        { reg = set_bits(reg, mask, val << from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subnhex(lev, name, get(val), msg); }
    }

    namespace apic_enable_bit
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8ULL;
        constexpr const auto name = "apic_enable_bit";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    namespace focus_checking
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9ULL;
        constexpr const auto name = "focus_checking";

        inline auto is_disabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_enabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void disable(value_type &val)
        { val = set_bit(val, from); }

        inline void enable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    namespace suppress_eoi_broadcast
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "suppress_eoi_broadcast";

        inline auto is_enabled(value_type val)
        { return is_bit_set(val, from); }

        inline auto is_disabled(value_type val)
        { return is_bit_cleared(val, from); }

        inline void enable(value_type &val)
        { val = set_bit(val, from); }

        inline void disable(value_type &val)
        { val = clear_bit(val, from); }

        inline void dump(int lev, value_type val, std::string *msg = nullptr)
        { bfdebug_subbool(lev, name, is_enabled(val), msg); }
    }

    inline void dump(int lev, value_type val, std::string *msg = nullptr)
    {
        bfdebug_nhex(lev, name, val, msg);
        vector::dump(lev, val, msg);
        apic_enable_bit::dump(lev, val, msg);
        focus_checking::dump(lev, val, msg);
        suppress_eoi_broadcast::dump(lev, val, msg);
    }
}

inline void dump_delivery_status(int lev, value_type val, std::string *msg)
{
    const auto name = "delivery_status";
    const auto idle = 0;
    const auto pending = 1;

    if (val == idle) {
        bfdebug_subtext(lev, name, "idle", msg);
        return;
    }

    if (val == pending) {
        bfdebug_subtext(lev, name, "send pending", msg);
        return;
    }
}

inline void dump_delivery_mode(int lev, value_type val, std::string *msg)
{
    const auto name = "delivery_mode";

    switch (val) {
        case 0: bfdebug_subtext(lev, name, "fixed", msg); break;
        case 2: bfdebug_subtext(lev, name, "smi", msg); break;
        case 4: bfdebug_subtext(lev, name, "nmi", msg); break;
        case 5: bfdebug_subtext(lev, name, "init", msg); break;
        case 7: bfdebug_subtext(lev, name, "extint", msg); break;

        default:
            bfalert_subtext(lev, name, "unknown", msg);
            bfalert_subnhex(lev, "value", val, msg);
            throw std::invalid_argument("unknown delivery_mode: " + std::to_string(val));
    }
}

inline void init_nonexistent(uint64_t offset) noexcept
{
    attr_t attr = 0ULL;

    xapic_readable::disable(attr);
    xapic_writable::disable(attr);

    x2apic_readable::disable(attr);
    x2apic_writable::disable(attr);

    attributes.at(offset) = attr;
}


inline void init_xapic_read_write(uint64_t offset) noexcept
{
    attr_t attr = attributes.at(offset);

    x2apic_readable::disable(attr);
    x2apic_writable::disable(attr);

    xapic_readable::enable(attr);
    xapic_writable::enable(attr);

    attributes.at(offset) = attr;
}

inline void init_x2apic_write_only(uint64_t offset) noexcept
{
    attr_t attr = attributes.at(offset);

    x2apic_readable::disable(attr);
    x2apic_writable::enable(attr);

    xapic_readable::disable(attr);
    xapic_writable::disable(attr);

    attributes.at(offset) = attr;
}

inline void init_both_write_only(uint64_t offset) noexcept
{
    attr_t attr = attributes.at(offset);

    x2apic_readable::disable(attr);
    x2apic_writable::enable(attr);

    xapic_readable::disable(attr);
    xapic_writable::enable(attr);

    attributes.at(offset) = attr;
}

inline void init_both_read_only(uint64_t offset) noexcept
{
    attr_t attr = attributes.at(offset);

    x2apic_readable::enable(attr);
    x2apic_writable::disable(attr);

    xapic_readable::enable(attr);
    xapic_writable::disable(attr);

    attributes.at(offset) = attr;
}

inline void init_both_read_write(uint64_t offset) noexcept
{
    attr_t attr = attributes.at(offset);

    x2apic_readable::enable(attr);
    x2apic_writable::enable(attr);

    xapic_readable::enable(attr);
    xapic_writable::enable(attr);

    attributes.at(offset) = attr;
}


inline void init_unstable(uint64_t offset) noexcept
{
    attr_t attr = attributes.at(offset);

    x2apic_unstable::enable(attr);
    xapic_unstable::enable(attr);

    attributes.at(offset) = attr;
}

/// Note the isr, irr, and tmr are marked as unstable. This
/// means that even though they are readable, we can't be sure that
/// the value read from a physical piece won't change before we
/// enter into the guest.
///
/// In the eapis, unstable registers will be initialized to 0 in the virt_lapic
/// initializers that read from the physical lapics. There are alot of
/// decisions made based on the values of the isr and irr, so starting from
/// known values will be better for debugging.

inline void init_attributes() noexcept
{
    using namespace ::intel_x64::msrs;

    const auto dfr_addr = xapic_default_base | 0x0E0ULL;
    const auto icr_high = xapic_default_base | 0x310ULL;

    for (auto i = 0ULL; i < count; i++) {
        attributes.at(i) = 0ULL;

        switch (i) {
            case mem_addr_to_offset(dfr_addr):
            case mem_addr_to_offset(icr_high):
                init_xapic_read_write(i);
                break;

            case msr_addr_to_offset(ia32_x2apic_self_ipi::addr):
                init_x2apic_write_only(i);
                break;

            case msr_addr_to_offset(ia32_x2apic_eoi::addr):
                init_both_write_only(i);
                break;

            case msr_addr_to_offset(ia32_x2apic_apicid::addr):
            case msr_addr_to_offset(ia32_x2apic_version::addr):
            case msr_addr_to_offset(ia32_x2apic_ppr::addr):

            case msr_addr_to_offset(ia32_x2apic_isr0::addr):
            case msr_addr_to_offset(ia32_x2apic_isr1::addr):
            case msr_addr_to_offset(ia32_x2apic_isr2::addr):
            case msr_addr_to_offset(ia32_x2apic_isr3::addr):
            case msr_addr_to_offset(ia32_x2apic_isr4::addr):
            case msr_addr_to_offset(ia32_x2apic_isr5::addr):
            case msr_addr_to_offset(ia32_x2apic_isr6::addr):
            case msr_addr_to_offset(ia32_x2apic_isr7::addr):

            case msr_addr_to_offset(ia32_x2apic_tmr0::addr):
            case msr_addr_to_offset(ia32_x2apic_tmr1::addr):
            case msr_addr_to_offset(ia32_x2apic_tmr2::addr):
            case msr_addr_to_offset(ia32_x2apic_tmr3::addr):
            case msr_addr_to_offset(ia32_x2apic_tmr4::addr):
            case msr_addr_to_offset(ia32_x2apic_tmr5::addr):
            case msr_addr_to_offset(ia32_x2apic_tmr6::addr):
            case msr_addr_to_offset(ia32_x2apic_tmr7::addr):

            case msr_addr_to_offset(ia32_x2apic_irr0::addr):
            case msr_addr_to_offset(ia32_x2apic_irr1::addr):
            case msr_addr_to_offset(ia32_x2apic_irr2::addr):
            case msr_addr_to_offset(ia32_x2apic_irr3::addr):
            case msr_addr_to_offset(ia32_x2apic_irr4::addr):
            case msr_addr_to_offset(ia32_x2apic_irr5::addr):
            case msr_addr_to_offset(ia32_x2apic_irr6::addr):
            case msr_addr_to_offset(ia32_x2apic_irr7::addr):
                init_unstable(i);

            case msr_addr_to_offset(ia32_x2apic_cur_count::addr):
                init_both_read_only(i);
                break;

            case msr_addr_to_offset(ia32_x2apic_tpr::addr):
            case msr_addr_to_offset(ia32_x2apic_sivr::addr):
            case msr_addr_to_offset(ia32_x2apic_esr::addr):
            case msr_addr_to_offset(ia32_x2apic_icr::addr):

            case msr_addr_to_offset(ia32_x2apic_lvt_cmci::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_timer::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_thermal::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_pmi::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_lint0::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_lint1::addr):
            case msr_addr_to_offset(ia32_x2apic_lvt_error::addr):

            case msr_addr_to_offset(ia32_x2apic_init_count::addr):
            case msr_addr_to_offset(ia32_x2apic_div_conf::addr):
                init_both_read_write(i);
                break;

            default:
                init_nonexistent(i);
                break;
        }
    }
}

}
}
// *INDENT-ON*

#endif
