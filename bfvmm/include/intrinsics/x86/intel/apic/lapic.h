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

#ifndef INTRINSICS_LAPIC_INTEL_X64_H
#define INTRINSICS_LAPIC_INTEL_X64_H

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_LAPIC
#ifdef SHARED_LAPIC
#define EXPORT_LAPIC EXPORT_SYM
#else
#define EXPORT_LAPIC IMPORT_SYM
#endif
#else
#define EXPORT_LAPIC
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

namespace intel_x64
{
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

    //
    // Note that this gets and sets the _full_address_
    //
    namespace base
    {
        constexpr const auto mask = 0xFFFFFF000ULL;
        constexpr const auto from = 12ULL;
        constexpr const auto name = "base";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask); }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask); }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val); }

        inline void dump(int level, std::string *msg = nullptr)
        { bfdebug_subnhex(level, name, get(), msg); }
    }

    namespace state
    {
        constexpr const auto mask = 0xC00ULL;
        constexpr const auto from = 10ULL;
        constexpr const auto name = "state";

        constexpr const auto disabled = 0x0ULL;
        constexpr const auto invalid = 0x4ULL;
        constexpr const auto xapic = 0x8ULL;
        constexpr const auto x2apic = 0xCULL;

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline auto enable_x2apic() noexcept
        { set(x2apic); }

        inline auto enable_x2apic(value_type msr) noexcept
        { return set_bits(msr, mask, x2apic << from); }

        inline auto enable_xapic() noexcept
        { set(xapic); }

        inline auto enable_xapic(value_type msr) noexcept
        { return set_bits(msr, mask, xapic << from); }

        inline auto disable() noexcept
        { set(disable); }

        inline auto disable(value_type msr) noexcept
        { return set_bits(msr, mask, disable << from); }

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
                default:
                    bferror_subtext(level, name, "UNKNOWN", msg);
                    return;
            }
        }
    }

    // TODO: add fields
}
}

namespace apic
{
    inline auto present() noexcept
    {
        // return cpuid::feature_information::edx::apic::is_enabled();
    }

    inline auto x2apic_supported() noexcept
    {
        // return cpuid::feature_information::ecx::x2apic::is_enabled();
    }

    inline auto
}

/// Local APIC base class
///
/// This abstract class provides an interface to lapic control operations
/// that are common to both xAPIC and x2APIC modes.
///
struct EXPORT_LAPIC lapic_ctl
{
    using value_type = uint64_t;
    using vector_type = uint64_t;

    enum index { idx0, idx1, idx2, idx3, idx4, idx5, idx6, idx7 };
    enum lvt_reg { cmci, timer, thermal, perf, lint0, lint1, error };
    enum count_reg { initial, current };

    //
    // Register reads
    //
    virtual value_type read_id() = 0;
    virtual value_type read_version() = 0;
    virtual value_type read_tpr() = 0;
    virtual value_type read_ldr() = 0;
    virtual value_type read_svr() = 0;
    virtual value_type read_icr() = 0;
    virtual value_type read_isr(index idx) = 0;
    virtual value_type read_tmr(index idx) = 0;
    virtual value_type read_irr(index idx) = 0;
    virtual value_type read_lvt(lvt_reg reg) = 0;
    virtual value_type read_count(count_reg reg) = 0;
    virtual value_type read_div_config() = 0;

    //
    // Register writes
    //
    virtual void write_eoi() = 0;
    virtual void write_tpr(value_type tpr) = 0;
    virtual void write_svr(value_type svr) = 0;
    virtual void write_icr(value_type icr) = 0;
    virtual void write_lvt(lvt_reg reg, value_type val) = 0;
    virtual void write_init_count(value_type count) = 0;
    virtual void write_div_config(value_type config) = 0;

    //
    // Send a self-ipi
    //
    // A self-ipi is a self-targeted, edge-triggered, fixed interrupt
    // with the specified vector.
    //
    // @param vec - the vector of the self-ipi
    //
    virtual void write_self_ipi(vector_type vec) = 0;

    //
    // Check trigger-mode
    //
    // @return true if the supplied vector is set in the TMR
    // @return false if the supplied vector is clear in the TMR
    //
    // @param vec - the vector for which the check occurs.
    //
    // @note to ensure an accurate result, the caller should mask
    // the vector prior to the call
    //
    virtual bool level_triggered(vector_type vec) = 0;

    //
    // Check if in-service
    //
    // @return true if the supplied vector is set in the ISR
    // @return false if the supplied vector is clear in the ISR
    //
    // @param vec - the vector for which the check occurs.
    //
    // @note to ensure an accurate result, the caller should mask
    // the vector prior to the call
    //
    virtual bool in_service(vector_type vec) = 0;

    //
    // Default operations
    //
    lapic_ctl() = default;
    virtual ~lapic_ctl() = default;

    lapic_ctl(lapic_ctl &&) = default;
    lapic_ctl &operator=(lapic_ctl &&) = default;

    lapic_ctl(const lapic_ctl &) = delete;
    lapic_ctl &operator=(const lapic_ctl &) = delete;
};

}

#endif
