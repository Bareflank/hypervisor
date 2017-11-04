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

#ifndef XAPIC_INTEL_X64_H
#define XAPIC_INTEL_X64_H

#include <intrinsics/x86/intel/apic/lapic.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_XAPIC
#ifdef SHARED_XAPIC
#define EXPORT_XAPIC EXPORT_SYM
#else
#define EXPORT_XAPIC IMPORT_SYM
#endif
#else
#define EXPORT_XAPIC
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

namespace intel_x64
{

/// xAPIC subclass of the lapic abstract base class
///
/// This class implements the abstract lapic interface for xapic
/// mode. It is marked final because it is intended to interact
/// directly with xapic hardware.
///
struct EXPORT_XAPIC xapic_ctl final : public lapic_ctl
{
    using apic_base_type = uintptr_t;

    //
    // Register reads
    //
    value_type read_id() override noexcept;
    value_type read_version() override noexcept;
    value_type read_tpr() override noexcept;
    value_type read_ldr() override noexcept;
    value_type read_svr() override noexcept;
    value_type read_icr() override noexcept;

    value_type read_isr(index idx) override noexcept;
    value_type read_tmr(index idx) override noexcept;
    value_type read_irr(index idx) override noexcept;

    value_type read_lvt(lvt_reg reg) override noexcept;
    value_type read_count(count_reg reg) override noexcept;
    value_type read_div_config() override noexcept;

    //
    // Register writes
    //
    void write_eoi() override noexcept;
    void write_tpr(value_type tpr) override noexcept;
    void write_svr(value_type svr) override noexcept;
    void write_icr(value_type icr) override noexcept;
    void write_lvt(lvt_reg reg, value_type val) override noexcept;
    void write_init_count(value_type count) override noexcept;
    void write_div_config(value_type config) override noexcept;

    //
    // Send a self-ipi
    //
    // A self-ipi is a self-targeted, edge-triggered, fixed interrupt
    // with the specified vector.
    //
    // @param vec - the vector of the self-ipi
    //
    void write_self_ipi(vector_type vec) override noexcept;

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
    bool level_triggered(vector_type vec) override noexcept;

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
    bool in_service(vector_type vec) override noexcept;

    //
    // Default operations
    //
    xapic_ctl();
    ~xapic_ctl() override = default;

    xapic_ctl(xapic_ctl &&) = default;
    xapic_ctl &operator=(xapic_ctl &&) = default;

    xapic_ctl(const xapic_ctl &) = delete;
    xapic_ctl &operator=(const xapic_ctl &) = delete;


private:

    std::unique_ptr<uint32_t[]> m_apic_page;

};

}

#endif
