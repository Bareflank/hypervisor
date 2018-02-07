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

#include <catch/catch.hpp>
#include <intrinsics.h>
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;

TEST_CASE("test name goes here")
{
    CHECK(true);
}

std::map<msrs::field_type, msrs::value_type> g_msrs;

std::map<cpuid::field_type, cpuid::value_type> g_edx_cpuid;

uint32_t g_apic_page[1024];

extern "C" uint64_t
_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

struct cpuid_regs {
    cpuid::value_type edx;
};

struct cpuid_regs g_regs;

extern "C" uint32_t
_cpuid_edx(uint32_t val) noexcept
{ return g_edx_cpuid[val]; }

extern "C" void
_sfence() noexcept
{ }

TEST_CASE("xapic_supported")
{
    g_edx_cpuid[cpuid::feature_information::addr] =
        cpuid::feature_information::edx::apic::mask;
    CHECK(xapic::supported());

    g_edx_cpuid[cpuid::feature_information::addr] = 0x0;
    CHECK_FALSE(xapic::supported());
}

TEST_CASE("xapic_control_validate_gpa_op")
{
    xapic_control ctrl;

    CHECK(ctrl.validate_gpa_op(0xFEE00000ULL, lapic_control::read) == -1);      // Non-existent Register
    CHECK(ctrl.validate_gpa_op(0xFEE00030ULL, lapic_control::write) == -1);     // Unwritable Register (version)
    CHECK(ctrl.validate_gpa_op(0xFEE000B0ULL, lapic_control::read) == -1);      // Unreadable Register (eoi)
    CHECK(ctrl.validate_gpa_op(0xFEE00020ULL, lapic_control::read) == 0x2U);    // Successful Operation

    // x2apic vs xapic register conflicts
    CHECK(ctrl.validate_gpa_op(0xFEE00020ULL, lapic_control::write) == 0x2U);   // ID Write
    CHECK(ctrl.validate_gpa_op(0xFEE00090ULL, lapic_control::read) == 0x9U);    // APR Read
    CHECK(ctrl.validate_gpa_op(0xFEE00090ULL, lapic_control::write) == -1);     // APR Write
    CHECK(ctrl.validate_gpa_op(0xFEE000C0ULL, lapic_control::read) == 0xCU);    // RRD Read
    CHECK(ctrl.validate_gpa_op(0xFEE000C0ULL, lapic_control::write) == -1);     // RRD Write
    CHECK(ctrl.validate_gpa_op(0xFEE000D0ULL, lapic_control::write) == 0xDU);   // LDR Write
    CHECK(ctrl.validate_gpa_op(0xFEE000E0ULL, lapic_control::read) == 0xEU);    // DFR Read
    CHECK(ctrl.validate_gpa_op(0xFEE000E0ULL, lapic_control::write) == 0xEU);   // DFR Write
    CHECK(ctrl.validate_gpa_op(0xFEE00280ULL, lapic_control::write) == -1);     // ESR Write
    CHECK(ctrl.validate_gpa_op(0xFEE00310ULL, lapic_control::read) == 0x31U);   // ICR High Read
    CHECK(ctrl.validate_gpa_op(0xFEE00310ULL, lapic_control::write) == 0x31U);  // ICR High Write
    CHECK(ctrl.validate_gpa_op(0xFEE003F0ULL, lapic_control::read) == -1);      // Self IPI Read
    CHECK(ctrl.validate_gpa_op(0xFEE003F0ULL, lapic_control::write) == -1);     // Self IPI Write
}

TEST_CASE("xapic_control_validate_msr_op")
{
    xapic_control ctrl;

    CHECK(ctrl.validate_msr_op(0x00000000ULL, lapic_control::read) == -1);      // Out of Lower Bound Register
    CHECK(ctrl.validate_msr_op(0xFFFFFFFFULL, lapic_control::read) == -1);      // Out of Upper Bound Register
    CHECK(ctrl.validate_msr_op(0x00000800ULL, lapic_control::read) == -1);      // Non-existent Register
    CHECK(ctrl.validate_msr_op(0x00000803ULL, lapic_control::write) == -1);     // Unwritable Register (version)
    CHECK(ctrl.validate_msr_op(0x0000080BULL, lapic_control::read) == -1);      // Unreadable Register (eoi)
    CHECK(ctrl.validate_msr_op(0x00000802ULL, lapic_control::read) == 0x2U);    // Successful Operation

    // x2apic vs xapic register conflicts
    CHECK(ctrl.validate_msr_op(0x00000802ULL, lapic_control::write) == 0x2U);   // ID Write
    CHECK(ctrl.validate_msr_op(0x00000809ULL, lapic_control::read) == 0x9U);    // APR Read
    CHECK(ctrl.validate_msr_op(0x00000809ULL, lapic_control::write) == -1);     // APR Write
    CHECK(ctrl.validate_msr_op(0x0000080CULL, lapic_control::read) == 0xCU);    // RRD Read
    CHECK(ctrl.validate_msr_op(0x0000080CULL, lapic_control::write) == -1);     // RRD Write
    CHECK(ctrl.validate_msr_op(0x0000080DULL, lapic_control::write) == 0xDU);   // LDR Write
    CHECK(ctrl.validate_msr_op(0x0000080EULL, lapic_control::read) == 0xEU);    // DFR Read
    CHECK(ctrl.validate_msr_op(0x0000080EULL, lapic_control::write) == 0xEU);   // DFR Write
    CHECK(ctrl.validate_msr_op(0x00000828ULL, lapic_control::write) == -1);     // ESR Write
    CHECK(ctrl.validate_msr_op(0x00000831ULL, lapic_control::read) == 0x31U);   // ICR High Read
    CHECK(ctrl.validate_msr_op(0x00000831ULL, lapic_control::write) == 0x31U);  // ICR High Write
    CHECK(ctrl.validate_msr_op(0x0000083FULL, lapic_control::read) == -1);      // Self IPI Read
    CHECK(ctrl.validate_msr_op(0x0000083FULL, lapic_control::write) == -1);     // Self IPI Write
}

TEST_CASE("xapic_control_read_register")
{
    xapic_control ctrl(g_apic_page);

    g_apic_page[0x02ULL << 2] = 0xFFFFFFFFULL;
    CHECK(ctrl.read_register(0x02U) == 0xFFFFFFFFULL);

    g_apic_page[0x02ULL << 2] = 0x0ULL;
    CHECK(ctrl.read_register(0x02U) == 0x0ULL);
}

TEST_CASE("xapic_control_write_register")
{
    xapic_control ctrl(g_apic_page);

    ctrl.write_register(0x02ULL, 0xFFFFFFFFULL);
    CHECK(g_apic_page[0x02ULL << 2] == 0xFFFFFFFFULL);

    ctrl.write_register(0x02ULL, 0x0ULL);
    CHECK(g_apic_page[0x02ULL << 2] == 0x0ULL);
}

TEST_CASE("xapic_control_read_id")
{
    xapic_control ctrl(g_apic_page);

    g_apic_page[xapic::regs::id.offset << 2] = 0xFFFFFFFFULL;
    CHECK(ctrl.read_id() == 0xFFFFFFFFULL);

    g_apic_page[xapic::regs::id.offset << 2] = 0x0ULL;
    CHECK(ctrl.read_id() == 0x0ULL);
}

TEST_CASE("xapid_control_write_tpr")
{
    xapic_control ctrl(g_apic_page);

    ctrl.write_tpr(0xFFFFFFFFULL);
    CHECK(g_apic_page[xapic::regs::tpr.offset << 2] == 0xFFFFFFFFULL);

    ctrl.write_tpr(0x0ULL);
    CHECK(g_apic_page[xapic::regs::tpr.offset << 2] == 0x0ULL);
}

#endif
