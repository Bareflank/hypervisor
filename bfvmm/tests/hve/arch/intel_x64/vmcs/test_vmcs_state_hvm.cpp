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
#include <hippomocks.h>

#include <intrinsics/x86/intel_x64.h>
#include <vmcs/vmcs_intel_x64_host_vm_state.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

uint16_t test_es;
uint16_t test_cs;
uint16_t test_ss;
uint16_t test_ds;
uint16_t test_fs;
uint16_t test_gs;
uint16_t test_ldtr;
uint16_t test_tr;

uint64_t test_cr0;
uint64_t test_cr3;
uint64_t test_cr4;
uint64_t test_dr7;
uint64_t test_rflags;

gdt_reg_x64_t test_gdtr{};
idt_reg_x64_t test_idtr{};

std::vector<gdt_x64::segment_descriptor_type> test_gdt = {
    0x0,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF
};

std::vector<idt_x64::interrupt_descriptor_type> test_idt{512};

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint32_t, uint32_t> g_eax_cpuid;

static uint16_t
test_read_es() noexcept
{ return test_es; }

static uint16_t
test_read_cs() noexcept
{ return test_cs; }

static uint16_t
test_read_ss() noexcept
{ return test_ss; }

static uint16_t
test_read_ds() noexcept
{ return test_ds; }

static uint16_t
test_read_fs() noexcept
{ return test_fs; }

static uint16_t
test_read_gs() noexcept
{ return test_gs; }

static uint16_t
test_read_tr() noexcept
{ return test_tr; }

static uint16_t
test_read_ldtr() noexcept
{ return test_ldtr; }

static void
test_write_es(uint16_t val) noexcept
{ test_es = val; }

static void
test_write_cs(uint16_t val) noexcept
{ test_cs = val; }

static void
test_write_ss(uint16_t val) noexcept
{ test_ss = val; }

static void
test_write_ds(uint16_t val) noexcept
{ test_ds = val; }

static void
test_write_fs(uint16_t val) noexcept
{ test_fs = val; }

static void
test_write_gs(uint16_t val) noexcept
{ test_gs = val; }

static void
test_write_tr(uint16_t val) noexcept
{ test_tr = val; }

static void
test_write_ldtr(uint16_t val) noexcept
{ test_ldtr = val; }

static uint64_t
test_read_cr0() noexcept
{ return test_cr0; }

static uint64_t
test_read_cr3() noexcept
{ return test_cr3; }

static uint64_t
test_read_cr4() noexcept
{ return test_cr4; }

static void
test_write_cr0(uint64_t val) noexcept
{ test_cr0 = val; }

static void
test_write_cr3(uint64_t val) noexcept
{ test_cr3 = val; }

static void
test_write_cr4(uint64_t val) noexcept
{ test_cr4 = val; }

static uint64_t
test_read_dr7() noexcept
{ return test_dr7; }

static void
test_write_dr7(uint64_t val) noexcept
{ test_dr7 = val; }

static uint64_t
test_read_rflags() noexcept
{ return test_rflags; }

static void
test_write_rflags(uint64_t val) noexcept
{ test_rflags = val; }

static void
test_read_gdt(gdt_reg_x64_t *gdt_reg) noexcept
{ *gdt_reg = test_gdtr; }

static void
test_read_idt(idt_reg_x64_t *idt_reg) noexcept
{ *idt_reg = test_idtr; }

static uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

static void
test_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

static uint32_t
test_cpuid_eax(uint32_t val) noexcept
{ return g_eax_cpuid[val]; }

void
setup_gdt()
{
    auto limit = test_gdt.size() * sizeof(gdt_x64::segment_descriptor_type);

    test_gdtr.base = &test_gdt.at(0);
    test_gdtr.limit = gsl::narrow_cast<gdt_reg_x64_t::limit_type>(limit);
}

void
setup_idt()
{
    auto limit = test_idt.size() * sizeof(idt_x64::interrupt_descriptor_type);

    test_idtr.base = &test_idt.at(0);
    test_idtr.limit = gsl::narrow_cast<idt_reg_x64_t::limit_type>(limit);
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_es).Do(test_read_es);
    mocks.OnCallFunc(_read_cs).Do(test_read_cs);
    mocks.OnCallFunc(_read_ss).Do(test_read_ss);
    mocks.OnCallFunc(_read_ds).Do(test_read_ds);
    mocks.OnCallFunc(_read_fs).Do(test_read_fs);
    mocks.OnCallFunc(_read_gs).Do(test_read_gs);
    mocks.OnCallFunc(_read_tr).Do(test_read_tr);
    mocks.OnCallFunc(_read_ldtr).Do(test_read_ldtr);

    mocks.OnCallFunc(_write_es).Do(test_write_es);
    mocks.OnCallFunc(_write_cs).Do(test_write_cs);
    mocks.OnCallFunc(_write_ss).Do(test_write_ss);
    mocks.OnCallFunc(_write_ds).Do(test_write_ds);
    mocks.OnCallFunc(_write_fs).Do(test_write_fs);
    mocks.OnCallFunc(_write_gs).Do(test_write_gs);
    mocks.OnCallFunc(_write_tr).Do(test_write_tr);
    mocks.OnCallFunc(_write_ldtr).Do(test_write_ldtr);

    mocks.OnCallFunc(_read_cr0).Do(test_read_cr0);
    mocks.OnCallFunc(_read_cr3).Do(test_read_cr3);
    mocks.OnCallFunc(_read_cr4).Do(test_read_cr4);
    mocks.OnCallFunc(_write_cr0).Do(test_write_cr0);
    mocks.OnCallFunc(_write_cr3).Do(test_write_cr3);
    mocks.OnCallFunc(_write_cr4).Do(test_write_cr4);

    mocks.OnCallFunc(_read_dr7).Do(test_read_dr7);
    mocks.OnCallFunc(_write_dr7).Do(test_write_dr7);

    mocks.OnCallFunc(_read_rflags).Do(test_read_rflags);
    mocks.OnCallFunc(_write_rflags).Do(test_write_rflags);

    mocks.OnCallFunc(_read_gdt).Do(test_read_gdt);
    mocks.OnCallFunc(_read_idt).Do(test_read_idt);

    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_write_msr).Do(test_write_msr);

    mocks.OnCallFunc(_cpuid_eax).Do(test_cpuid_eax);

    setup_gdt();
    setup_idt();
}

TEST_CASE("vmcs: host_vm_state")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK_NOTHROW(vmcs_intel_x64_host_vm_state{});
}

TEST_CASE("vmcs: host_vm_state_segment_registers")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    segment_register::es::set(1U);
    segment_register::cs::set(1U);
    segment_register::ss::set(1U);
    segment_register::ds::set(1U);
    segment_register::fs::set(1U);
    segment_register::gs::set(1U);
    segment_register::tr::set(1U);
    segment_register::ldtr::set(1U);

    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.es() == 1U);
    CHECK(state.cs() == 1U);
    CHECK(state.ss() == 1U);
    CHECK(state.ds() == 1U);
    CHECK(state.fs() == 1U);
    CHECK(state.gs() == 1U);
    CHECK(state.tr() == 1U);
    CHECK(state.ldtr() == 1U);
}

TEST_CASE("vmcs: host_vm_state_control_registers")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::cr0::set(1U);
    intel_x64::cr3::set(2U);
    intel_x64::cr4::set(3U);

    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.cr0() == 1U);
    CHECK(state.cr3() == 2U);
    CHECK(state.cr4() == (3U | intel_x64::cr4::vmx_enable_bit::mask));
}

TEST_CASE("vmcs: host_vm_state_debug_registers")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    dr7::set(42U);
    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.dr7() == 42U);
}

TEST_CASE("vmcs: host_vm_state_rflags")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    rflags::set(42U);
    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.rflags() == 42U);
}

TEST_CASE("vmcs: host_vm_state_gdt_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs_intel_x64_host_vm_state state{};
    CHECK(state.gdt_base() == bfrcast(gdt_x64::integer_pointer, test_gdtr.base));
}

TEST_CASE("vmcs: host_vm_state_idt_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs_intel_x64_host_vm_state state{};
    CHECK(state.idt_base() == bfrcast(gdt_x64::integer_pointer, test_idtr.base));
}

TEST_CASE("vmcs: host_vm_state_gdt_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs_intel_x64_host_vm_state state{};
    CHECK(state.gdt_limit() == test_gdtr.limit);
}

TEST_CASE("vmcs: host_vm_state_idt_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs_intel_x64_host_vm_state state{};
    CHECK(state.idt_limit() == test_idtr.limit);
}

TEST_CASE("vmcs: host_vm_state_es_limit")
{
    SECTION("es_limit == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::es::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_limit() == 0U);
    }

    SECTION("es_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::es::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_cs_limit")
{
    SECTION("cs_limit == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::cs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_limit() == 0U);
    }

    SECTION("cs_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::cs::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ss_limit")
{
    SECTION("ss_limit == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ss::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_limit() == 0U);
    }

    SECTION("ss_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ss::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ds_limit")
{
    SECTION("ds_limit == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ds::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_limit() == 0U);
    }

    SECTION("ds_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ds::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_fs_limit")
{
    SECTION("fs_limit == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::fs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_limit() == 0U);
    }

    SECTION("fs_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::fs::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_gs_limit")
{
    SECTION("gs_limit == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::gs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_limit() == 0U);
    }

    SECTION("gs_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::gs::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_tr_limit")
{
    SECTION("tr_limit == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::tr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_limit() == 0U);
    }

    SECTION("tr_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::tr::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ldtr_limit")
{
    SECTION("ldtr_limit == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ldtr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_limit() == 0U);
    }

    SECTION("ldtr_limit == 0xFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ldtr::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_limit() == 0xFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_es_access_rights")
{
    SECTION("es_access_rights unusable") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::es::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_access_rights() == x64::access_rights::unusable);
    }

    SECTION("es_access_rights == 0x70") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::es::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_cs_access_rights")
{
    SECTION("cs_access_rights unusable") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::cs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_access_rights() == x64::access_rights::unusable);
    }

    SECTION("cs_access_rights == 0x70") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::cs::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_ss_access_rights")
{
    SECTION("ss_access_rights unusable") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ss::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_access_rights() == x64::access_rights::unusable);
    }

    SECTION("ss_access_rights == 0x70") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ss::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_ds_access_rights")
{
    SECTION("ds_access_rights unusable") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ds::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_access_rights() == x64::access_rights::unusable);
    }

    SECTION("ds_access_rights == 0x70") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ds::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_fs_access_rights")
{
    SECTION("fs_access_rights unusable") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::fs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_access_rights() == x64::access_rights::unusable);
    }

    SECTION("fs_access_rights == 0x70") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::fs::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_gs_access_rights")
{
    SECTION("gs_access_rights unusable") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::gs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_access_rights() == x64::access_rights::unusable);
    }

    SECTION("gs_access_rights == 0x70") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::gs::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_tr_access_rights")
{
    SECTION("tr_access_rights unusable") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::tr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_access_rights() == x64::access_rights::unusable);
    }

    SECTION("tr_access_rights == 0x70") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::tr::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_ldtr_access_rights")
{
    SECTION("ldtr_access_rights unusable") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ldtr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_access_rights() == x64::access_rights::unusable);
    }

    SECTION("ldtr_access_rights == 0x70") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ldtr::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_access_rights() == 0x70FF);
    }
}

TEST_CASE("vmcs: host_vm_state_es_base")
{
    SECTION("es_base == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::es::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_base() == 0U);
    }

    SECTION("es_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::es::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.es_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_cs_base")
{
    SECTION("cs_base == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::cs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_base() == 0U);
    }

    SECTION("cs_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::cs::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.cs_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ss_base")
{
    SECTION("ss_base == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ss::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_base() == 0U);
    }

    SECTION("ss_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ss::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ss_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ds_base")
{
    SECTION("ds_base == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ds::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_base() == 0U);
    }

    SECTION("ds_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ds::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ds_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_fs_base")
{
    SECTION("fs_base == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::fs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_base() == 0U);
    }

    SECTION("fs_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::fs::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.fs_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_gs_base")
{
    SECTION("gs_base == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::gs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_base() == 0U);
    }

    SECTION("gs_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::gs::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.gs_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_tr_base")
{
    SECTION("tr_base == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::tr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_base() == 0U);
    }

    SECTION("tr_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::tr::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.tr_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ldtr_base")
{
    SECTION("ldtr_base == 0") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ldtr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_base() == 0U);
    }

    SECTION("ldtr_base == 0xFFFFFFFF") {
        MockRepository mocks;
        setup_intrinsics(mocks);

        segment_register::ldtr::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        CHECK(state.ldtr_base() == 0xFFFFFFFF);
    }
}

TEST_CASE("vmcs: host_vm_state_ia32_msrs_no_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::set(42U);
    x64::msrs::ia32_pat::set(42U);
    intel_x64::msrs::ia32_efer::set(42U);
    intel_x64::msrs::ia32_perf_global_ctrl::set(42U);
    intel_x64::msrs::ia32_sysenter_cs::set(42U);
    intel_x64::msrs::ia32_sysenter_esp::set(42U);
    intel_x64::msrs::ia32_sysenter_eip::set(42U);
    intel_x64::msrs::ia32_fs_base::set(42U);
    intel_x64::msrs::ia32_gs_base::set(42U);

    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.ia32_debugctl_msr() == 42U);
    CHECK(state.ia32_pat_msr() == 42U);
    CHECK(state.ia32_efer_msr() == 42U);
    CHECK(state.ia32_perf_global_ctrl_msr() != 42U);
    CHECK(state.ia32_sysenter_cs_msr() == 42U);
    CHECK(state.ia32_sysenter_esp_msr() == 42U);
    CHECK(state.ia32_sysenter_eip_msr() == 42U);
    CHECK(state.ia32_fs_base_msr() == 42U);
    CHECK(state.ia32_gs_base_msr() == 42U);
}

TEST_CASE("vmcs: host_vm_state_ia32_msrs_perf")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    intel_x64::msrs::ia32_debugctl::set(42U);
    x64::msrs::ia32_pat::set(42U);
    intel_x64::msrs::ia32_efer::set(42U);
    intel_x64::msrs::ia32_perf_global_ctrl::set(42U);
    intel_x64::msrs::ia32_sysenter_cs::set(42U);
    intel_x64::msrs::ia32_sysenter_esp::set(42U);
    intel_x64::msrs::ia32_sysenter_eip::set(42U);
    intel_x64::msrs::ia32_fs_base::set(42U);
    intel_x64::msrs::ia32_gs_base::set(42U);
    g_eax_cpuid[intel_x64::cpuid::arch_perf_monitoring::addr] = 2;

    vmcs_intel_x64_host_vm_state state{};

    CHECK(state.ia32_debugctl_msr() == 42U);
    CHECK(state.ia32_pat_msr() == 42U);
    CHECK(state.ia32_efer_msr() == 42U);
    CHECK(state.ia32_perf_global_ctrl_msr() == 42U);
    CHECK(state.ia32_sysenter_cs_msr() == 42U);
    CHECK(state.ia32_sysenter_esp_msr() == 42U);
    CHECK(state.ia32_sysenter_eip_msr() == 42U);
    CHECK(state.ia32_fs_base_msr() == 42U);
    CHECK(state.ia32_gs_base_msr() == 42U);
}

TEST_CASE("vmcs: host_vm_state_dump")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs_intel_x64_host_vm_state state{};
    CHECK_NOTHROW(state.dump());
}

#endif
