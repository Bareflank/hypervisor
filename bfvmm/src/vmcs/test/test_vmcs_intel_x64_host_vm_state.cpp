//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#include <test.h>
#include <vmcs/vmcs_intel_x64_host_vm_state.h>

#include <intrinsics/srs_x64.h>
#include <intrinsics/gdt_x64.h>
#include <intrinsics/idt_x64.h>
#include <intrinsics/debug_x64.h>
#include <intrinsics/crs_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>

using namespace x64;

uint16_t test_es;
uint16_t test_cs;
uint16_t test_ss;
uint16_t test_ds;
uint16_t test_fs;
uint16_t test_gs;
uint16_t test_ldtr;
uint16_t test_tr;

uint16_t test_es_index;
uint16_t test_cs_index;
uint16_t test_ss_index;
uint16_t test_ds_index;
uint16_t test_fs_index;
uint16_t test_gs_index;
uint16_t test_ldtr_index;
uint16_t test_tr_index;
uint16_t test_gdt_index;

uint64_t test_cr0;
uint64_t test_cr3;
uint64_t test_cr4;
uint64_t test_dr7;
uint64_t test_rflags;

gdt_reg_x64_t test_gdtr{};
idt_reg_x64_t test_idtr{};

std::vector<gdt_x64::segment_descriptor_type> test_gdt =
{
    0x0,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF
};

std::vector<idt_x64::interrupt_descriptor_type> test_idt = { 0x0 };

void
setup_gdt()
{
    test_gdtr.base = &test_gdt.at(0);
    test_gdtr.limit = gsl::narrow_cast<gdt_reg_x64_t::limit_type>(test_gdt.size() *
                      sizeof(decltype(test_gdt)::value_type));
}

void
setup_idt()
{
    test_idtr.base = &test_idt.at(0);
    test_idtr.limit = gsl::narrow_cast<idt_reg_x64_t::limit_type>(test_idt.size() *
                      sizeof(decltype(test_idt)::value_type));
}

extern "C" uint16_t __read_es(void) noexcept { return test_es;}
extern "C" uint16_t __read_cs(void) noexcept { return test_cs;}
extern "C" uint16_t __read_ss(void) noexcept { return test_ss;}
extern "C" uint16_t __read_ds(void) noexcept { return test_ds;}
extern "C" uint16_t __read_fs(void) noexcept { return test_fs;}
extern "C" uint16_t __read_gs(void) noexcept { return test_gs;}
extern "C" uint16_t __read_tr(void) noexcept { return test_tr;}
extern "C" uint16_t __read_ldtr(void) noexcept { return test_ldtr; }
extern "C" void __write_es(uint16_t val) noexcept { test_es = val; }
extern "C" void __write_cs(uint16_t val) noexcept { test_cs = val; }
extern "C" void __write_ss(uint16_t val) noexcept { test_ss = val; }
extern "C" void __write_ds(uint16_t val) noexcept { test_ds = val; }
extern "C" void __write_fs(uint16_t val) noexcept { test_fs = val; }
extern "C" void __write_gs(uint16_t val) noexcept { test_gs = val; }
extern "C" void __write_tr(uint16_t val) noexcept { test_tr = val; }
extern "C" void __write_ldtr(uint16_t val) noexcept { test_ldtr = val; }

extern "C" uint64_t __read_cr0(void) noexcept { return test_cr0; }
extern "C" uint64_t __read_cr3(void) noexcept { return test_cr3; }
extern "C" uint64_t __read_cr4(void) noexcept { return test_cr4; }
extern "C" void __write_cr0(uint64_t val) noexcept { test_cr0 = val; }
extern "C" void __write_cr3(uint64_t val) noexcept { test_cr3 = val; }
extern "C" void __write_cr4(uint64_t val) noexcept { test_cr4 = val; }

extern "C" uint64_t __read_dr7(void) noexcept { return test_dr7; }
extern "C" void __write_dr7(uint64_t val) noexcept { test_dr7 = val; }

extern "C" uint64_t __read_rflags(void) noexcept { return test_rflags; }

extern "C" void __read_gdt(gdt_reg_x64_t *gdt_reg) noexcept
{ *gdt_reg = test_gdtr; }

extern "C" void __read_idt(idt_reg_x64_t *idt_reg) noexcept
{ *idt_reg = test_idtr; }

void
vmcs_ut::test_host_vm_state()
{
    this->expect_no_exception([&] { vmcs_intel_x64_host_vm_state state{}; });
}

void
vmcs_ut::test_host_vm_state_segment_registers()
{
    segment_register::es::set(1U);
    segment_register::cs::set(1U);
    segment_register::ss::set(1U);
    segment_register::ds::set(1U);
    segment_register::fs::set(1U);
    segment_register::gs::set(1U);
    segment_register::tr::set(1U);
    segment_register::ldtr::set(1U);

    this->expect_no_exception([&]
    {
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.es() == 1U);
        this->expect_true(state.cs() == 1U);
        this->expect_true(state.ss() == 1U);
        this->expect_true(state.ds() == 1U);
        this->expect_true(state.fs() == 1U);
        this->expect_true(state.gs() == 1U);
        this->expect_true(state.tr() == 1U);
        this->expect_true(state.ldtr() == 1U);
    });
}

void
vmcs_ut::test_host_vm_state_control_registers()
{
    cr0::set(1U);
    cr3::set(2U);
    cr4::set(3U);

    this->expect_no_exception([&]
    {
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.cr0() == 1U);
        this->expect_true(state.cr3() == 2U);
        this->expect_true(state.cr4() == (3U | cr4::vmx_enable_bit::mask));
    });
}

void
vmcs_ut::test_host_vm_state_debug_registers()
{
    dr7::set(42U);

    this->expect_no_exception([&]
    {
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.dr7() == 42U);
    });
}

void
vmcs_ut::test_host_vm_state_rflags()
{
    test_rflags = 42U;

    this->expect_no_exception([&]
    {
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.rflags() == 42U);
    });
}

void
vmcs_ut::test_host_vm_state_gdt_base()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        vmcs_intel_x64_host_vm_state state{};
        this->expect_true(state.gdt_base() == reinterpret_cast<gdt_x64::integer_pointer>(test_gdtr.base));
    });
}

void
vmcs_ut::test_host_vm_state_idt_base()
{
    setup_idt();

    this->expect_no_exception([&]
    {
        vmcs_intel_x64_host_vm_state state{};
        this->expect_true(state.idt_base() == reinterpret_cast<gdt_x64::integer_pointer>(test_idtr.base));
    });
}

void
vmcs_ut::test_host_vm_state_gdt_limit()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        vmcs_intel_x64_host_vm_state state{};
        this->expect_true(state.gdt_limit() == test_gdtr.limit);
    });
}

void
vmcs_ut::test_host_vm_state_idt_limit()
{
    setup_idt();

    this->expect_no_exception([&]
    {
        vmcs_intel_x64_host_vm_state state{};
        this->expect_true(state.idt_limit() == test_idtr.limit);
    });
}


void
vmcs_ut::test_host_vm_state_es_limit()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::es::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.es_limit() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::es::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.es_limit() == 0xFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_cs_limit()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::cs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.cs_limit() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::cs::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.cs_limit() == 0xFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_ss_limit()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::ss::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ss_limit() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::ss::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ss_limit() == 0xFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_ds_limit()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::ds::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ds_limit() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::ds::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ds_limit() == 0xFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_fs_limit()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::fs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.fs_limit() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::fs::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.fs_limit() == 0xFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_gs_limit()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::gs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.gs_limit() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::gs::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.gs_limit() == 0xFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_tr_limit()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::tr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.tr_limit() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::tr::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.tr_limit() == 0xFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_ldtr_limit()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::ldtr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ldtr_limit() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::ldtr::index::set(1U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ldtr_limit() == 0xFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_es_access_rights()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::es::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.es_access_rights() == x64::access_rights::unusable);
    });

    this->expect_no_exception([&]
    {
        segment_register::es::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.es_access_rights() == 0x70FF);
    });
}

void
vmcs_ut::test_host_vm_state_cs_access_rights()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::cs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.cs_access_rights() == x64::access_rights::unusable);
    });

    this->expect_no_exception([&]
    {
        segment_register::cs::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.cs_access_rights() == 0x70FF);
    });
}

void
vmcs_ut::test_host_vm_state_ss_access_rights()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::ss::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ss_access_rights() == x64::access_rights::unusable);
    });

    this->expect_no_exception([&]
    {
        segment_register::ss::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ss_access_rights() == 0x70FF);
    });
}

void
vmcs_ut::test_host_vm_state_ds_access_rights()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::ds::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ds_access_rights() == x64::access_rights::unusable);
    });

    this->expect_no_exception([&]
    {
        segment_register::ds::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ds_access_rights() == 0x70FF);
    });
}

void
vmcs_ut::test_host_vm_state_fs_access_rights()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::fs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.fs_access_rights() == x64::access_rights::unusable);
    });

    this->expect_no_exception([&]
    {
        segment_register::fs::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.fs_access_rights() == 0x70FF);
    });
}

void
vmcs_ut::test_host_vm_state_gs_access_rights()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::gs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.gs_access_rights() == x64::access_rights::unusable);
    });

    this->expect_no_exception([&]
    {
        segment_register::gs::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.gs_access_rights() == 0x70FF);
    });
}

void
vmcs_ut::test_host_vm_state_tr_access_rights()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::tr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.tr_access_rights() == x64::access_rights::unusable);
    });

    this->expect_no_exception([&]
    {
        segment_register::tr::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.tr_access_rights() == 0x70FF);
    });
}

void
vmcs_ut::test_host_vm_state_ldtr_access_rights()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::ldtr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ldtr_access_rights() == x64::access_rights::unusable);
    });

    this->expect_no_exception([&]
    {
        segment_register::ldtr::index::set(2U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ldtr_access_rights() == 0x70FF);
    });
}

void
vmcs_ut::test_host_vm_state_es_base()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::es::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.es_base() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::es::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.es_base() == 0xFFFFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_cs_base()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::cs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.cs_base() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::cs::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.cs_base() == 0xFFFFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_ss_base()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::ss::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ss_base() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::ss::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ss_base() == 0xFFFFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_ds_base()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::ds::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ds_base() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::ds::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ds_base() == 0xFFFFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_fs_base()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::fs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.fs_base() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::fs::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.fs_base() == 0xFFFFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_gs_base()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::gs::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.gs_base() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::gs::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.gs_base() == 0xFFFFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_tr_base()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::tr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.tr_base() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::tr::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.tr_base() == 0xFFFFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_ldtr_base()
{
    setup_gdt();

    this->expect_no_exception([&]
    {
        segment_register::ldtr::index::set(0U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ldtr_base() == 0U);
    });

    this->expect_no_exception([&]
    {
        segment_register::ldtr::index::set(3U);
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ldtr_base() == 0xFFFFFFFF);
    });
}

void
vmcs_ut::test_host_vm_state_ia32_msrs()
{
    msrs::ia32_debugctl::set(42U);
    msrs::ia32_pat::set(42U);
    msrs::ia32_efer::set(42U);
    msrs::ia32_perf_global_ctrl::set(42U);
    msrs::ia32_sysenter_cs::set(42U);
    msrs::ia32_sysenter_esp::set(42U);
    msrs::ia32_sysenter_eip::set(42U);
    msrs::ia32_fs_base::set(42U);
    msrs::ia32_gs_base::set(42U);

    this->expect_no_exception([&]
    {
        vmcs_intel_x64_host_vm_state state{};

        this->expect_true(state.ia32_debugctl_msr() == 42U);
        this->expect_true(state.ia32_pat_msr() == 42U);
        this->expect_true(state.ia32_efer_msr() == 42U);
        this->expect_true(state.ia32_perf_global_ctrl_msr() == 42U);
        this->expect_true(state.ia32_sysenter_cs_msr() == 42U);
        this->expect_true(state.ia32_sysenter_esp_msr() == 42U);
        this->expect_true(state.ia32_sysenter_eip_msr() == 42U);
        this->expect_true(state.ia32_fs_base_msr() == 42U);
        this->expect_true(state.ia32_gs_base_msr() == 42U);
    });
}

void
vmcs_ut::test_host_vm_state_dump()
{
    this->expect_no_exception([&]
    {
        vmcs_intel_x64_host_vm_state state{};
        this->expect_no_exception([&] { state.dump(); });
    });
}
