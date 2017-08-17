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

#include <catch/catch.hpp>
#include <hippomocks.h>
#include <intrinsics/x86/intel_x64.h>
#include <intrinsics/x86/common_x64.h>
#include <test/vmcs_utils.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;

uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

static bool
test_vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs_fields[field];
    return true;
}

static bool
test_vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs_fields[field] = val;
    return true;
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_vmread).Do(test_vmread);
    mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
}

TEST_CASE("test name goes here")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(true);
}

TEST_CASE("vmcs_guest_es_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_selector::set(100UL);
    CHECK(vmcs::guest_es_selector::get() == 100UL);
    CHECK(vmcs::guest_es_selector::exists());

    vmcs::guest_es_selector::set_if_exists(200UL);
    CHECK(vmcs::guest_es_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_guest_es_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_selector::rpl::set(1UL);
    CHECK(vmcs::guest_es_selector::rpl::get() == 1UL);

    vmcs::guest_es_selector::rpl::set(0UL);
    CHECK(vmcs::guest_es_selector::rpl::get() == 0UL);

    vmcs::guest_es_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::guest_es_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_es_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::guest_es_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_es_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_selector::ti::set(true);
    CHECK(vmcs::guest_es_selector::ti::get());

    vmcs::guest_es_selector::ti::set(false);
    CHECK_FALSE(vmcs::guest_es_selector::ti::get());

    vmcs::guest_es_selector::ti::set_if_exists(true);
    CHECK(vmcs::guest_es_selector::ti::get_if_exists());

    vmcs::guest_es_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::guest_es_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_guest_es_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_selector::index::set(1UL);
    CHECK(vmcs::guest_es_selector::index::get() == 1UL);

    vmcs::guest_es_selector::index::set(0UL);
    CHECK(vmcs::guest_es_selector::index::get() == 0UL);

    vmcs::guest_es_selector::index::set_if_exists(1UL);
    CHECK(vmcs::guest_es_selector::index::get_if_exists() == 1UL);

    vmcs::guest_es_selector::index::set_if_exists(0UL);
    CHECK(vmcs::guest_es_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_selector::set(100UL);

    CHECK(vmcs::guest_cs_selector::get() == 100UL);
    CHECK(vmcs::guest_cs_selector::exists());

    vmcs::guest_cs_selector::set_if_exists(200UL);
    CHECK(vmcs::guest_cs_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_guest_cs_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_selector::rpl::set(1UL);
    CHECK(vmcs::guest_cs_selector::rpl::get() == 1UL);

    vmcs::guest_cs_selector::rpl::set(0UL);
    CHECK(vmcs::guest_cs_selector::rpl::get() == 0UL);

    vmcs::guest_cs_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::guest_cs_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_cs_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_selector::ti::set(true);
    CHECK(vmcs::guest_cs_selector::ti::get());

    vmcs::guest_cs_selector::ti::set(false);
    CHECK_FALSE(vmcs::guest_cs_selector::ti::get());

    vmcs::guest_cs_selector::ti::set_if_exists(true);
    CHECK(vmcs::guest_cs_selector::ti::get_if_exists());

    vmcs::guest_cs_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::guest_cs_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_guest_cs_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_selector::index::set(1UL);
    CHECK(vmcs::guest_cs_selector::index::get() == 1UL);

    vmcs::guest_cs_selector::index::set(0UL);
    CHECK(vmcs::guest_cs_selector::index::get() == 0UL);

    vmcs::guest_cs_selector::index::set_if_exists(1UL);
    CHECK(vmcs::guest_cs_selector::index::get_if_exists() == 1UL);

    vmcs::guest_cs_selector::index::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_selector::set(100UL);

    CHECK(vmcs::guest_ss_selector::get() == 100UL);
    CHECK(vmcs::guest_ss_selector::exists());

    vmcs::guest_ss_selector::set_if_exists(200UL);
    CHECK(vmcs::guest_ss_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_guest_ss_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_selector::rpl::set(1UL);
    CHECK(vmcs::guest_ss_selector::rpl::get() == 1UL);

    vmcs::guest_ss_selector::rpl::set(0UL);
    CHECK(vmcs::guest_ss_selector::rpl::get() == 0UL);

    vmcs::guest_ss_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::guest_ss_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_ss_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_selector::ti::set(true);
    CHECK(vmcs::guest_ss_selector::ti::get());

    vmcs::guest_ss_selector::ti::set(false);
    CHECK_FALSE(vmcs::guest_ss_selector::ti::get());

    vmcs::guest_ss_selector::ti::set_if_exists(true);
    CHECK(vmcs::guest_ss_selector::ti::get_if_exists());

    vmcs::guest_ss_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::guest_ss_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_guest_ss_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_selector::index::set(1UL);
    CHECK(vmcs::guest_ss_selector::index::get() == 1UL);

    vmcs::guest_ss_selector::index::set(0UL);
    CHECK(vmcs::guest_ss_selector::index::get() == 0UL);

    vmcs::guest_ss_selector::index::set_if_exists(1UL);
    CHECK(vmcs::guest_ss_selector::index::get_if_exists() == 1UL);

    vmcs::guest_ss_selector::index::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_selector::set(100UL);

    CHECK(vmcs::guest_ds_selector::get() == 100UL);
    CHECK(vmcs::guest_ds_selector::exists());

    vmcs::guest_ds_selector::set_if_exists(200UL);
    CHECK(vmcs::guest_ds_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_guest_ds_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_selector::rpl::set(1UL);
    CHECK(vmcs::guest_ds_selector::rpl::get() == 1UL);

    vmcs::guest_ds_selector::rpl::set(0UL);
    CHECK(vmcs::guest_ds_selector::rpl::get() == 0UL);

    vmcs::guest_ds_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::guest_ds_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_ds_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_selector::ti::set(true);
    CHECK(vmcs::guest_ds_selector::ti::get());

    vmcs::guest_ds_selector::ti::set(false);
    CHECK_FALSE(vmcs::guest_ds_selector::ti::get());

    vmcs::guest_ds_selector::ti::set_if_exists(true);
    CHECK(vmcs::guest_ds_selector::ti::get_if_exists());

    vmcs::guest_ds_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::guest_ds_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_guest_ds_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_selector::index::set(1UL);
    CHECK(vmcs::guest_ds_selector::index::get() == 1UL);

    vmcs::guest_ds_selector::index::set(0UL);
    CHECK(vmcs::guest_ds_selector::index::get() == 0UL);

    vmcs::guest_ds_selector::index::set_if_exists(1UL);
    CHECK(vmcs::guest_ds_selector::index::get_if_exists() == 1UL);

    vmcs::guest_ds_selector::index::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_selector::set(100UL);

    CHECK(vmcs::guest_fs_selector::get() == 100UL);
    CHECK(vmcs::guest_fs_selector::exists());

    vmcs::guest_fs_selector::set_if_exists(200UL);
    CHECK(vmcs::guest_fs_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_guest_fs_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_selector::rpl::set(1UL);
    CHECK(vmcs::guest_fs_selector::rpl::get() == 1UL);

    vmcs::guest_fs_selector::rpl::set(0UL);
    CHECK(vmcs::guest_fs_selector::rpl::get() == 0UL);

    vmcs::guest_fs_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::guest_fs_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_fs_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_selector::ti::set(true);
    CHECK(vmcs::guest_fs_selector::ti::get());

    vmcs::guest_fs_selector::ti::set(false);
    CHECK_FALSE(vmcs::guest_fs_selector::ti::get());

    vmcs::guest_fs_selector::ti::set_if_exists(true);
    CHECK(vmcs::guest_fs_selector::ti::get_if_exists());

    vmcs::guest_fs_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::guest_fs_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_guest_fs_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_selector::index::set(1UL);
    CHECK(vmcs::guest_fs_selector::index::get() == 1UL);

    vmcs::guest_fs_selector::index::set(0UL);
    CHECK(vmcs::guest_fs_selector::index::get() == 0UL);

    vmcs::guest_fs_selector::index::set_if_exists(1UL);
    CHECK(vmcs::guest_fs_selector::index::get_if_exists() == 1UL);

    vmcs::guest_fs_selector::index::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_selector::set(100UL);

    CHECK(vmcs::guest_gs_selector::get() == 100UL);
    CHECK(vmcs::guest_gs_selector::exists());

    vmcs::guest_gs_selector::set_if_exists(200UL);
    CHECK(vmcs::guest_gs_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_guest_gs_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_selector::rpl::set(1UL);
    CHECK(vmcs::guest_gs_selector::rpl::get() == 1UL);

    vmcs::guest_gs_selector::rpl::set(0UL);
    CHECK(vmcs::guest_gs_selector::rpl::get() == 0UL);

    vmcs::guest_gs_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::guest_gs_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_gs_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_selector::ti::set(true);
    CHECK(vmcs::guest_gs_selector::ti::get());

    vmcs::guest_gs_selector::ti::set(false);
    CHECK_FALSE(vmcs::guest_gs_selector::ti::get());

    vmcs::guest_gs_selector::ti::set_if_exists(true);
    CHECK(vmcs::guest_gs_selector::ti::get_if_exists());

    vmcs::guest_gs_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::guest_gs_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_guest_gs_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_selector::index::set(1UL);
    CHECK(vmcs::guest_gs_selector::index::get() == 1UL);

    vmcs::guest_gs_selector::index::set(0UL);
    CHECK(vmcs::guest_gs_selector::index::get() == 0UL);

    vmcs::guest_gs_selector::index::set_if_exists(1UL);
    CHECK(vmcs::guest_gs_selector::index::get_if_exists() == 1UL);

    vmcs::guest_gs_selector::index::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_selector::set(100UL);

    CHECK(vmcs::guest_ldtr_selector::get() == 100UL);
    CHECK(vmcs::guest_ldtr_selector::exists());

    vmcs::guest_ldtr_selector::set_if_exists(200UL);
    CHECK(vmcs::guest_ldtr_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_guest_ldtr_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_selector::rpl::set(1UL);
    CHECK(vmcs::guest_ldtr_selector::rpl::get() == 1UL);

    vmcs::guest_ldtr_selector::rpl::set(0UL);
    CHECK(vmcs::guest_ldtr_selector::rpl::get() == 0UL);

    vmcs::guest_ldtr_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::guest_ldtr_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_ldtr_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_selector::ti::set(true);
    CHECK(vmcs::guest_ldtr_selector::ti::get());

    vmcs::guest_ldtr_selector::ti::set(false);
    CHECK_FALSE(vmcs::guest_ldtr_selector::ti::get());

    vmcs::guest_ldtr_selector::ti::set_if_exists(true);
    CHECK(vmcs::guest_ldtr_selector::ti::get_if_exists());

    vmcs::guest_ldtr_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::guest_ldtr_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_guest_ldtr_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_selector::index::set(1UL);
    CHECK(vmcs::guest_ldtr_selector::index::get() == 1UL);

    vmcs::guest_ldtr_selector::index::set(0UL);
    CHECK(vmcs::guest_ldtr_selector::index::get() == 0UL);

    vmcs::guest_ldtr_selector::index::set_if_exists(1UL);
    CHECK(vmcs::guest_ldtr_selector::index::get_if_exists() == 1UL);

    vmcs::guest_ldtr_selector::index::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_selector::set(100UL);

    CHECK(vmcs::guest_tr_selector::get() == 100UL);
    CHECK(vmcs::guest_tr_selector::exists());

    vmcs::guest_tr_selector::set_if_exists(200UL);
    CHECK(vmcs::guest_tr_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_guest_tr_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_selector::rpl::set(1UL);
    CHECK(vmcs::guest_tr_selector::rpl::get() == 1UL);

    vmcs::guest_tr_selector::rpl::set(0UL);
    CHECK(vmcs::guest_tr_selector::rpl::get() == 0UL);

    vmcs::guest_tr_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::guest_tr_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_tr_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_selector::ti::set(true);
    CHECK(vmcs::guest_tr_selector::ti::get());

    vmcs::guest_tr_selector::ti::set(false);
    CHECK_FALSE(vmcs::guest_tr_selector::ti::get());

    vmcs::guest_tr_selector::ti::set_if_exists(true);
    CHECK(vmcs::guest_tr_selector::ti::get_if_exists());

    vmcs::guest_tr_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::guest_tr_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_guest_tr_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_selector::index::set(1UL);
    CHECK(vmcs::guest_tr_selector::index::get() == 1UL);

    vmcs::guest_tr_selector::index::set(0UL);
    CHECK(vmcs::guest_tr_selector::index::get() == 0UL);

    vmcs::guest_tr_selector::index::set_if_exists(1UL);
    CHECK(vmcs::guest_tr_selector::index::get_if_exists() == 1UL);

    vmcs::guest_tr_selector::index::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_interrupt_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] =
        msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask << 32;

    CHECK(vmcs::guest_interrupt_status::exists());

    vmcs::guest_interrupt_status::set(100UL);
    CHECK(vmcs::guest_interrupt_status::get() == 100UL);

    vmcs::guest_interrupt_status::set_if_exists(200UL);
    CHECK(vmcs::guest_interrupt_status::get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;
    CHECK_FALSE(vmcs::guest_interrupt_status::exists());
    CHECK_THROWS(vmcs::guest_interrupt_status::set(1UL));
    CHECK_THROWS(vmcs::guest_interrupt_status::get());
    CHECK_NOTHROW(vmcs::guest_interrupt_status::set_if_exists(1UL));
    CHECK_NOTHROW(vmcs::guest_interrupt_status::get_if_exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask << 32;
    CHECK(vmcs::guest_interrupt_status::get() == 200UL);
}

TEST_CASE("vmcs_pml_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] =
        msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::enable_pml::mask << 32;

    CHECK(vmcs::pml_index::exists());

    vmcs::pml_index::set(100UL);
    CHECK(vmcs::pml_index::get() == 100UL);

    vmcs::pml_index::set_if_exists(200UL);
    CHECK(vmcs::pml_index::get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;
    CHECK_FALSE(vmcs::pml_index::exists());
    CHECK_THROWS(vmcs::pml_index::set(1UL));
    CHECK_THROWS(vmcs::pml_index::get());
    CHECK_NOTHROW(vmcs::pml_index::set_if_exists(1UL));
    CHECK_NOTHROW(vmcs::pml_index::get_if_exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::enable_pml::mask << 32;
    CHECK(vmcs::pml_index::get() == 200UL);
}

#endif
