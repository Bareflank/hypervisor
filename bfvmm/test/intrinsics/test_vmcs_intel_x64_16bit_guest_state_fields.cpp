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

    using namespace vmcs::guest_es_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::guest_es_selector::dump(0);
}

TEST_CASE("vmcs_guest_es_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_es_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_guest_es_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_es_selector;

    ti::set(true);
    CHECK(ti::is_enabled());
    ti::set(false);
    CHECK(ti::is_disabled());

    ti::set(ti::mask, true);
    CHECK(ti::is_enabled(ti::mask));
    ti::set(0x0, false);
    CHECK(ti::is_disabled(0x0));

    ti::set_if_exists(true);
    CHECK(ti::is_enabled_if_exists());
    ti::set_if_exists(false);
    CHECK(ti::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_es_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_es_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_guest_cs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cs_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::guest_cs_selector::dump(0);
}

TEST_CASE("vmcs_guest_cs_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cs_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_guest_cs_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cs_selector;

    ti::set(true);
    CHECK(ti::is_enabled());
    ti::set(false);
    CHECK(ti::is_disabled());

    ti::set(ti::mask, true);
    CHECK(ti::is_enabled(ti::mask));
    ti::set(0x0, false);
    CHECK(ti::is_disabled(0x0));

    ti::set_if_exists(true);
    CHECK(ti::is_enabled_if_exists());
    ti::set_if_exists(false);
    CHECK(ti::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cs_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_cs_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_guest_ss_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ss_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::guest_ss_selector::dump(0);
}

TEST_CASE("vmcs_guest_ss_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ss_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_guest_ss_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ss_selector;

    ti::set(true);
    CHECK(ti::is_enabled());
    ti::set(false);
    CHECK(ti::is_disabled());

    ti::set(ti::mask, true);
    CHECK(ti::is_enabled(ti::mask));
    ti::set(0x0, false);
    CHECK(ti::is_disabled(0x0));

    ti::set_if_exists(true);
    CHECK(ti::is_enabled_if_exists());
    ti::set_if_exists(false);
    CHECK(ti::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ss_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ss_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_guest_ds_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ds_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::guest_ds_selector::dump(0);
}

TEST_CASE("vmcs_guest_ds_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ds_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_guest_ds_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ds_selector;

    ti::set(true);
    CHECK(ti::is_enabled());
    ti::set(false);
    CHECK(ti::is_disabled());

    ti::set(ti::mask, true);
    CHECK(ti::is_enabled(ti::mask));
    ti::set(0x0, false);
    CHECK(ti::is_disabled(0x0));

    ti::set_if_exists(true);
    CHECK(ti::is_enabled_if_exists());
    ti::set_if_exists(false);
    CHECK(ti::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ds_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ds_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_guest_fs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_fs_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::guest_fs_selector::dump(0);
}

TEST_CASE("vmcs_guest_fs_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_fs_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_guest_fs_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_fs_selector;

    ti::set(true);
    CHECK(ti::is_enabled());
    ti::set(false);
    CHECK(ti::is_disabled());

    ti::set(ti::mask, true);
    CHECK(ti::is_enabled(ti::mask));
    ti::set(0x0, false);
    CHECK(ti::is_disabled(0x0));

    ti::set_if_exists(true);
    CHECK(ti::is_enabled_if_exists());
    ti::set_if_exists(false);
    CHECK(ti::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_fs_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_fs_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_guest_gs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_gs_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::guest_gs_selector::dump(0);
}

TEST_CASE("vmcs_guest_gs_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_gs_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_guest_gs_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_gs_selector;

    ti::set(true);
    CHECK(ti::is_enabled());
    ti::set(false);
    CHECK(ti::is_disabled());

    ti::set(ti::mask, true);
    CHECK(ti::is_enabled(ti::mask));
    ti::set(0x0, false);
    CHECK(ti::is_disabled(0x0));

    ti::set_if_exists(true);
    CHECK(ti::is_enabled_if_exists());
    ti::set_if_exists(false);
    CHECK(ti::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_gs_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_gs_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_guest_ldtr_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ldtr_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::guest_ldtr_selector::dump(0);
}

TEST_CASE("vmcs_guest_ldtr_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ldtr_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_guest_ldtr_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ldtr_selector;

    ti::set(true);
    CHECK(ti::is_enabled());
    ti::set(false);
    CHECK(ti::is_disabled());

    ti::set(ti::mask, true);
    CHECK(ti::is_enabled(ti::mask));
    ti::set(0x0, false);
    CHECK(ti::is_disabled(0x0));

    ti::set_if_exists(true);
    CHECK(ti::is_enabled_if_exists());
    ti::set_if_exists(false);
    CHECK(ti::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ldtr_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_ldtr_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_guest_tr_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_tr_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::guest_tr_selector::dump(0);
}

TEST_CASE("vmcs_guest_tr_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_tr_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_guest_tr_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_tr_selector;

    ti::set(true);
    CHECK(ti::is_enabled());
    ti::set(false);
    CHECK(ti::is_disabled());

    ti::set(ti::mask, true);
    CHECK(ti::is_enabled(ti::mask));
    ti::set(0x0, false);
    CHECK(ti::is_disabled(0x0));

    ti::set_if_exists(true);
    CHECK(ti::is_enabled_if_exists());
    ti::set_if_exists(false);
    CHECK(ti::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_tr_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_tr_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_guest_interrupt_status")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_interrupt_status;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] =
        msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask << 32;

    CHECK(exists());

    set(100UL);
    CHECK(get() == 100UL);

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;
    CHECK_FALSE(exists());
    CHECK_THROWS(set(1UL));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(1UL));
    CHECK_NOTHROW(get_if_exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask << 32;
    CHECK(get() == 200UL);
}

TEST_CASE("vmcs_pml_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::pml_index;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] =
        msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::enable_pml::mask << 32;

    CHECK(exists());

    set(100UL);
    CHECK(get() == 100UL);

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;
    CHECK_FALSE(exists());
    CHECK_THROWS(set(1UL));
    CHECK_THROWS(get());
    CHECK_NOTHROW(set_if_exists(1UL));
    CHECK_NOTHROW(get_if_exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] =
        msrs::ia32_vmx_procbased_ctls2::enable_pml::mask << 32;
    CHECK(get() == 200UL);
}

#endif
