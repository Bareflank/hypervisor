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

#include <map>
#include <arch/intel_x64/msrs.h>
#include <arch/intel_x64/vmcs/16bit_host_state_fields.h>

using namespace intel_x64;

std::map<uint64_t, uint64_t> g_vmcs_fields;

extern "C" bool
_vmread(uint64_t field, uint64_t *value) noexcept
{
    *value = g_vmcs_fields[field];
    return true;
}

extern "C" bool
_vmwrite(uint64_t field, uint64_t value) noexcept
{
    g_vmcs_fields[field] = value;
    return true;
}

TEST_CASE("vmcs_host_es_selector")
{
    using namespace vmcs::host_es_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::host_es_selector::dump(0);
}

TEST_CASE("vmcs_host_es_selector_rpl")
{
    using namespace vmcs::host_es_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_host_es_selector_ti")
{
    using namespace vmcs::host_es_selector;

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

TEST_CASE("vmcs_host_es_selector_index")
{
    using namespace vmcs::host_es_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_host_cs_selector")
{
    using namespace vmcs::host_cs_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::host_cs_selector::dump(0);
}

TEST_CASE("vmcs_host_cs_selector_rpl")
{
    using namespace vmcs::host_cs_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_host_cs_selector_ti")
{
    using namespace vmcs::host_cs_selector;

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

TEST_CASE("vmcs_host_cs_selector_index")
{
    using namespace vmcs::host_cs_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_host_ss_selector")
{
    using namespace vmcs::host_ss_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::host_ss_selector::dump(0);
}

TEST_CASE("vmcs_host_ss_selector_rpl")
{
    using namespace vmcs::host_ss_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_host_ss_selector_ti")
{
    using namespace vmcs::host_ss_selector;

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

TEST_CASE("vmcs_host_ss_selector_index")
{
    using namespace vmcs::host_ss_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_host_ds_selector")
{
    using namespace vmcs::host_ds_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::host_ds_selector::dump(0);
}

TEST_CASE("vmcs_host_ds_selector_rpl")
{
    using namespace vmcs::host_ds_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_host_ds_selector_ti")
{
    using namespace vmcs::host_ds_selector;

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

TEST_CASE("vmcs_host_ds_selector_index")
{
    using namespace vmcs::host_ds_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_host_fs_selector")
{
    using namespace vmcs::host_fs_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::host_fs_selector::dump(0);
}

TEST_CASE("vmcs_host_fs_selector_rpl")
{
    using namespace vmcs::host_fs_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_host_fs_selector_ti")
{
    using namespace vmcs::host_fs_selector;

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

TEST_CASE("vmcs_host_fs_selector_index")
{
    using namespace vmcs::host_fs_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_host_gs_selector")
{
    using namespace vmcs::host_gs_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::host_gs_selector::dump(0);
}

TEST_CASE("vmcs_host_gs_selector_rpl")
{
    using namespace vmcs::host_gs_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_host_gs_selector_ti")
{
    using namespace vmcs::host_gs_selector;

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

TEST_CASE("vmcs_host_gs_selector_index")
{
    using namespace vmcs::host_gs_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}

TEST_CASE("vmcs_host_tr_selector")
{
    using namespace vmcs::host_tr_selector;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    vmcs::host_tr_selector::dump(0);
}

TEST_CASE("vmcs_host_tr_selector_rpl")
{
    using namespace vmcs::host_tr_selector;

    rpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get() == (rpl::mask >> rpl::from));

    rpl::set(rpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get(rpl::mask) == (rpl::mask >> rpl::from));

    rpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(rpl::get_if_exists() == (rpl::mask >> rpl::from));
}

TEST_CASE("vmcs_host_tr_selector_ti")
{
    using namespace vmcs::host_tr_selector;

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

TEST_CASE("vmcs_host_tr_selector_index")
{
    using namespace vmcs::host_tr_selector;

    index::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get() == (index::mask >> index::from));

    index::set(index::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get(index::mask) == (index::mask >> index::from));

    index::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(index::get_if_exists() == (index::mask >> index::from));
}
