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
#include <intrinsics.h>

using namespace intel_x64;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;

extern "C" uint64_t
_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

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

TEST_CASE("vmcs_guest_es_limit")
{
    using namespace vmcs::guest_es_limit;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_cs_limit")
{
    using namespace vmcs::guest_cs_limit;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ss_limit")
{
    using namespace vmcs::guest_ss_limit;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ds_limit")
{
    using namespace vmcs::guest_ds_limit;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_fs_limit")
{
    using namespace vmcs::guest_fs_limit;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_gs_limit")
{
    using namespace vmcs::guest_gs_limit;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ldtr_limit")
{
    using namespace vmcs::guest_ldtr_limit;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_tr_limit")
{
    using namespace vmcs::guest_tr_limit;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_gdtr_limit")
{
    using namespace vmcs::guest_gdtr_limit;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);
    CHECK(size() == get() + 1UL);

    dump(0);
}

TEST_CASE("vmcs_guest_idtr_limit")
{
    using namespace vmcs::guest_idtr_limit;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);
    CHECK(size() == get() + 1UL);

    dump(0);
}

TEST_CASE("vmcs_guest_es_access_rights")
{
    using namespace vmcs::guest_es_access_rights;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_es_access_rights_type")
{
    using namespace vmcs::guest_es_access_rights;

    type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get() == (type::mask >> type::from));

    type::set(type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get(type::mask) == (type::mask >> type::from));

    type::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get_if_exists() == (type::mask >> type::from));
}

TEST_CASE("vmcs_guest_es_access_rights_s")
{
    using namespace vmcs::guest_es_access_rights;

    s::set(true);
    CHECK(s::is_enabled());
    s::set(false);
    CHECK(s::is_disabled());

    s::set(s::mask, true);
    CHECK(s::is_enabled(s::mask));
    s::set(0x0, false);
    CHECK(s::is_disabled(0x0));

    s::set_if_exists(true);
    CHECK(s::is_enabled_if_exists());
    s::set_if_exists(false);
    CHECK(s::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_es_access_rights_dpl")
{
    using namespace vmcs::guest_es_access_rights;

    dpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get() == (dpl::mask >> dpl::from));

    dpl::set(dpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get(dpl::mask) == (dpl::mask >> dpl::from));

    dpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get_if_exists() == (dpl::mask >> dpl::from));
}

TEST_CASE("vmcs_guest_es_access_rights_present")
{
    using namespace vmcs::guest_es_access_rights;

    present::set(true);
    CHECK(present::is_enabled());
    present::set(false);
    CHECK(present::is_disabled());

    present::set(present::mask, true);
    CHECK(present::is_enabled(present::mask));
    present::set(0x0, false);
    CHECK(present::is_disabled(0x0));

    present::set_if_exists(true);
    CHECK(present::is_enabled_if_exists());
    present::set_if_exists(false);
    CHECK(present::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_es_access_rights_avl")
{
    using namespace vmcs::guest_es_access_rights;

    avl::set(true);
    CHECK(avl::is_enabled());
    avl::set(false);
    CHECK(avl::is_disabled());

    avl::set(avl::mask, true);
    CHECK(avl::is_enabled(avl::mask));
    avl::set(0x0, false);
    CHECK(avl::is_disabled(0x0));

    avl::set_if_exists(true);
    CHECK(avl::is_enabled_if_exists());
    avl::set_if_exists(false);
    CHECK(avl::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_es_access_rights_l")
{
    using namespace vmcs::guest_es_access_rights;

    l::set(true);
    CHECK(l::is_enabled());
    l::set(false);
    CHECK(l::is_disabled());

    l::set(l::mask, true);
    CHECK(l::is_enabled(l::mask));
    l::set(0x0, false);
    CHECK(l::is_disabled(0x0));

    l::set_if_exists(true);
    CHECK(l::is_enabled_if_exists());
    l::set_if_exists(false);
    CHECK(l::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_es_access_rights_db")
{
    using namespace vmcs::guest_es_access_rights;

    db::set(true);
    CHECK(db::is_enabled());
    db::set(false);
    CHECK(db::is_disabled());

    db::set(db::mask, true);
    CHECK(db::is_enabled(db::mask));
    db::set(0x0, false);
    CHECK(db::is_disabled(0x0));

    db::set_if_exists(true);
    CHECK(db::is_enabled_if_exists());
    db::set_if_exists(false);
    CHECK(db::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_es_access_rights_granularity")
{
    using namespace vmcs::guest_es_access_rights;

    granularity::set(true);
    CHECK(granularity::is_enabled());
    granularity::set(false);
    CHECK(granularity::is_disabled());

    granularity::set(granularity::mask, true);
    CHECK(granularity::is_enabled(granularity::mask));
    granularity::set(0x0, false);
    CHECK(granularity::is_disabled(0x0));

    granularity::set_if_exists(true);
    CHECK(granularity::is_enabled_if_exists());
    granularity::set_if_exists(false);
    CHECK(granularity::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_es_access_rights_reserved")
{
    using namespace vmcs::guest_es_access_rights;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_es_access_rights_unusable")
{
    using namespace vmcs::guest_es_access_rights;

    unusable::set(true);
    CHECK(unusable::is_enabled());
    unusable::set(false);
    CHECK(unusable::is_disabled());

    unusable::set(unusable::mask, true);
    CHECK(unusable::is_enabled(unusable::mask));
    unusable::set(0x0, false);
    CHECK(unusable::is_disabled(0x0));

    unusable::set_if_exists(true);
    CHECK(unusable::is_enabled_if_exists());
    unusable::set_if_exists(false);
    CHECK(unusable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cs_access_rights")
{
    using namespace vmcs::guest_cs_access_rights;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_cs_access_rights_type")
{
    using namespace vmcs::guest_cs_access_rights;

    type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get() == (type::mask >> type::from));

    type::set(type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get(type::mask) == (type::mask >> type::from));

    type::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get_if_exists() == (type::mask >> type::from));
}

TEST_CASE("vmcs_guest_cs_access_rights_s")
{
    using namespace vmcs::guest_cs_access_rights;

    s::set(true);
    CHECK(s::is_enabled());
    s::set(false);
    CHECK(s::is_disabled());

    s::set(s::mask, true);
    CHECK(s::is_enabled(s::mask));
    s::set(0x0, false);
    CHECK(s::is_disabled(0x0));

    s::set_if_exists(true);
    CHECK(s::is_enabled_if_exists());
    s::set_if_exists(false);
    CHECK(s::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cs_access_rights_dpl")
{
    using namespace vmcs::guest_cs_access_rights;

    dpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get() == (dpl::mask >> dpl::from));

    dpl::set(dpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get(dpl::mask) == (dpl::mask >> dpl::from));

    dpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get_if_exists() == (dpl::mask >> dpl::from));
}

TEST_CASE("vmcs_guest_cs_access_rights_present")
{
    using namespace vmcs::guest_cs_access_rights;

    present::set(true);
    CHECK(present::is_enabled());
    present::set(false);
    CHECK(present::is_disabled());

    present::set(present::mask, true);
    CHECK(present::is_enabled(present::mask));
    present::set(0x0, false);
    CHECK(present::is_disabled(0x0));

    present::set_if_exists(true);
    CHECK(present::is_enabled_if_exists());
    present::set_if_exists(false);
    CHECK(present::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cs_access_rights_avl")
{
    using namespace vmcs::guest_cs_access_rights;

    avl::set(true);
    CHECK(avl::is_enabled());
    avl::set(false);
    CHECK(avl::is_disabled());

    avl::set(avl::mask, true);
    CHECK(avl::is_enabled(avl::mask));
    avl::set(0x0, false);
    CHECK(avl::is_disabled(0x0));

    avl::set_if_exists(true);
    CHECK(avl::is_enabled_if_exists());
    avl::set_if_exists(false);
    CHECK(avl::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cs_access_rights_l")
{
    using namespace vmcs::guest_cs_access_rights;

    l::set(true);
    CHECK(l::is_enabled());
    l::set(false);
    CHECK(l::is_disabled());

    l::set(l::mask, true);
    CHECK(l::is_enabled(l::mask));
    l::set(0x0, false);
    CHECK(l::is_disabled(0x0));

    l::set_if_exists(true);
    CHECK(l::is_enabled_if_exists());
    l::set_if_exists(false);
    CHECK(l::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cs_access_rights_db")
{
    using namespace vmcs::guest_cs_access_rights;

    db::set(true);
    CHECK(db::is_enabled());
    db::set(false);
    CHECK(db::is_disabled());

    db::set(db::mask, true);
    CHECK(db::is_enabled(db::mask));
    db::set(0x0, false);
    CHECK(db::is_disabled(0x0));

    db::set_if_exists(true);
    CHECK(db::is_enabled_if_exists());
    db::set_if_exists(false);
    CHECK(db::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cs_access_rights_granularity")
{
    using namespace vmcs::guest_cs_access_rights;

    granularity::set(true);
    CHECK(granularity::is_enabled());
    granularity::set(false);
    CHECK(granularity::is_disabled());

    granularity::set(granularity::mask, true);
    CHECK(granularity::is_enabled(granularity::mask));
    granularity::set(0x0, false);
    CHECK(granularity::is_disabled(0x0));

    granularity::set_if_exists(true);
    CHECK(granularity::is_enabled_if_exists());
    granularity::set_if_exists(false);
    CHECK(granularity::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_cs_access_rights_reserved")
{
    using namespace vmcs::guest_cs_access_rights;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_cs_access_rights_unusable")
{
    using namespace vmcs::guest_cs_access_rights;

    unusable::set(true);
    CHECK(unusable::is_enabled());
    unusable::set(false);
    CHECK(unusable::is_disabled());

    unusable::set(unusable::mask, true);
    CHECK(unusable::is_enabled(unusable::mask));
    unusable::set(0x0, false);
    CHECK(unusable::is_disabled(0x0));

    unusable::set_if_exists(true);
    CHECK(unusable::is_enabled_if_exists());
    unusable::set_if_exists(false);
    CHECK(unusable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ss_access_rights")
{
    using namespace vmcs::guest_ss_access_rights;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ss_access_rights_type")
{
    using namespace vmcs::guest_ss_access_rights;

    type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get() == (type::mask >> type::from));

    type::set(type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get(type::mask) == (type::mask >> type::from));

    type::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get_if_exists() == (type::mask >> type::from));
}

TEST_CASE("vmcs_guest_ss_access_rights_s")
{
    using namespace vmcs::guest_ss_access_rights;

    s::set(true);
    CHECK(s::is_enabled());
    s::set(false);
    CHECK(s::is_disabled());

    s::set(s::mask, true);
    CHECK(s::is_enabled(s::mask));
    s::set(0x0, false);
    CHECK(s::is_disabled(0x0));

    s::set_if_exists(true);
    CHECK(s::is_enabled_if_exists());
    s::set_if_exists(false);
    CHECK(s::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ss_access_rights_dpl")
{
    using namespace vmcs::guest_ss_access_rights;

    dpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get() == (dpl::mask >> dpl::from));

    dpl::set(dpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get(dpl::mask) == (dpl::mask >> dpl::from));

    dpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get_if_exists() == (dpl::mask >> dpl::from));
}

TEST_CASE("vmcs_guest_ss_access_rights_present")
{
    using namespace vmcs::guest_ss_access_rights;

    present::set(true);
    CHECK(present::is_enabled());
    present::set(false);
    CHECK(present::is_disabled());

    present::set(present::mask, true);
    CHECK(present::is_enabled(present::mask));
    present::set(0x0, false);
    CHECK(present::is_disabled(0x0));

    present::set_if_exists(true);
    CHECK(present::is_enabled_if_exists());
    present::set_if_exists(false);
    CHECK(present::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ss_access_rights_avl")
{
    using namespace vmcs::guest_ss_access_rights;

    avl::set(true);
    CHECK(avl::is_enabled());
    avl::set(false);
    CHECK(avl::is_disabled());

    avl::set(avl::mask, true);
    CHECK(avl::is_enabled(avl::mask));
    avl::set(0x0, false);
    CHECK(avl::is_disabled(0x0));

    avl::set_if_exists(true);
    CHECK(avl::is_enabled_if_exists());
    avl::set_if_exists(false);
    CHECK(avl::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ss_access_rights_l")
{
    using namespace vmcs::guest_ss_access_rights;

    l::set(true);
    CHECK(l::is_enabled());
    l::set(false);
    CHECK(l::is_disabled());

    l::set(l::mask, true);
    CHECK(l::is_enabled(l::mask));
    l::set(0x0, false);
    CHECK(l::is_disabled(0x0));

    l::set_if_exists(true);
    CHECK(l::is_enabled_if_exists());
    l::set_if_exists(false);
    CHECK(l::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ss_access_rights_db")
{
    using namespace vmcs::guest_ss_access_rights;

    db::set(true);
    CHECK(db::is_enabled());
    db::set(false);
    CHECK(db::is_disabled());

    db::set(db::mask, true);
    CHECK(db::is_enabled(db::mask));
    db::set(0x0, false);
    CHECK(db::is_disabled(0x0));

    db::set_if_exists(true);
    CHECK(db::is_enabled_if_exists());
    db::set_if_exists(false);
    CHECK(db::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ss_access_rights_granularity")
{
    using namespace vmcs::guest_ss_access_rights;

    granularity::set(true);
    CHECK(granularity::is_enabled());
    granularity::set(false);
    CHECK(granularity::is_disabled());

    granularity::set(granularity::mask, true);
    CHECK(granularity::is_enabled(granularity::mask));
    granularity::set(0x0, false);
    CHECK(granularity::is_disabled(0x0));

    granularity::set_if_exists(true);
    CHECK(granularity::is_enabled_if_exists());
    granularity::set_if_exists(false);
    CHECK(granularity::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ss_access_rights_reserved")
{
    using namespace vmcs::guest_ss_access_rights;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_ss_access_rights_unusable")
{
    using namespace vmcs::guest_ss_access_rights;

    unusable::set(true);
    CHECK(unusable::is_enabled());
    unusable::set(false);
    CHECK(unusable::is_disabled());

    unusable::set(unusable::mask, true);
    CHECK(unusable::is_enabled(unusable::mask));
    unusable::set(0x0, false);
    CHECK(unusable::is_disabled(0x0));

    unusable::set_if_exists(true);
    CHECK(unusable::is_enabled_if_exists());
    unusable::set_if_exists(false);
    CHECK(unusable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ds_access_rights")
{
    using namespace vmcs::guest_ds_access_rights;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ds_access_rights_type")
{
    using namespace vmcs::guest_ds_access_rights;

    type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get() == (type::mask >> type::from));

    type::set(type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get(type::mask) == (type::mask >> type::from));

    type::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get_if_exists() == (type::mask >> type::from));
}

TEST_CASE("vmcs_guest_ds_access_rights_s")
{
    using namespace vmcs::guest_ds_access_rights;

    s::set(true);
    CHECK(s::is_enabled());
    s::set(false);
    CHECK(s::is_disabled());

    s::set(s::mask, true);
    CHECK(s::is_enabled(s::mask));
    s::set(0x0, false);
    CHECK(s::is_disabled(0x0));

    s::set_if_exists(true);
    CHECK(s::is_enabled_if_exists());
    s::set_if_exists(false);
    CHECK(s::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ds_access_rights_dpl")
{
    using namespace vmcs::guest_ds_access_rights;

    dpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get() == (dpl::mask >> dpl::from));

    dpl::set(dpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get(dpl::mask) == (dpl::mask >> dpl::from));

    dpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get_if_exists() == (dpl::mask >> dpl::from));
}

TEST_CASE("vmcs_guest_ds_access_rights_present")
{
    using namespace vmcs::guest_ds_access_rights;

    present::set(true);
    CHECK(present::is_enabled());
    present::set(false);
    CHECK(present::is_disabled());

    present::set(present::mask, true);
    CHECK(present::is_enabled(present::mask));
    present::set(0x0, false);
    CHECK(present::is_disabled(0x0));

    present::set_if_exists(true);
    CHECK(present::is_enabled_if_exists());
    present::set_if_exists(false);
    CHECK(present::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ds_access_rights_avl")
{
    using namespace vmcs::guest_ds_access_rights;

    avl::set(true);
    CHECK(avl::is_enabled());
    avl::set(false);
    CHECK(avl::is_disabled());

    avl::set(avl::mask, true);
    CHECK(avl::is_enabled(avl::mask));
    avl::set(0x0, false);
    CHECK(avl::is_disabled(0x0));

    avl::set_if_exists(true);
    CHECK(avl::is_enabled_if_exists());
    avl::set_if_exists(false);
    CHECK(avl::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ds_access_rights_l")
{
    using namespace vmcs::guest_ds_access_rights;

    l::set(true);
    CHECK(l::is_enabled());
    l::set(false);
    CHECK(l::is_disabled());

    l::set(l::mask, true);
    CHECK(l::is_enabled(l::mask));
    l::set(0x0, false);
    CHECK(l::is_disabled(0x0));

    l::set_if_exists(true);
    CHECK(l::is_enabled_if_exists());
    l::set_if_exists(false);
    CHECK(l::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ds_access_rights_db")
{
    using namespace vmcs::guest_ds_access_rights;

    db::set(true);
    CHECK(db::is_enabled());
    db::set(false);
    CHECK(db::is_disabled());

    db::set(db::mask, true);
    CHECK(db::is_enabled(db::mask));
    db::set(0x0, false);
    CHECK(db::is_disabled(0x0));

    db::set_if_exists(true);
    CHECK(db::is_enabled_if_exists());
    db::set_if_exists(false);
    CHECK(db::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ds_access_rights_granularity")
{
    using namespace vmcs::guest_ds_access_rights;

    granularity::set(true);
    CHECK(granularity::is_enabled());
    granularity::set(false);
    CHECK(granularity::is_disabled());

    granularity::set(granularity::mask, true);
    CHECK(granularity::is_enabled(granularity::mask));
    granularity::set(0x0, false);
    CHECK(granularity::is_disabled(0x0));

    granularity::set_if_exists(true);
    CHECK(granularity::is_enabled_if_exists());
    granularity::set_if_exists(false);
    CHECK(granularity::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ds_access_rights_reserved")
{
    using namespace vmcs::guest_ds_access_rights;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_ds_access_rights_unusable")
{
    using namespace vmcs::guest_ds_access_rights;

    unusable::set(true);
    CHECK(unusable::is_enabled());
    unusable::set(false);
    CHECK(unusable::is_disabled());

    unusable::set(unusable::mask, true);
    CHECK(unusable::is_enabled(unusable::mask));
    unusable::set(0x0, false);
    CHECK(unusable::is_disabled(0x0));

    unusable::set_if_exists(true);
    CHECK(unusable::is_enabled_if_exists());
    unusable::set_if_exists(false);
    CHECK(unusable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_fs_access_rights")
{
    using namespace vmcs::guest_fs_access_rights;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_fs_access_rights_type")
{
    using namespace vmcs::guest_fs_access_rights;

    type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get() == (type::mask >> type::from));

    type::set(type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get(type::mask) == (type::mask >> type::from));

    type::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get_if_exists() == (type::mask >> type::from));
}

TEST_CASE("vmcs_guest_fs_access_rights_s")
{
    using namespace vmcs::guest_fs_access_rights;

    s::set(true);
    CHECK(s::is_enabled());
    s::set(false);
    CHECK(s::is_disabled());

    s::set(s::mask, true);
    CHECK(s::is_enabled(s::mask));
    s::set(0x0, false);
    CHECK(s::is_disabled(0x0));

    s::set_if_exists(true);
    CHECK(s::is_enabled_if_exists());
    s::set_if_exists(false);
    CHECK(s::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_fs_access_rights_dpl")
{
    using namespace vmcs::guest_fs_access_rights;

    dpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get() == (dpl::mask >> dpl::from));

    dpl::set(dpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get(dpl::mask) == (dpl::mask >> dpl::from));

    dpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get_if_exists() == (dpl::mask >> dpl::from));
}

TEST_CASE("vmcs_guest_fs_access_rights_present")
{
    using namespace vmcs::guest_fs_access_rights;

    present::set(true);
    CHECK(present::is_enabled());
    present::set(false);
    CHECK(present::is_disabled());

    present::set(present::mask, true);
    CHECK(present::is_enabled(present::mask));
    present::set(0x0, false);
    CHECK(present::is_disabled(0x0));

    present::set_if_exists(true);
    CHECK(present::is_enabled_if_exists());
    present::set_if_exists(false);
    CHECK(present::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_fs_access_rights_avl")
{
    using namespace vmcs::guest_fs_access_rights;

    avl::set(true);
    CHECK(avl::is_enabled());
    avl::set(false);
    CHECK(avl::is_disabled());

    avl::set(avl::mask, true);
    CHECK(avl::is_enabled(avl::mask));
    avl::set(0x0, false);
    CHECK(avl::is_disabled(0x0));

    avl::set_if_exists(true);
    CHECK(avl::is_enabled_if_exists());
    avl::set_if_exists(false);
    CHECK(avl::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_fs_access_rights_l")
{
    using namespace vmcs::guest_fs_access_rights;

    l::set(true);
    CHECK(l::is_enabled());
    l::set(false);
    CHECK(l::is_disabled());

    l::set(l::mask, true);
    CHECK(l::is_enabled(l::mask));
    l::set(0x0, false);
    CHECK(l::is_disabled(0x0));

    l::set_if_exists(true);
    CHECK(l::is_enabled_if_exists());
    l::set_if_exists(false);
    CHECK(l::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_fs_access_rights_db")
{
    using namespace vmcs::guest_fs_access_rights;

    db::set(true);
    CHECK(db::is_enabled());
    db::set(false);
    CHECK(db::is_disabled());

    db::set(db::mask, true);
    CHECK(db::is_enabled(db::mask));
    db::set(0x0, false);
    CHECK(db::is_disabled(0x0));

    db::set_if_exists(true);
    CHECK(db::is_enabled_if_exists());
    db::set_if_exists(false);
    CHECK(db::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_fs_access_rights_granularity")
{
    using namespace vmcs::guest_fs_access_rights;

    granularity::set(true);
    CHECK(granularity::is_enabled());
    granularity::set(false);
    CHECK(granularity::is_disabled());

    granularity::set(granularity::mask, true);
    CHECK(granularity::is_enabled(granularity::mask));
    granularity::set(0x0, false);
    CHECK(granularity::is_disabled(0x0));

    granularity::set_if_exists(true);
    CHECK(granularity::is_enabled_if_exists());
    granularity::set_if_exists(false);
    CHECK(granularity::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_fs_access_rights_reserved")
{
    using namespace vmcs::guest_fs_access_rights;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_fs_access_rights_unusable")
{
    using namespace vmcs::guest_fs_access_rights;

    unusable::set(true);
    CHECK(unusable::is_enabled());
    unusable::set(false);
    CHECK(unusable::is_disabled());

    unusable::set(unusable::mask, true);
    CHECK(unusable::is_enabled(unusable::mask));
    unusable::set(0x0, false);
    CHECK(unusable::is_disabled(0x0));

    unusable::set_if_exists(true);
    CHECK(unusable::is_enabled_if_exists());
    unusable::set_if_exists(false);
    CHECK(unusable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_gs_access_rights")
{
    using namespace vmcs::guest_gs_access_rights;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_gs_access_rights_type")
{
    using namespace vmcs::guest_gs_access_rights;

    type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get() == (type::mask >> type::from));

    type::set(type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get(type::mask) == (type::mask >> type::from));

    type::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get_if_exists() == (type::mask >> type::from));
}

TEST_CASE("vmcs_guest_gs_access_rights_s")
{
    using namespace vmcs::guest_gs_access_rights;

    s::set(true);
    CHECK(s::is_enabled());
    s::set(false);
    CHECK(s::is_disabled());

    s::set(s::mask, true);
    CHECK(s::is_enabled(s::mask));
    s::set(0x0, false);
    CHECK(s::is_disabled(0x0));

    s::set_if_exists(true);
    CHECK(s::is_enabled_if_exists());
    s::set_if_exists(false);
    CHECK(s::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_gs_access_rights_dpl")
{
    using namespace vmcs::guest_gs_access_rights;

    dpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get() == (dpl::mask >> dpl::from));

    dpl::set(dpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get(dpl::mask) == (dpl::mask >> dpl::from));

    dpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get_if_exists() == (dpl::mask >> dpl::from));
}

TEST_CASE("vmcs_guest_gs_access_rights_present")
{
    using namespace vmcs::guest_gs_access_rights;

    present::set(true);
    CHECK(present::is_enabled());
    present::set(false);
    CHECK(present::is_disabled());

    present::set(present::mask, true);
    CHECK(present::is_enabled(present::mask));
    present::set(0x0, false);
    CHECK(present::is_disabled(0x0));

    present::set_if_exists(true);
    CHECK(present::is_enabled_if_exists());
    present::set_if_exists(false);
    CHECK(present::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_gs_access_rights_avl")
{
    using namespace vmcs::guest_gs_access_rights;

    avl::set(true);
    CHECK(avl::is_enabled());
    avl::set(false);
    CHECK(avl::is_disabled());

    avl::set(avl::mask, true);
    CHECK(avl::is_enabled(avl::mask));
    avl::set(0x0, false);
    CHECK(avl::is_disabled(0x0));

    avl::set_if_exists(true);
    CHECK(avl::is_enabled_if_exists());
    avl::set_if_exists(false);
    CHECK(avl::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_gs_access_rights_l")
{
    using namespace vmcs::guest_gs_access_rights;

    l::set(true);
    CHECK(l::is_enabled());
    l::set(false);
    CHECK(l::is_disabled());

    l::set(l::mask, true);
    CHECK(l::is_enabled(l::mask));
    l::set(0x0, false);
    CHECK(l::is_disabled(0x0));

    l::set_if_exists(true);
    CHECK(l::is_enabled_if_exists());
    l::set_if_exists(false);
    CHECK(l::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_gs_access_rights_db")
{
    using namespace vmcs::guest_gs_access_rights;

    db::set(true);
    CHECK(db::is_enabled());
    db::set(false);
    CHECK(db::is_disabled());

    db::set(db::mask, true);
    CHECK(db::is_enabled(db::mask));
    db::set(0x0, false);
    CHECK(db::is_disabled(0x0));

    db::set_if_exists(true);
    CHECK(db::is_enabled_if_exists());
    db::set_if_exists(false);
    CHECK(db::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_gs_access_rights_granularity")
{
    using namespace vmcs::guest_gs_access_rights;

    granularity::set(true);
    CHECK(granularity::is_enabled());
    granularity::set(false);
    CHECK(granularity::is_disabled());

    granularity::set(granularity::mask, true);
    CHECK(granularity::is_enabled(granularity::mask));
    granularity::set(0x0, false);
    CHECK(granularity::is_disabled(0x0));

    granularity::set_if_exists(true);
    CHECK(granularity::is_enabled_if_exists());
    granularity::set_if_exists(false);
    CHECK(granularity::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_gs_access_rights_reserved")
{
    using namespace vmcs::guest_gs_access_rights;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_gs_access_rights_unusable")
{
    using namespace vmcs::guest_gs_access_rights;

    unusable::set(true);
    CHECK(unusable::is_enabled());
    unusable::set(false);
    CHECK(unusable::is_disabled());

    unusable::set(unusable::mask, true);
    CHECK(unusable::is_enabled(unusable::mask));
    unusable::set(0x0, false);
    CHECK(unusable::is_disabled(0x0));

    unusable::set_if_exists(true);
    CHECK(unusable::is_enabled_if_exists());
    unusable::set_if_exists(false);
    CHECK(unusable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ldtr_access_rights")
{
    using namespace vmcs::guest_ldtr_access_rights;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_type")
{
    using namespace vmcs::guest_ldtr_access_rights;

    type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get() == (type::mask >> type::from));

    type::set(type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get(type::mask) == (type::mask >> type::from));

    type::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get_if_exists() == (type::mask >> type::from));
}

TEST_CASE("vmcs_guest_ldtr_access_rights_s")
{
    using namespace vmcs::guest_ldtr_access_rights;

    s::set(true);
    CHECK(s::is_enabled());
    s::set(false);
    CHECK(s::is_disabled());

    s::set(s::mask, true);
    CHECK(s::is_enabled(s::mask));
    s::set(0x0, false);
    CHECK(s::is_disabled(0x0));

    s::set_if_exists(true);
    CHECK(s::is_enabled_if_exists());
    s::set_if_exists(false);
    CHECK(s::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ldtr_access_rights_dpl")
{
    using namespace vmcs::guest_ldtr_access_rights;

    dpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get() == (dpl::mask >> dpl::from));

    dpl::set(dpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get(dpl::mask) == (dpl::mask >> dpl::from));

    dpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get_if_exists() == (dpl::mask >> dpl::from));
}

TEST_CASE("vmcs_guest_ldtr_access_rights_present")
{
    using namespace vmcs::guest_ldtr_access_rights;

    present::set(true);
    CHECK(present::is_enabled());
    present::set(false);
    CHECK(present::is_disabled());

    present::set(present::mask, true);
    CHECK(present::is_enabled(present::mask));
    present::set(0x0, false);
    CHECK(present::is_disabled(0x0));

    present::set_if_exists(true);
    CHECK(present::is_enabled_if_exists());
    present::set_if_exists(false);
    CHECK(present::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ldtr_access_rights_avl")
{
    using namespace vmcs::guest_ldtr_access_rights;

    avl::set(true);
    CHECK(avl::is_enabled());
    avl::set(false);
    CHECK(avl::is_disabled());

    avl::set(avl::mask, true);
    CHECK(avl::is_enabled(avl::mask));
    avl::set(0x0, false);
    CHECK(avl::is_disabled(0x0));

    avl::set_if_exists(true);
    CHECK(avl::is_enabled_if_exists());
    avl::set_if_exists(false);
    CHECK(avl::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ldtr_access_rights_l")
{
    using namespace vmcs::guest_ldtr_access_rights;

    l::set(true);
    CHECK(l::is_enabled());
    l::set(false);
    CHECK(l::is_disabled());

    l::set(l::mask, true);
    CHECK(l::is_enabled(l::mask));
    l::set(0x0, false);
    CHECK(l::is_disabled(0x0));

    l::set_if_exists(true);
    CHECK(l::is_enabled_if_exists());
    l::set_if_exists(false);
    CHECK(l::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ldtr_access_rights_db")
{
    using namespace vmcs::guest_ldtr_access_rights;

    db::set(true);
    CHECK(db::is_enabled());
    db::set(false);
    CHECK(db::is_disabled());

    db::set(db::mask, true);
    CHECK(db::is_enabled(db::mask));
    db::set(0x0, false);
    CHECK(db::is_disabled(0x0));

    db::set_if_exists(true);
    CHECK(db::is_enabled_if_exists());
    db::set_if_exists(false);
    CHECK(db::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ldtr_access_rights_granularity")
{
    using namespace vmcs::guest_ldtr_access_rights;

    granularity::set(true);
    CHECK(granularity::is_enabled());
    granularity::set(false);
    CHECK(granularity::is_disabled());

    granularity::set(granularity::mask, true);
    CHECK(granularity::is_enabled(granularity::mask));
    granularity::set(0x0, false);
    CHECK(granularity::is_disabled(0x0));

    granularity::set_if_exists(true);
    CHECK(granularity::is_enabled_if_exists());
    granularity::set_if_exists(false);
    CHECK(granularity::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_ldtr_access_rights_reserved")
{
    using namespace vmcs::guest_ldtr_access_rights;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_ldtr_access_rights_unusable")
{
    using namespace vmcs::guest_ldtr_access_rights;

    unusable::set(true);
    CHECK(unusable::is_enabled());
    unusable::set(false);
    CHECK(unusable::is_disabled());

    unusable::set(unusable::mask, true);
    CHECK(unusable::is_enabled(unusable::mask));
    unusable::set(0x0, false);
    CHECK(unusable::is_disabled(0x0));

    unusable::set_if_exists(true);
    CHECK(unusable::is_enabled_if_exists());
    unusable::set_if_exists(false);
    CHECK(unusable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_tr_access_rights")
{
    using namespace vmcs::guest_tr_access_rights;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_tr_access_rights_type")
{
    using namespace vmcs::guest_tr_access_rights;

    type::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get() == (type::mask >> type::from));

    type::set(type::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get(type::mask) == (type::mask >> type::from));

    type::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(type::get_if_exists() == (type::mask >> type::from));
}

TEST_CASE("vmcs_guest_tr_access_rights_s")
{
    using namespace vmcs::guest_tr_access_rights;

    s::set(true);
    CHECK(s::is_enabled());
    s::set(false);
    CHECK(s::is_disabled());

    s::set(s::mask, true);
    CHECK(s::is_enabled(s::mask));
    s::set(0x0, false);
    CHECK(s::is_disabled(0x0));

    s::set_if_exists(true);
    CHECK(s::is_enabled_if_exists());
    s::set_if_exists(false);
    CHECK(s::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_tr_access_rights_dpl")
{
    using namespace vmcs::guest_tr_access_rights;

    dpl::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get() == (dpl::mask >> dpl::from));

    dpl::set(dpl::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get(dpl::mask) == (dpl::mask >> dpl::from));

    dpl::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(dpl::get_if_exists() == (dpl::mask >> dpl::from));
}

TEST_CASE("vmcs_guest_tr_access_rights_present")
{
    using namespace vmcs::guest_tr_access_rights;

    present::set(true);
    CHECK(present::is_enabled());
    present::set(false);
    CHECK(present::is_disabled());

    present::set(present::mask, true);
    CHECK(present::is_enabled(present::mask));
    present::set(0x0, false);
    CHECK(present::is_disabled(0x0));

    present::set_if_exists(true);
    CHECK(present::is_enabled_if_exists());
    present::set_if_exists(false);
    CHECK(present::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_tr_access_rights_avl")
{
    using namespace vmcs::guest_tr_access_rights;

    avl::set(true);
    CHECK(avl::is_enabled());
    avl::set(false);
    CHECK(avl::is_disabled());

    avl::set(avl::mask, true);
    CHECK(avl::is_enabled(avl::mask));
    avl::set(0x0, false);
    CHECK(avl::is_disabled(0x0));

    avl::set_if_exists(true);
    CHECK(avl::is_enabled_if_exists());
    avl::set_if_exists(false);
    CHECK(avl::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_tr_access_rights_l")
{
    using namespace vmcs::guest_tr_access_rights;

    l::set(true);
    CHECK(l::is_enabled());
    l::set(false);
    CHECK(l::is_disabled());

    l::set(l::mask, true);
    CHECK(l::is_enabled(l::mask));
    l::set(0x0, false);
    CHECK(l::is_disabled(0x0));

    l::set_if_exists(true);
    CHECK(l::is_enabled_if_exists());
    l::set_if_exists(false);
    CHECK(l::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_tr_access_rights_db")
{
    using namespace vmcs::guest_tr_access_rights;

    db::set(true);
    CHECK(db::is_enabled());
    db::set(false);
    CHECK(db::is_disabled());

    db::set(db::mask, true);
    CHECK(db::is_enabled(db::mask));
    db::set(0x0, false);
    CHECK(db::is_disabled(0x0));

    db::set_if_exists(true);
    CHECK(db::is_enabled_if_exists());
    db::set_if_exists(false);
    CHECK(db::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_tr_access_rights_granularity")
{
    using namespace vmcs::guest_tr_access_rights;

    granularity::set(true);
    CHECK(granularity::is_enabled());
    granularity::set(false);
    CHECK(granularity::is_disabled());

    granularity::set(granularity::mask, true);
    CHECK(granularity::is_enabled(granularity::mask));
    granularity::set(0x0, false);
    CHECK(granularity::is_disabled(0x0));

    granularity::set_if_exists(true);
    CHECK(granularity::is_enabled_if_exists());
    granularity::set_if_exists(false);
    CHECK(granularity::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_tr_access_rights_reserved")
{
    using namespace vmcs::guest_tr_access_rights;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_tr_access_rights_unusable")
{
    using namespace vmcs::guest_tr_access_rights;

    unusable::set(true);
    CHECK(unusable::is_enabled());
    unusable::set(false);
    CHECK(unusable::is_disabled());

    unusable::set(unusable::mask, true);
    CHECK(unusable::is_enabled(unusable::mask));
    unusable::set(0x0, false);
    CHECK(unusable::is_disabled(0x0));

    unusable::set_if_exists(true);
    CHECK(unusable::is_enabled_if_exists());
    unusable::set_if_exists(false);
    CHECK(unusable::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_interruptibility_state")
{
    using namespace vmcs::guest_interruptibility_state;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_interruptibility_state_blocking_by_sti")
{
    using namespace vmcs::guest_interruptibility_state;

    blocking_by_sti::set(true);
    CHECK(blocking_by_sti::is_enabled());
    blocking_by_sti::set(false);
    CHECK(blocking_by_sti::is_disabled());

    blocking_by_sti::set(blocking_by_sti::mask, true);
    CHECK(blocking_by_sti::is_enabled(blocking_by_sti::mask));
    blocking_by_sti::set(0x0, false);
    CHECK(blocking_by_sti::is_disabled(0x0));

    blocking_by_sti::set_if_exists(true);
    CHECK(blocking_by_sti::is_enabled_if_exists());
    blocking_by_sti::set_if_exists(false);
    CHECK(blocking_by_sti::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_interruptibility_state_blocking_by_mov_ss")
{
    using namespace vmcs::guest_interruptibility_state;

    blocking_by_mov_ss::set(true);
    CHECK(blocking_by_mov_ss::is_enabled());
    blocking_by_mov_ss::set(false);
    CHECK(blocking_by_mov_ss::is_disabled());

    blocking_by_mov_ss::set(blocking_by_mov_ss::mask, true);
    CHECK(blocking_by_mov_ss::is_enabled(blocking_by_mov_ss::mask));
    blocking_by_mov_ss::set(0x0, false);
    CHECK(blocking_by_mov_ss::is_disabled(0x0));

    blocking_by_mov_ss::set_if_exists(true);
    CHECK(blocking_by_mov_ss::is_enabled_if_exists());
    blocking_by_mov_ss::set_if_exists(false);
    CHECK(blocking_by_mov_ss::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_interruptibility_state_blocking_by_smi")
{
    using namespace vmcs::guest_interruptibility_state;

    blocking_by_smi::set(true);
    CHECK(blocking_by_smi::is_enabled());
    blocking_by_smi::set(false);
    CHECK(blocking_by_smi::is_disabled());

    blocking_by_smi::set(blocking_by_smi::mask, true);
    CHECK(blocking_by_smi::is_enabled(blocking_by_smi::mask));
    blocking_by_smi::set(0x0, false);
    CHECK(blocking_by_smi::is_disabled(0x0));

    blocking_by_smi::set_if_exists(true);
    CHECK(blocking_by_smi::is_enabled_if_exists());
    blocking_by_smi::set_if_exists(false);
    CHECK(blocking_by_smi::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_interruptibility_state_blocking_by_nmi")
{
    using namespace vmcs::guest_interruptibility_state;

    blocking_by_nmi::set(true);
    CHECK(blocking_by_nmi::is_enabled());
    blocking_by_nmi::set(false);
    CHECK(blocking_by_nmi::is_disabled());

    blocking_by_nmi::set(blocking_by_nmi::mask, true);
    CHECK(blocking_by_nmi::is_enabled(blocking_by_nmi::mask));
    blocking_by_nmi::set(0x0, false);
    CHECK(blocking_by_nmi::is_disabled(0x0));

    blocking_by_nmi::set_if_exists(true);
    CHECK(blocking_by_nmi::is_enabled_if_exists());
    blocking_by_nmi::set_if_exists(false);
    CHECK(blocking_by_nmi::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_interruptibility_state_enclave_interruption")
{
    using namespace vmcs::guest_interruptibility_state;

    enclave_interruption::set(true);
    CHECK(enclave_interruption::is_enabled());
    enclave_interruption::set(false);
    CHECK(enclave_interruption::is_disabled());

    enclave_interruption::set(enclave_interruption::mask, true);
    CHECK(enclave_interruption::is_enabled(enclave_interruption::mask));
    enclave_interruption::set(0x0, false);
    CHECK(enclave_interruption::is_disabled(0x0));

    enclave_interruption::set_if_exists(true);
    CHECK(enclave_interruption::is_enabled_if_exists());
    enclave_interruption::set_if_exists(false);
    CHECK(enclave_interruption::is_disabled_if_exists());
}

TEST_CASE("vmcs_guest_interruptibility_state_reserved")
{
    using namespace vmcs::guest_interruptibility_state;

    reserved::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get() == (reserved::mask >> reserved::from));

    reserved::set(reserved::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get(reserved::mask) == (reserved::mask >> reserved::from));

    reserved::set_if_exists(0xFFFFFFFFFFFFFFFFULL);
    CHECK(reserved::get_if_exists() == (reserved::mask >> reserved::from));
}

TEST_CASE("vmcs_guest_activity_state")
{
    using namespace vmcs::guest_activity_state;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_smbase")
{
    using namespace vmcs::guest_smbase;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_guest_ia32_sysenter_cs")
{
    using namespace vmcs::guest_ia32_sysenter_cs;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_vmx_preemption_timer_value")
{
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] =
        msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::mask << 32;

    using namespace vmcs::vmx_preemption_timer_value;

    set(100UL);
    CHECK(get() == 100UL);
    CHECK(exists());

    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}
