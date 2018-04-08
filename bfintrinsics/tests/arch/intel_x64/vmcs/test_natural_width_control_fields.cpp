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
#include <arch/intel_x64/vmcs/natural_width_control_fields.h>

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

TEST_CASE("vmcs_cr0_guest_host_mask")
{
    using namespace vmcs::cr0_guest_host_mask;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr4_guest_host_mask")
{
    using namespace vmcs::cr4_guest_host_mask;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr0_read_shadow")
{
    using namespace vmcs::cr0_read_shadow;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr4_read_shadow")
{
    using namespace vmcs::cr4_read_shadow;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr3_target_value_0")
{
    using namespace vmcs::cr3_target_value_0;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr3_target_value_1")
{
    using namespace vmcs::cr3_target_value_1;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr3_target_value_2")
{
    using namespace vmcs::cr3_target_value_2;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}

TEST_CASE("vmcs_cr3_target_value_3")
{
    using namespace vmcs::cr3_target_value_3;

    CHECK(exists());
    set(100UL);
    CHECK(get() == 100UL);
    set_if_exists(200UL);
    CHECK(get_if_exists() == 200UL);

    dump(0);
}
