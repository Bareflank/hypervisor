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

#include <catch/catch.hpp>

#include <map>
#include <intrinsics.h>

using namespace intel_x64;
using namespace msrs;
using namespace vmcs;
using namespace debug;

std::map<uint32_t, uint64_t> g_msrs;
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

TEST_CASE("get_vmcs_field")
{
    constexpr const auto name = "field";

    CHECK_THROWS(get_vmcs_field(0ULL, name, false));

    g_vmcs_fields[0UL] = 42UL;
    CHECK(get_vmcs_field(0ULL, name, true) == 42UL);
}

TEST_CASE("get_vmcs_field_if_exists")
{
    constexpr const auto name = "field";

    g_vmcs_fields[0UL] = 42UL;

    CHECK(get_vmcs_field_if_exists(0ULL, name, true, false) == 0UL);
    CHECK(get_vmcs_field_if_exists(0ULL, name, true, true) == 42UL);
}

TEST_CASE("set_vmcs_field")
{
    constexpr const auto name("field");
    g_vmcs_fields[0UL] = 0UL;

    CHECK_THROWS(set_vmcs_field(1ULL, 0ULL, name, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);

    CHECK_NOTHROW(set_vmcs_field(1ULL, 0ULL, name, true));
    CHECK(g_vmcs_fields[0UL] == 1UL);
}

TEST_CASE("set_vmcs_field_if_exists")
{
    constexpr const auto name("field");
    g_vmcs_fields[0UL] = 42UL;

    CHECK_NOTHROW(set_vmcs_field_if_exists(0ULL, 0ULL, name, false, false));
    CHECK(g_vmcs_fields[0UL] == 42UL);

    CHECK_NOTHROW(set_vmcs_field_if_exists(0ULL, 0ULL, name, true, false));
    CHECK(g_vmcs_fields[0UL] == 42UL);

    CHECK_NOTHROW(set_vmcs_field_if_exists(0ULL, 0ULL, name, false, true));
    CHECK(g_vmcs_fields[0UL] == 0U);

    CHECK_NOTHROW(set_vmcs_field_if_exists(1ULL, 0ULL, name, true, true));
    CHECK(g_vmcs_fields[0UL] == 1UL);
}

TEST_CASE("set_vmcs_field_bits")
{
    constexpr const auto name("field");
    g_vmcs_fields[0UL] = 0UL;

    CHECK_THROWS(set_vmcs_field_bits(0xFFFFFFFFULL, 0ULL, 0x00000080ULL, 3ULL, name, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);

    CHECK_NOTHROW(set_vmcs_field_bits(0xFFFFFFFFULL, 0ULL, 0x00000008ULL, 3ULL, name, true));
    CHECK(g_vmcs_fields[0UL] == 8UL);
}

TEST_CASE("set_vmcs_field_bits_if_exists")
{
    constexpr const auto name("field");
    g_vmcs_fields[0UL] = 0UL;

    CHECK_NOTHROW(set_vmcs_field_bits_if_exists(0xFFFFFFFFULL, 0ULL,
                  0x00000008ULL, 3ULL, name, false, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);

    CHECK_NOTHROW(set_vmcs_field_bits_if_exists(0xFFFFFFFFULL, 0ULL,
                  0x00000008ULL, 3ULL, name, true, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);

    CHECK_NOTHROW(set_vmcs_field_bits_if_exists(0xFFFFFFFFULL, 0ULL,
                  0x00000008ULL, 3ULL, name, false, true));
    CHECK(g_vmcs_fields[0UL] == 8UL);

    g_vmcs_fields[0UL] = 0UL;

    CHECK_NOTHROW(set_vmcs_field_bits_if_exists(0xFFFFFFFFULL, 0ULL,
                  0x00000008ULL, 3ULL, name, true, true));
    CHECK(g_vmcs_fields[0UL] == 8UL);
}

TEST_CASE("clear_vmcs_field_bit")
{
    constexpr const auto name("field");
    g_vmcs_fields[0UL] = 8UL;

    CHECK_THROWS(clear_vmcs_field_bit(0ULL, 3ULL, name, false));
    CHECK(g_vmcs_fields[0UL] == 8UL);

    CHECK_NOTHROW(clear_vmcs_field_bit(0ULL, 3ULL, name, true));
    CHECK(g_vmcs_fields[0UL] == 0UL);
}

TEST_CASE("clear_vmcs_field_bit_if_exists")
{
    constexpr const auto name("field");
    g_vmcs_fields[0UL] = 8UL;

    CHECK_NOTHROW(clear_vmcs_field_bit_if_exists(0ULL, 3ULL, name, false, false));
    CHECK(g_vmcs_fields[0UL] == 8UL);

    CHECK_NOTHROW(clear_vmcs_field_bit_if_exists(0ULL, 3ULL, name, true, false));
    CHECK(g_vmcs_fields[0UL] == 8UL);

    CHECK_NOTHROW(clear_vmcs_field_bit_if_exists(0ULL, 3ULL, name, false, true));
    CHECK(g_vmcs_fields[0UL] == 0UL);

    g_vmcs_fields[0UL] = 8UL;

    CHECK_NOTHROW(clear_vmcs_field_bit_if_exists(0ULL, 3ULL, name, true, true));
    CHECK(g_vmcs_fields[0UL] == 0UL);
}

TEST_CASE("enable_vm_control")
{
    constexpr const auto name = "control";
    g_vmcs_fields[0UL] = 0UL;

    CHECK_THROWS(enable_vm_control(0ULL, 3ULL, false, name, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);
    CHECK_THROWS(enable_vm_control(0ULL, 3ULL, true, name, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);
    CHECK_THROWS(enable_vm_control(0ULL, 3ULL, false, name, true));
    CHECK(g_vmcs_fields[0UL] == 0UL);

    CHECK_NOTHROW(enable_vm_control(0ULL, 3ULL, true, name, true));
    CHECK(g_vmcs_fields[0UL] == 8UL);
}

TEST_CASE("enable_vm_control_if_allowed")
{
    constexpr const auto name = "control";
    g_vmcs_fields[0UL] = 0UL;

    CHECK_NOTHROW(enable_vm_control_if_allowed(0ULL, 3ULL, false, name, false, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);
    CHECK_NOTHROW(enable_vm_control_if_allowed(0ULL, 3ULL, false, name, true, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);

    CHECK_NOTHROW(enable_vm_control_if_allowed(0ULL, 3ULL, false, name, false, true));
    CHECK(g_vmcs_fields[0UL] == 0UL);
    CHECK_NOTHROW(enable_vm_control_if_allowed(0ULL, 3ULL, false, name, true, true));
    CHECK(g_vmcs_fields[0UL] == 0UL);

    CHECK_NOTHROW(enable_vm_control_if_allowed(0ULL, 3ULL, true, name, false, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);
    CHECK_NOTHROW(enable_vm_control_if_allowed(0ULL, 3ULL, true, name, true, false));
    CHECK(g_vmcs_fields[0UL] == 0UL);

    CHECK_NOTHROW(enable_vm_control_if_allowed(0ULL, 3ULL, true, name, false, true));
    CHECK(g_vmcs_fields[0UL] == 8UL);
    CHECK_NOTHROW(enable_vm_control_if_allowed(0ULL, 3ULL, true, name, true, true));
    CHECK(g_vmcs_fields[0UL] == 8UL);
}

TEST_CASE("disable_vm_control")
{
    constexpr const auto name = "control";
    g_vmcs_fields[0UL] = 8UL;

    CHECK_THROWS(disable_vm_control(0ULL, 3ULL, false, name, false));
    CHECK(g_vmcs_fields[0UL] == 8UL);
    CHECK_THROWS(disable_vm_control(0ULL, 3ULL, false, name, true));
    CHECK(g_vmcs_fields[0UL] == 8UL);
    CHECK_THROWS(disable_vm_control(0ULL, 3ULL, true, name, false));
    CHECK(g_vmcs_fields[0UL] == 8UL);

    CHECK_NOTHROW(disable_vm_control(0ULL, 3ULL, true, name, true));
    CHECK(g_vmcs_fields[0UL] == 0UL);
}

TEST_CASE("disable_vm_control_if_allowed")
{
    constexpr const auto name = "control";
    g_vmcs_fields[0UL] = 8UL;

    CHECK_NOTHROW(disable_vm_control_if_allowed(0ULL, 3ULL, false, name, false, false));
    CHECK(g_vmcs_fields[0UL] == 8UL);
    CHECK_NOTHROW(disable_vm_control_if_allowed(0ULL, 3ULL, false, name, true, false));
    CHECK(g_vmcs_fields[0UL] == 8UL);

    CHECK_NOTHROW(disable_vm_control_if_allowed(0ULL, 3ULL, false, name, false, true));
    CHECK(g_vmcs_fields[0UL] == 8UL);
    CHECK_NOTHROW(disable_vm_control_if_allowed(0ULL, 3ULL, false, name, true, true));
    CHECK(g_vmcs_fields[0UL] == 8UL);

    CHECK_NOTHROW(disable_vm_control_if_allowed(0ULL, 3ULL, true, name, false, false));
    CHECK(g_vmcs_fields[0UL] == 8UL);
    CHECK_NOTHROW(disable_vm_control_if_allowed(0ULL, 3ULL, true, name, true, false));
    CHECK(g_vmcs_fields[0UL] == 8UL);

    CHECK_NOTHROW(disable_vm_control_if_allowed(0ULL, 3ULL, true, name, false, true));
    CHECK(g_vmcs_fields[0UL] == 0UL);
    CHECK_NOTHROW(disable_vm_control_if_allowed(0ULL, 3ULL, true, name, true, true));
    CHECK(g_vmcs_fields[0UL] == 0UL);
}

TEST_CASE("dump_vm_control")
{
    constexpr const auto name = "dump";
    std::string msg = "dump";

    CHECK_NOTHROW(dump_vm_control(0, false, false, false, name, &msg));
    CHECK_NOTHROW(dump_vm_control(0, false, true, false, name, &msg));
    CHECK_NOTHROW(dump_vm_control(0, true, false, false, name, &msg));
    CHECK_NOTHROW(dump_vm_control(0, true, true, false, name, &msg));
}

TEST_CASE("memory_type_reserved")
{
    CHECK_FALSE(memory_type_reserved(0x00000000ULL));
    CHECK_FALSE(memory_type_reserved(0x00000001ULL));
    CHECK_FALSE(memory_type_reserved(0x00000004ULL));
    CHECK_FALSE(memory_type_reserved(0x00000005ULL));
    CHECK_FALSE(memory_type_reserved(0x00000006ULL));
    CHECK_FALSE(memory_type_reserved(0x00000007ULL));

    CHECK(memory_type_reserved(0x00000008ULL));
}
