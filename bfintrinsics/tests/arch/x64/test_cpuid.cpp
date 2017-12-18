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

using namespace x64;

std::map<cpuid::field_type, cpuid::value_type> g_eax_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_ebx_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_ecx_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_edx_cpuid;

extern "C" uint32_t
_cpuid_eax(uint32_t val) noexcept
{ return g_eax_cpuid[val]; }

extern "C" uint32_t
_cpuid_ebx(uint32_t val) noexcept
{ return g_ebx_cpuid[val]; }

extern "C" uint32_t
_cpuid_ecx(uint32_t val) noexcept
{ return g_ecx_cpuid[val]; }

extern "C" uint32_t
_cpuid_edx(uint32_t val) noexcept
{ return g_edx_cpuid[val]; }

TEST_CASE("intrinsics: cpuid_addr_size")
{
    using namespace cpuid::addr_size;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(get() == 0xFFFFFFFF);
    dump(0);
}

TEST_CASE("intrinsics: cpuid_addr_size_phys")
{
    using namespace cpuid::addr_size;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(phys::get() == (phys::mask >> phys::from));
    CHECK(phys::get(phys::mask) == (phys::mask >> phys::from));
}

TEST_CASE("intrinsics: cpuid_addr_size_linear")
{
    using namespace cpuid::addr_size;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(linear::get() == (linear::mask >> linear::from));
    CHECK(linear::get(linear::mask) == (linear::mask >> linear::from));
}

TEST_CASE("intrinsics: cpuid_basic_cpuid_info_eax")
{
    using namespace cpuid::basic_cpuid_info;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
    dump(0);
}

TEST_CASE("intrinsics: cpuid_extend_cpuid_info_eax")
{
    using namespace cpuid::extend_cpuid_info;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
    dump(0);
}

TEST_CASE("intrinsics: cpuid_processor_string_1")
{
    using namespace cpuid::processor_string_1;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_eax")
{
    using namespace cpuid::processor_string_1;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_ebx")
{
    using namespace cpuid::processor_string_1;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_ecx")
{
    using namespace cpuid::processor_string_1;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_edx")
{
    using namespace cpuid::processor_string_1;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2")
{
    using namespace cpuid::processor_string_2;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_eax")
{
    using namespace cpuid::processor_string_2;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_ebx")
{
    using namespace cpuid::processor_string_2;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_ecx")
{
    using namespace cpuid::processor_string_2;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_edx")
{
    using namespace cpuid::processor_string_2;
    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3")
{
    using namespace cpuid::processor_string_3;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_eax")
{
    using namespace cpuid::processor_string_3;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_ebx")
{
    using namespace cpuid::processor_string_3;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_ecx")
{
    using namespace cpuid::processor_string_3;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_edx")
{
    using namespace cpuid::processor_string_3;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::get() == 0xFFFFFFFFULL);
}
