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
#include <intrinsics/x86/common_x64.h>
#include <intrinsics/x86/intel_x64.h>
#include <map>
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

std::map<cpuid::field_type, cpuid::value_type> g_eax_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_ebx_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_ecx_cpuid;
std::map<cpuid::field_type, cpuid::value_type> g_edx_cpuid;

extern "C" uint32_t _cpuid_eax(uint32_t val) noexcept;
extern "C" uint32_t _cpuid_ebx(uint32_t val) noexcept;
extern "C" uint32_t _cpuid_ecx(uint32_t val) noexcept;
extern "C" uint32_t _cpuid_edx(uint32_t val) noexcept;
extern "C" void _cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept;

struct cpuid_regs {
    cpuid::value_type eax;
    cpuid::value_type ebx;
    cpuid::value_type ecx;
    cpuid::value_type edx;
};

struct cpuid_regs g_regs;

extern "C" uint32_t
test_cpuid_eax(uint32_t val) noexcept
{ return g_eax_cpuid[val]; }
extern "C" uint32_t
test_cpuid_ebx(uint32_t val) noexcept
{ return g_ebx_cpuid[val]; }

extern "C" uint32_t
test_cpuid_ecx(uint32_t val) noexcept
{ return g_ecx_cpuid[val]; }

extern "C" uint32_t
test_cpuid_edx(uint32_t val) noexcept
{ return g_edx_cpuid[val]; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_cpuid_eax).Do(test_cpuid_eax);
    mocks.OnCallFunc(_cpuid_ebx).Do(test_cpuid_ebx);
    mocks.OnCallFunc(_cpuid_ecx).Do(test_cpuid_ecx);
    mocks.OnCallFunc(_cpuid_edx).Do(test_cpuid_edx);
}

TEST_CASE("intrinsics: cpuid_addr_size")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::addr_size;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(get() == 0xFFFFFFFF);
    dump(0);
}

TEST_CASE("intrinsics: cpuid_addr_size_phys")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::addr_size;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(phys::get() == (phys::mask >> phys::from));
    CHECK(phys::get(phys::mask) == (phys::mask >> phys::from));
}

TEST_CASE("intrinsics: cpuid_addr_size_linear")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::addr_size;

    g_eax_cpuid[addr] = 0xFFFFFFFF;
    CHECK(linear::get() == (linear::mask >> linear::from));
    CHECK(linear::get(linear::mask) == (linear::mask >> linear::from));
}

TEST_CASE("intrinsics: cpuid_basic_cpuid_info_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::basic_cpuid_info;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
    dump(0);
}

TEST_CASE("intrinsics: cpuid_extend_cpuid_info_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::extend_cpuid_info;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
    dump(0);
}

TEST_CASE("intrinsics: cpuid_processor_string_1")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_1;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_1;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_1;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_1;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_1_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_1;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_2;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_2;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_2;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_2;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_2_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_2;
    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_3;

    dump(0);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_eax")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_3;

    g_eax_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(eax::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_ebx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_3;

    g_ebx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ebx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_ecx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_3;

    g_ecx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(ecx::get() == 0xFFFFFFFFULL);
}

TEST_CASE("intrinsics: cpuid_processor_string_3_edx")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace cpuid::processor_string_3;

    g_edx_cpuid[addr] = 0xFFFFFFFFULL;
    CHECK(edx::get() == 0xFFFFFFFFULL);
}

#endif
