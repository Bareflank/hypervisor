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
#include <hippomocks.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;

TEST_CASE("test name goes here")
{
    CHECK(true);
}

std::map<msrs::field_type, msrs::value_type> g_msrs;

extern "C" uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
test_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_write_msr).Do(test_write_msr);
}

TEST_CASE("ia32_apic_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_apic_base;

    set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(get() == 0xFFFFFFFFFFFFFFFFULL);
    dump(0);
}

TEST_CASE("ia32_apic_base_bsp")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_apic_base;

    bsp::enable();
    CHECK(bsp::is_enabled());
    bsp::disable();
    CHECK(bsp::is_disabled());

    bsp::enable(bsp::mask);
    CHECK(bsp::is_enabled(bsp::mask));
    bsp::disable(0x0);
    CHECK(bsp::is_disabled(0x0));
}

TEST_CASE("ia32_apic_base_extd")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_apic_base;

    extd::enable();
    CHECK(extd::is_enabled());
    extd::disable();
    CHECK(extd::is_disabled());

    extd::enable(extd::mask);
    CHECK(extd::is_enabled(extd::mask));
    extd::disable(0x0);
    CHECK(extd::is_disabled(0x0));
}

TEST_CASE("ia32_apic_base_en")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_apic_base;

    en::enable();
    CHECK(en::is_enabled());
    en::disable();
    CHECK(en::is_disabled());

    en::enable(en::mask);
    CHECK(en::is_enabled(en::mask));
    en::disable(0x0);
    CHECK(en::is_disabled(0x0));
}

TEST_CASE("ia32_apic_base_state")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_apic_base;

    state::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(state::get() == (state::mask >> state::from));

    state::set(state::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(state::get(state::mask) == (state::mask >> state::from));

    state::disable();
    CHECK(state::get() == state::disabled);
    state::disable(state::disabled);
    CHECK(state::get(state::disabled << state::from) == state::disabled);
    state::dump(0);

    state::enable_xapic();
    CHECK(state::get() == state::xapic);
    state::enable_xapic(state::xapic);
    CHECK(state::get(state::xapic << state::from) == state::xapic);
    state::dump(0);

    state::enable_x2apic();
    CHECK(state::get() == state::x2apic);
    state::enable_x2apic(state::x2apic);
    CHECK(state::get(state::x2apic << state::from) == state::x2apic);
    state::dump(0);

    state::set(state::invalid);
    CHECK(state::get() == state::invalid);
    state::dump(0);
}

TEST_CASE("ia32_apic_base_apic_base")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace msrs::ia32_apic_base;

    apic_base::set(0xFFFFFFFFFFFFFFFFULL);
    CHECK(apic_base::get() == (apic_base::mask));

    apic_base::set(apic_base::mask, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(apic_base::get(apic_base::mask) == (apic_base::mask));
}

#endif
