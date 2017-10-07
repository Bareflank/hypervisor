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
#include <intrinsics/x86/common_x64.h>
//#include <vector>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

TEST_CASE("test name goes here")
{
    CHECK(true);
}

constexpr const auto buf_size = 4;
std::map<portio::port_addr_type, portio::port_32bit_type> g_ports;

uint8_t g_buf_8bit[buf_size] = {};
uint16_t g_buf_16bit[buf_size] = {};
uint32_t g_buf_32bit[buf_size] = {};

uint8_t
test_inb(uint16_t port) noexcept
{ return gsl::narrow_cast<portio::port_8bit_type>(g_ports[port]); }

uint16_t
test_inw(uint16_t port) noexcept
{ return gsl::narrow_cast<portio::port_16bit_type>(g_ports[port]); }

uint32_t
test_ind(uint16_t port) noexcept
{ return gsl::narrow_cast<portio::port_32bit_type>(g_ports[port]); }

void
test_insb(uint16_t port, uint64_t m8) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m8), static_cast<void *>(g_buf_8bit), 1); }

void
test_insw(uint16_t port, uint64_t m16) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m16), static_cast<void *>(g_buf_16bit), 2); }

void
test_insd(uint16_t port, uint64_t m32) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m32), static_cast<void *>(g_buf_32bit), 4); }

void
test_insbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m8), static_cast<void *>(g_buf_8bit), static_cast<uint32_t>(count * 1)); }

void
test_inswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m16), static_cast<void *>(g_buf_16bit), static_cast<uint32_t>(count * 2)); }

void
test_insdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m32), static_cast<void *>(g_buf_32bit), static_cast<uint32_t>(count * 4)); }

void
test_outb(uint16_t port, uint8_t val) noexcept
{ g_ports[port] = val; }

void
test_outw(uint16_t port, uint16_t val) noexcept
{ g_ports[port] = val; }

void
test_outd(uint16_t port, uint32_t val) noexcept
{ g_ports[port] = val; }

void
test_outsb(uint16_t port, uint64_t m8) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_8bit), reinterpret_cast<void *>(m8), 1); }

void
test_outsw(uint16_t port, uint64_t m16) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_16bit), reinterpret_cast<void *>(m16), 2); }

void
test_outsd(uint16_t port, uint64_t m32) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_32bit), reinterpret_cast<void *>(m32), 4); }

void
test_outsbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_8bit), reinterpret_cast<void *>(m8), static_cast<uint32_t>(count * 1)); }

void
test_outswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_16bit), reinterpret_cast<void *>(m16), static_cast<uint32_t>(count * 2)); }

void
test_outsdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_32bit), reinterpret_cast<void *>(m32), static_cast<uint32_t>(count * 4)); }

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_inb).Do(test_inb);
    mocks.OnCallFunc(_inw).Do(test_inw);
    mocks.OnCallFunc(_ind).Do(test_ind);
    mocks.OnCallFunc(_insb).Do(test_insb);
    mocks.OnCallFunc(_insw).Do(test_insw);
    mocks.OnCallFunc(_insd).Do(test_insd);
    mocks.OnCallFunc(_insbrep).Do(test_insbrep);
    mocks.OnCallFunc(_inswrep).Do(test_inswrep);
    mocks.OnCallFunc(_insdrep).Do(test_insdrep);
    mocks.OnCallFunc(_outb).Do(test_outb);
    mocks.OnCallFunc(_outw).Do(test_outw);
    mocks.OnCallFunc(_outd).Do(test_outd);
    mocks.OnCallFunc(_outsb).Do(test_outsb);
    mocks.OnCallFunc(_outsw).Do(test_outsw);
    mocks.OnCallFunc(_outsd).Do(test_outsd);
    mocks.OnCallFunc(_outsbrep).Do(test_outsbrep);
    mocks.OnCallFunc(_outswrep).Do(test_outswrep);
    mocks.OnCallFunc(_outsdrep).Do(test_outsdrep);
}

TEST_CASE("portio_x64_byte")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    std::vector<uint8_t> buf1 = {0, 1, 2, 3};
    std::vector<uint8_t> buf2 = {42, 42, 42, 42};
    std::vector<uint8_t> buf3 = {42, 42, 42, 42};

    portio::outb(10, 100U);
    CHECK(portio::inb(10) == 100U);

    portio::outsb(10, buf1.data());
    portio::insb(10, buf2.data());
    CHECK(buf2.at(0) == 0);

    portio::outsb(10, reinterpret_cast<portio::integer_pointer>(buf1.data()));
    portio::insb(10, reinterpret_cast<portio::integer_pointer>(buf2.data()));
    CHECK(buf2.at(0) == 0);

    portio::outsbrep(10, buf1.data(), buf_size);
    portio::insbrep(10, buf3.data(), buf_size);
    CHECK(buf3.at(0) == 0);
    CHECK(buf3.at(1) == 1);
    CHECK(buf3.at(2) == 2);
    CHECK(buf3.at(3) == 3);

    portio::outsbrep(10, reinterpret_cast<portio::integer_pointer>(buf1.data()), buf_size);
    portio::insbrep(10, reinterpret_cast<portio::integer_pointer>(buf3.data()), buf_size);
    CHECK(buf3.at(0) == 0);
    CHECK(buf3.at(1) == 1);
    CHECK(buf3.at(2) == 2);
    CHECK(buf3.at(3) == 3);
}

TEST_CASE("portio_x64_word")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    std::vector<uint16_t> buf1 = {0, 1, 2, 3};
    std::vector<uint16_t> buf2 = {42, 42, 42, 42};
    std::vector<uint16_t> buf3 = {42, 42, 42, 42};

    portio::outw(10, 10000U);
    CHECK(portio::inw(10) == 10000U);

    portio::outsw(10, buf1.data());
    portio::insw(10, buf2.data());
    CHECK(buf2.at(0) == 0);

    portio::outsw(10, reinterpret_cast<portio::integer_pointer>(buf1.data()));
    portio::insw(10, reinterpret_cast<portio::integer_pointer>(buf2.data()));
    CHECK(buf2.at(0) == 0);

    portio::outswrep(10, buf1.data(), buf_size);
    portio::inswrep(10, buf3.data(), buf_size);
    CHECK(buf3.at(0) == 0);
    CHECK(buf3.at(1) == 1);
    CHECK(buf3.at(2) == 2);
    CHECK(buf3.at(3) == 3);

    portio::outswrep(10, reinterpret_cast<portio::integer_pointer>(buf1.data()), buf_size);
    portio::inswrep(10, reinterpret_cast<portio::integer_pointer>(buf3.data()), buf_size);
    CHECK(buf3.at(0) == 0);
    CHECK(buf3.at(1) == 1);
    CHECK(buf3.at(2) == 2);
    CHECK(buf3.at(3) == 3);
}

TEST_CASE("portio_x64_doubleword")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    std::vector<uint32_t> buf1 = {0, 1, 2, 3};
    std::vector<uint32_t> buf2 = {42, 42, 42, 42};
    std::vector<uint32_t> buf3 = {42, 42, 42, 42};

    portio::outd(10, 10000U);
    CHECK(portio::ind(10) == 10000U);

    portio::outsd(10, buf1.data());
    portio::insd(10, buf2.data());
    CHECK(buf2.at(0) == 0);

    portio::outsd(10, reinterpret_cast<portio::integer_pointer>(buf1.data()));
    portio::insd(10, reinterpret_cast<portio::integer_pointer>(buf2.data()));
    CHECK(buf2.at(0) == 0);

    portio::outsdrep(10, buf1.data(), buf_size);
    portio::insdrep(10, buf3.data(), buf_size);
    CHECK(buf3.at(0) == 0);
    CHECK(buf3.at(1) == 1);
    CHECK(buf3.at(2) == 2);
    CHECK(buf3.at(3) == 3);

    portio::outsdrep(10, reinterpret_cast<portio::integer_pointer>(buf1.data()), buf_size);
    portio::insdrep(10, reinterpret_cast<portio::integer_pointer>(buf3.data()), buf_size);
    CHECK(buf3.at(0) == 0);
    CHECK(buf3.at(1) == 1);
    CHECK(buf3.at(2) == 2);
    CHECK(buf3.at(3) == 3);
}

#endif
