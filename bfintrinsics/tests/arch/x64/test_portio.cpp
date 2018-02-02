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

constexpr const auto buf_size = 4;
std::map<portio::port_addr_type, portio::port_32bit_type> g_ports;

uint8_t g_buf_8bit[buf_size] = {};
uint16_t g_buf_16bit[buf_size] = {};
uint32_t g_buf_32bit[buf_size] = {};

extern "C" uint8_t
_inb(uint16_t port) noexcept
{ return gsl::narrow_cast<portio::port_8bit_type>(g_ports[port]); }

extern "C" uint16_t
_inw(uint16_t port) noexcept
{ return gsl::narrow_cast<portio::port_16bit_type>(g_ports[port]); }

extern "C" uint32_t
_ind(uint16_t port) noexcept
{ return gsl::narrow_cast<portio::port_32bit_type>(g_ports[port]); }

extern "C" void
_insb(uint16_t port, uint64_t m8) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m8), static_cast<void *>(g_buf_8bit), 1); }

extern "C" void
_insw(uint16_t port, uint64_t m16) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m16), static_cast<void *>(g_buf_16bit), 2); }

extern "C" void
_insd(uint16_t port, uint64_t m32) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m32), static_cast<void *>(g_buf_32bit), 4); }

extern "C" void
_insbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m8), static_cast<void *>(g_buf_8bit), static_cast<uint32_t>(count * 1)); }

extern "C" void
_inswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m16), static_cast<void *>(g_buf_16bit), static_cast<uint32_t>(count * 2)); }

extern "C" void
_insdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept
{ (void) port; memcpy(reinterpret_cast<void *>(m32), static_cast<void *>(g_buf_32bit), static_cast<uint32_t>(count * 4)); }

extern "C" void
_outb(uint16_t port, uint8_t val) noexcept
{ g_ports[port] = val; }

extern "C" void
_outw(uint16_t port, uint16_t val) noexcept
{ g_ports[port] = val; }

extern "C" void
_outd(uint16_t port, uint32_t val) noexcept
{ g_ports[port] = val; }

extern "C" void
_outsb(uint16_t port, uint64_t m8) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_8bit), reinterpret_cast<void *>(m8), 1); }

extern "C" void
_outsw(uint16_t port, uint64_t m16) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_16bit), reinterpret_cast<void *>(m16), 2); }

extern "C" void
_outsd(uint16_t port, uint64_t m32) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_32bit), reinterpret_cast<void *>(m32), 4); }

extern "C" void
_outsbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_8bit), reinterpret_cast<void *>(m8), static_cast<uint32_t>(count * 1)); }

extern "C" void
_outswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_16bit), reinterpret_cast<void *>(m16), static_cast<uint32_t>(count * 2)); }

extern "C" void
_outsdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept
{ (void) port; memcpy(static_cast<void *>(g_buf_32bit), reinterpret_cast<void *>(m32), static_cast<uint32_t>(count * 4)); }

TEST_CASE("portio_byte")
{
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

TEST_CASE("portio_word")
{
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

TEST_CASE("portio_doubleword")
{
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
