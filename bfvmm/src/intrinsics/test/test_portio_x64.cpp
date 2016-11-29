//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <vector>

#include <test.h>
#include <intrinsics/portio_x64.h>

using namespace x64;

constexpr const auto buf_size = 4;
std::map<portio::port_addr_type, portio::port_32bit_type> g_ports;

uint8_t g_buf_8bit[buf_size] = {};
uint16_t g_buf_16bit[buf_size] = {};
uint32_t g_buf_32bit[buf_size] = {};

extern "C" uint8_t
__inb(uint16_t port) noexcept
{ return gsl::narrow_cast<portio::port_8bit_type>(g_ports[port]); }

extern "C" uint16_t
__inw(uint16_t port) noexcept
{ return gsl::narrow_cast<portio::port_16bit_type>(g_ports[port]); }

extern "C" uint32_t
__ind(uint16_t port) noexcept
{ return gsl::narrow_cast<portio::port_32bit_type>(g_ports[port]); }

extern "C" void
__insb(uint16_t port, uint64_t m8) noexcept
{ (void) port; __builtin_memcpy(reinterpret_cast<void *>(m8), static_cast<void *>(g_buf_8bit), 1); }

extern "C" void
__insw(uint16_t port, uint64_t m16) noexcept
{ (void) port; __builtin_memcpy(reinterpret_cast<void *>(m16), static_cast<void *>(g_buf_16bit), 2); }

extern "C" void
__insd(uint16_t port, uint64_t m32) noexcept
{ (void) port; __builtin_memcpy(reinterpret_cast<void *>(m32), static_cast<void *>(g_buf_32bit), 4); }

extern "C" void
__insbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept
{ (void) port; __builtin_memcpy(reinterpret_cast<void *>(m8), static_cast<void *>(g_buf_8bit), count * 1); }

extern "C" void
__inswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept
{ (void) port; __builtin_memcpy(reinterpret_cast<void *>(m16), static_cast<void *>(g_buf_16bit), count * 2); }

extern "C" void
__insdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept
{ (void) port; __builtin_memcpy(reinterpret_cast<void *>(m32), static_cast<void *>(g_buf_32bit), count * 4); }

extern "C" void
__outb(uint16_t port, uint8_t val) noexcept
{ g_ports[port] = val; }

extern "C" void
__outw(uint16_t port, uint16_t val) noexcept
{ g_ports[port] = val; }

extern "C" void
__outd(uint16_t port, uint32_t val) noexcept
{ g_ports[port] = val; }

extern "C" void
__outsb(uint16_t port, uint64_t m8) noexcept
{ (void) port; __builtin_memcpy(static_cast<void *>(g_buf_8bit), reinterpret_cast<void *>(m8), 1); }

extern "C" void
__outsw(uint16_t port, uint64_t m16) noexcept
{ (void) port; __builtin_memcpy(static_cast<void *>(g_buf_16bit), reinterpret_cast<void *>(m16), 2); }

extern "C" void
__outsd(uint16_t port, uint64_t m32) noexcept
{ (void) port; __builtin_memcpy(static_cast<void *>(g_buf_32bit), reinterpret_cast<void *>(m32), 4); }

extern "C" void
__outsbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept
{ (void) port; __builtin_memcpy(static_cast<void *>(g_buf_8bit), reinterpret_cast<void *>(m8), count * 1); }

extern "C" void
__outswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept
{ (void) port; __builtin_memcpy(static_cast<void *>(g_buf_16bit), reinterpret_cast<void *>(m16), count * 2); }

extern "C" void
__outsdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept
{ (void) port; __builtin_memcpy(static_cast<void *>(g_buf_32bit), reinterpret_cast<void *>(m32), count * 4); }

void
intrinsics_ut::test_portio_x64_byte()
{
    std::vector<uint8_t> buf1 = {0, 1, 2, 3};
    std::vector<uint8_t> buf2 = {42, 42, 42, 42};
    std::vector<uint8_t> buf3 = {42, 42, 42, 42};

    portio::outb(10, 100U);
    this->expect_true(portio::inb(10) == 100U);

    portio::outsb(10, buf1.data());
    portio::insb(10, buf2.data());
    this->expect_true(buf2.at(0) == 0);

    portio::outsb(10, reinterpret_cast<portio::integer_pointer>(buf1.data()));
    portio::insb(10, reinterpret_cast<portio::integer_pointer>(buf2.data()));
    this->expect_true(buf2.at(0) == 0);

    portio::outsbrep(10, buf1.data(), buf_size);
    portio::insbrep(10, buf3.data(), buf_size);
    this->expect_true(buf3.at(0) == 0);
    this->expect_true(buf3.at(1) == 1);
    this->expect_true(buf3.at(2) == 2);
    this->expect_true(buf3.at(3) == 3);

    portio::outsbrep(10, reinterpret_cast<portio::integer_pointer>(buf1.data()), buf_size);
    portio::insbrep(10, reinterpret_cast<portio::integer_pointer>(buf3.data()), buf_size);
    this->expect_true(buf3.at(0) == 0);
    this->expect_true(buf3.at(1) == 1);
    this->expect_true(buf3.at(2) == 2);
    this->expect_true(buf3.at(3) == 3);
}

void
intrinsics_ut::test_portio_x64_word()
{
    std::vector<uint16_t> buf1 = {0, 1, 2, 3};
    std::vector<uint16_t> buf2 = {42, 42, 42, 42};
    std::vector<uint16_t> buf3 = {42, 42, 42, 42};

    portio::outw(10, 10000U);
    this->expect_true(portio::inw(10) == 10000U);

    portio::outsw(10, buf1.data());
    portio::insw(10, buf2.data());
    this->expect_true(buf2.at(0) == 0);

    portio::outsw(10, reinterpret_cast<portio::integer_pointer>(buf1.data()));
    portio::insw(10, reinterpret_cast<portio::integer_pointer>(buf2.data()));
    this->expect_true(buf2.at(0) == 0);

    portio::outswrep(10, buf1.data(), buf_size);
    portio::inswrep(10, buf3.data(), buf_size);
    this->expect_true(buf3.at(0) == 0);
    this->expect_true(buf3.at(1) == 1);
    this->expect_true(buf3.at(2) == 2);
    this->expect_true(buf3.at(3) == 3);

    portio::outswrep(10, reinterpret_cast<portio::integer_pointer>(buf1.data()), buf_size);
    portio::inswrep(10, reinterpret_cast<portio::integer_pointer>(buf3.data()), buf_size);
    this->expect_true(buf3.at(0) == 0);
    this->expect_true(buf3.at(1) == 1);
    this->expect_true(buf3.at(2) == 2);
    this->expect_true(buf3.at(3) == 3);
}

void
intrinsics_ut::test_portio_x64_doubleword()
{
    std::vector<uint32_t> buf1 = {0, 1, 2, 3};
    std::vector<uint32_t> buf2 = {42, 42, 42, 42};
    std::vector<uint32_t> buf3 = {42, 42, 42, 42};

    portio::outd(10, 10000U);
    this->expect_true(portio::ind(10) == 10000U);

    portio::outsd(10, buf1.data());
    portio::insd(10, buf2.data());
    this->expect_true(buf2.at(0) == 0);

    portio::outsd(10, reinterpret_cast<portio::integer_pointer>(buf1.data()));
    portio::insd(10, reinterpret_cast<portio::integer_pointer>(buf2.data()));
    this->expect_true(buf2.at(0) == 0);

    portio::outsdrep(10, buf1.data(), buf_size);
    portio::insdrep(10, buf3.data(), buf_size);
    this->expect_true(buf3.at(0) == 0);
    this->expect_true(buf3.at(1) == 1);
    this->expect_true(buf3.at(2) == 2);
    this->expect_true(buf3.at(3) == 3);

    portio::outsdrep(10, reinterpret_cast<portio::integer_pointer>(buf1.data()), buf_size);
    portio::insdrep(10, reinterpret_cast<portio::integer_pointer>(buf3.data()), buf_size);
    this->expect_true(buf3.at(0) == 0);
    this->expect_true(buf3.at(1) == 1);
    this->expect_true(buf3.at(2) == 2);
    this->expect_true(buf3.at(3) == 3);
}
