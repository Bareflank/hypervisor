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

#include <catch/catch.hpp>

#include <map>
#include <string>
#include <bfvmm/debug/serial/serial_port_base.h>

static std::map<serial_port_base::port_type, serial_port_base::value_type_32> g_ports;

extern "C" uint32_t
_ind(uint16_t port) noexcept
{ return g_ports[port]; }

extern "C" void
_outd(uint16_t port, uint32_t val) noexcept
{ g_ports[port] = val; }

extern "C" uint8_t
_inb(uint16_t port) noexcept
{ return static_cast<uint8_t>(g_ports[port]); }

extern "C" void
_outb(uint16_t port, uint8_t val) noexcept
{ g_ports[port] = val; }

class serial_port_base_tester : public serial_port_base
{
public:

    std::string str;

    port_type port() const noexcept override
    { return DEFAULT_COM_PORT; }

    void write(char c) noexcept override
    { str += c; }

    void set_port(port_type port) noexcept override
    { (void) port; }

    using serial_port_base::write;
    using serial_port_base::offset_inb;
    using serial_port_base::offset_ind;
    using serial_port_base::offset_outb;
    using serial_port_base::offset_outd;
};

TEST_CASE("serial_port_base: tester self-test")
{
    serial_port_base_tester tester;

    CHECK(tester.port() == DEFAULT_COM_PORT);

    tester.set_port(DEFAULT_COM_PORT + 1);
    CHECK(tester.port() == DEFAULT_COM_PORT);
}

TEST_CASE("serial_port_base: outb, inb, outd, ind")
{
    serial_port_base_tester tester;

    tester.offset_outb(1, 0xaa);
    CHECK(g_ports[DEFAULT_COM_PORT + 1] == 0xaa);
    CHECK(tester.offset_inb(1) == 0xaa);

    tester.offset_outd(2, 0x55aa55aa);
    CHECK(g_ports[DEFAULT_COM_PORT + 2] == 0x55aa55aa);
    CHECK(tester.offset_ind(2) == 0x55aa55aa);
}

TEST_CASE("serial_port_base: write string")
{
    serial_port_base_tester tester;

    tester.write("hello world");
    CHECK(tester.str == "hello world");
}

TEST_CASE("serial_port_base: write char buffer")
{
    serial_port_base_tester tester;

    tester.write("hello world", strlen("hello world"));
    CHECK(tester.str == "hello world");
}
