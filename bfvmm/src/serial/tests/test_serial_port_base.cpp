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

#include <serial/serial_port_base.h>
#include <hippomocks.h>
#include <map>
#include <string>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

static std::map<serial_port_base::port_type, serial_port_base::value_type_32> g_ports;

static uint32_t
mock_ind(uint16_t port) noexcept
{
    return g_ports[port];
}

static void
mock_outd(uint16_t port, uint32_t val) noexcept
{
    g_ports[port] = val;
}

static uint8_t
mock_inb(uint16_t port) noexcept
{
    return static_cast<uint8_t>(g_ports[port]);
}

static void
mock_outb(uint16_t port, uint8_t val) noexcept
{
    g_ports[port] = val;
}

static void
mock_portio(MockRepository &mocks)
{
    mocks.OnCallFunc(_outd).Do(mock_outd);
    mocks.OnCallFunc(_ind).Do(mock_ind);
    mocks.OnCallFunc(_outb).Do(mock_outb);
    mocks.OnCallFunc(_inb).Do(mock_inb);
}

class serial_port_base_tester : public serial_port_base
{
public:

    std::string str;

    virtual port_type port() const noexcept override
    {
        return DEFAULT_COM_PORT;
    }

    virtual void write(char c) noexcept override
    {
        str += c;
    }

    virtual void set_port(port_type port) noexcept override
    {
        (void) port;
    }

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
    MockRepository mocks;
    mock_portio(mocks);

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
    MockRepository mocks;
    mock_portio(mocks);

    serial_port_base_tester tester;

    tester.write("hello world");
    CHECK(tester.str == "hello world");
}

TEST_CASE("serial_port_base: write char buffer")
{
    MockRepository mocks;
    mock_portio(mocks);

    serial_port_base_tester tester;

    tester.write("hello world", strlen("hello world"));
    CHECK(tester.str == "hello world");
}

#endif
