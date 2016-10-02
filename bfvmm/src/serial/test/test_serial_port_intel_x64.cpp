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

#include <test.h>
#include <serial/serial_port_intel_x64.h>

#include <map>
static std::map<uint16_t, uint8_t> g_ports;

static uint8_t
read_portio_8(uint16_t port)
{
    return g_ports[port];
}

static void
write_portio_8(uint16_t port, uint8_t val)
{
    g_ports[port] = val;
}

static void
setup_intrinsics(MockRepository &mocks, intrinsics_intel_x64 *in)
{
    mocks.OnCall(in, intrinsics_intel_x64::read_portio_8).Do(read_portio_8);
    mocks.OnCall(in, intrinsics_intel_x64::write_portio_8).Do(write_portio_8);
}

void
serial_ut::test_serial_null_intrinsics()
{
    this->expect_no_exception([&] { std::make_shared<serial_port_intel_x64>(); });

}

void
serial_ut::test_serial_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, intrinsics.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_true(serial_port_intel_x64::instance(intrinsics)->port() == DEFAULT_COM_PORT);
        this->expect_true(serial_port_intel_x64::instance(intrinsics)->baud_rate() == serial_port_intel_x64::DEFAULT_BAUD_RATE);
        this->expect_true(serial_port_intel_x64::instance(intrinsics)->data_bits() == serial_port_intel_x64::DEFAULT_DATA_BITS);
        this->expect_true(serial_port_intel_x64::instance(intrinsics)->stop_bits() == serial_port_intel_x64::DEFAULT_STOP_BITS);
        this->expect_true(serial_port_intel_x64::instance(intrinsics)->parity_bits() == serial_port_intel_x64::DEFAULT_PARITY_BITS);

        this->expect_true((g_ports[DEFAULT_COM_PORT + BAUD_RATE_LO_REG]) == ((serial_port_intel_x64::DEFAULT_BAUD_RATE & 0x00FF) >> 0));
        this->expect_true((g_ports[DEFAULT_COM_PORT + BAUD_RATE_HI_REG]) == ((serial_port_intel_x64::DEFAULT_BAUD_RATE & 0xFF00) >> 8));
        this->expect_true((g_ports[DEFAULT_COM_PORT + FIFO_CONTROL_REG] & FIFO_CONTROL_ENABLE_FIFOS) != 0);
        this->expect_true((g_ports[DEFAULT_COM_PORT + FIFO_CONTROL_REG] & FIFO_CONTROL_CLEAR_RECIEVE_FIFO) != 0);
        this->expect_true((g_ports[DEFAULT_COM_PORT + FIFO_CONTROL_REG] & FIFO_CONTROL_CLEAR_TRANSMIT_FIFO) != 0);
        this->expect_true((g_ports[DEFAULT_COM_PORT + LINE_CONTROL_REG] & LINE_CONTROL_DATA_MASK) == serial_port_intel_x64::DEFAULT_DATA_BITS);
        this->expect_true((g_ports[DEFAULT_COM_PORT + LINE_CONTROL_REG] & LINE_CONTROL_STOP_MASK) == serial_port_intel_x64::DEFAULT_STOP_BITS);
        this->expect_true((g_ports[DEFAULT_COM_PORT + LINE_CONTROL_REG] & LINE_CONTROL_PARITY_MASK) == serial_port_intel_x64::DEFAULT_PARITY_BITS);
    });
}

void
serial_ut::test_serial_set_baud_rate_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, intrinsics.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto serial = std::make_shared<serial_port_intel_x64>(intrinsics);
        serial->init();

        serial->set_baud_rate(serial_port_intel_x64::baud_rate_50);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_50);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_75);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_75);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_110);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_110);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_150);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_150);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_300);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_300);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_600);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_600);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_1200);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_1200);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_1800);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_1800);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_2000);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_2000);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_2400);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_2400);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_3600);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_3600);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_4800);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_4800);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_7200);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_7200);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_9600);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_9600);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_19200);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_19200);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_38400);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_38400);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_57600);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_57600);
        serial->set_baud_rate(serial_port_intel_x64::baud_rate_115200);
        this->expect_true(serial->baud_rate() == serial_port_intel_x64::baud_rate_115200);
    });
}

void
serial_ut::test_serial_set_data_bits_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, intrinsics.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto serial = std::make_shared<serial_port_intel_x64>(intrinsics);
        serial->init();

        serial->set_data_bits(serial_port_intel_x64::char_length_5);
        this->expect_true(serial->data_bits() == serial_port_intel_x64::char_length_5);
        serial->set_data_bits(serial_port_intel_x64::char_length_6);
        this->expect_true(serial->data_bits() == serial_port_intel_x64::char_length_6);
        serial->set_data_bits(serial_port_intel_x64::char_length_7);
        this->expect_true(serial->data_bits() == serial_port_intel_x64::char_length_7);
        serial->set_data_bits(serial_port_intel_x64::char_length_8);
        this->expect_true(serial->data_bits() == serial_port_intel_x64::char_length_8);
    });
}

void
serial_ut::test_serial_set_data_bits_success_extra_bits()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, intrinsics.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto serial = std::make_shared<serial_port_intel_x64>(intrinsics);
        serial->init();

        auto bits = serial_port_intel_x64::DEFAULT_DATA_BITS | ~LINE_CONTROL_DATA_MASK;
        serial->set_data_bits(static_cast<serial_port_intel_x64::data_bits_t>(bits));

        this->expect_true(serial->data_bits() == serial_port_intel_x64::DEFAULT_DATA_BITS);
        this->expect_true(serial->stop_bits() == serial_port_intel_x64::DEFAULT_STOP_BITS);
        this->expect_true(serial->parity_bits() == serial_port_intel_x64::DEFAULT_PARITY_BITS);
    });
}

void
serial_ut::test_serial_set_stop_bits_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, intrinsics.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto serial = std::make_shared<serial_port_intel_x64>(intrinsics);
        serial->init();

        serial->set_stop_bits(serial_port_intel_x64::stop_bits_1);
        this->expect_true(serial->stop_bits() == serial_port_intel_x64::stop_bits_1);
        serial->set_stop_bits(serial_port_intel_x64::stop_bits_2);
        this->expect_true(serial->stop_bits() == serial_port_intel_x64::stop_bits_2);
    });
}

void
serial_ut::test_serial_set_stop_bits_success_extra_bits()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, intrinsics.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto serial = std::make_shared<serial_port_intel_x64>(intrinsics);
        serial->init();

        auto bits = serial_port_intel_x64::DEFAULT_STOP_BITS | ~LINE_CONTROL_STOP_MASK;
        serial->set_stop_bits(static_cast<serial_port_intel_x64::stop_bits_t>(bits));

        this->expect_true(serial->data_bits() == serial_port_intel_x64::DEFAULT_DATA_BITS);
        this->expect_true(serial->stop_bits() == serial_port_intel_x64::DEFAULT_STOP_BITS);
        this->expect_true(serial->parity_bits() == serial_port_intel_x64::DEFAULT_PARITY_BITS);
    });
}

void
serial_ut::test_serial_set_parity_bits_success()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, intrinsics.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto serial = std::make_shared<serial_port_intel_x64>(intrinsics);
        serial->init();

        serial->set_parity_bits(serial_port_intel_x64::parity_none);
        this->expect_true(serial->parity_bits() == serial_port_intel_x64::parity_none);
        serial->set_parity_bits(serial_port_intel_x64::parity_odd);
        this->expect_true(serial->parity_bits() == serial_port_intel_x64::parity_odd);
        serial->set_parity_bits(serial_port_intel_x64::parity_even);
        this->expect_true(serial->parity_bits() == serial_port_intel_x64::parity_even);
        serial->set_parity_bits(serial_port_intel_x64::parity_mark);
        this->expect_true(serial->parity_bits() == serial_port_intel_x64::parity_mark);
        serial->set_parity_bits(serial_port_intel_x64::parity_space);
        this->expect_true(serial->parity_bits() == serial_port_intel_x64::parity_space);
    });
}

void
serial_ut::test_serial_set_parity_bits_success_extra_bits()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, intrinsics.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto serial = std::make_shared<serial_port_intel_x64>(intrinsics);
        serial->init();

        auto bits = serial_port_intel_x64::DEFAULT_PARITY_BITS | ~LINE_CONTROL_PARITY_MASK;
        serial->set_parity_bits(static_cast<serial_port_intel_x64::parity_bits_t>(bits));

        this->expect_true(serial->data_bits() == serial_port_intel_x64::DEFAULT_DATA_BITS);
        this->expect_true(serial->stop_bits() == serial_port_intel_x64::DEFAULT_STOP_BITS);
        this->expect_true(serial->parity_bits() == serial_port_intel_x64::DEFAULT_PARITY_BITS);
    });
}

void
serial_ut::test_serial_write_character()
{
    MockRepository mocks;
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, intrinsics.get());

    mocks.OnCall(intrinsics.get(), intrinsics_intel_x64::read_portio_8).With(DEFAULT_COM_PORT + LINE_STATUS_REG).Return(0xFF);
    mocks.ExpectCall(intrinsics.get(), intrinsics_intel_x64::write_portio_8).With(DEFAULT_COM_PORT, _);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto serial = std::make_shared<serial_port_intel_x64>(intrinsics);
        serial->init();
        serial->write('c');
    });
}

void
serial_ut::test_serial_write_string()
{
    MockRepository mocks;
    auto msg = "hello world";
    auto intrinsics = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    setup_intrinsics(mocks, intrinsics.get());

    auto len = static_cast<uint32_t>(strlen(msg) + 1);

    mocks.OnCalls(intrinsics.get(), intrinsics_intel_x64::read_portio_8, len).With(DEFAULT_COM_PORT + LINE_STATUS_REG).Return(0xFF);
    mocks.ExpectCalls(intrinsics.get(), intrinsics_intel_x64::write_portio_8, len).With(DEFAULT_COM_PORT, _);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        auto serial = std::make_shared<serial_port_intel_x64>(intrinsics);
        serial->init();
        serial->write(msg);
    });
}
