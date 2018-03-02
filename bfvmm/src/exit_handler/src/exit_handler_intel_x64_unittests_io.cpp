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

#include <exit_handler/exit_handler_intel_x64_unittests.h>

#ifdef INCLUDE_LIBCXX_UNITTESTS

#include <iomanip>
#include <iostream>

void
exit_handler_intel_x64::unittest_1100_io_cout() const
{
    std::cout << "hello world" << std::endl;
    std::cout << 10 << std::endl;
    std::cout << 10U << std::endl;
    std::cout << 10L << std::endl;
    std::cout << 10UL << std::endl;
    std::cout << view_as_pointer(10UL) << std::endl;
}

void
exit_handler_intel_x64::unittest_1101_io_manipulators() const
{
    std::cout << std::boolalpha << true << '\n';
    std::cout << std::boolalpha << false << '\n';
    std::cout << std::noboolalpha << true << '\n';
    std::cout << std::noboolalpha << false << '\n';

    std::cout << std::noshowbase << 3.14 << '\n';
    std::cout << std::noshowpoint << 3.14 << '\n';
    std::cout << std::noshowpos << 3.14 << '\n';
    std::cout << std::noskipws << 3.14 << '\n';
    std::cout << std::nounitbuf << 3.14 << '\n';
    std::cout << std::nouppercase << 3.14 << '\n';

    std::cout << std::showbase << 3.14 << '\n';
    std::cout << std::showpoint << 3.14 << '\n';
    std::cout << std::showpos << 3.14 << '\n';
    std::cout << std::skipws << 3.14 << '\n';
    std::cout << std::unitbuf << 3.14 << '\n';
    std::cout << std::uppercase << 3.14 << '\n';

    std::cout << std::hex << 1 << '\n';
    std::cout << std::hex << 11 << '\n';
    std::cout << std::oct << 1 << '\n';
    std::cout << std::oct << 11 << '\n';
    std::cout << std::dec << 1 << '\n';
    std::cout << std::dec << 11 << '\n';
    std::cout << std::setbase(10) << 1 << '\n';
    std::cout << std::setbase(10) << 11 << '\n';

    std::cout << std::scientific << 3.14 << '\n';
    std::cout << std::setprecision(2) << 3.14 << '\n';

    std::cout << std::fixed << 3.14 << '\n';
    std::cout << std::fixed << 3.14 << '\n';

    std::cout << std::internal << 42 << '\n';
    std::cout << std::left << 42 << '\n';
    std::cout << std::right << 42 << '\n';

    std::cout << std::setfill('0') << std::setw(10) << 10 << std::endl;

    std::cout << std::endl;
    std::cout << std::ends;
    std::cout << std::flush;
}

#endif
