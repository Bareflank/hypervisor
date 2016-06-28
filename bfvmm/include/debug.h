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

#ifndef DEBUG_H
#define DEBUG_H

#include <unistd.h>
#include <iomanip>
#include <iostream>
#include <sstream>

#define bfcolor_green "\033[1;32m"
#define bfcolor_red "\033[1;31m"

#define bfcolor_end "\033[0m"
#define bfcolor_debug "\033[1;32m"
#define bfcolor_warning "\033[1;33m"
#define bfcolor_error "\033[1;31m"
#define bfcolor_func "\033[1;36m"
#define bfcolor_line "\033[1;35m"

#define bfostream_shift 4
#define bfostream_offset 0x1000

/// Output To Core
///
/// All std::cout and std::cerr are sent to a specific debug_ring
/// based on the vcpuid that you provide, instead of being
/// broadcast to all of the debug_rings and serial.
///
/// @param vcpuid the vcpu to send the output to
/// @param func a lambda function containing the output to redirect
///
template<class T>
void output_to_vcpu(int64_t vcpuid, T func)
{
    auto handle = (vcpuid << bfostream_shift) + bfostream_offset;

    std::stringstream buffer;

    std::streambuf *coutbuf = std::cout.rdbuf(buffer.rdbuf());
    std::streambuf *cerrbuf = std::cerr.rdbuf(buffer.rdbuf());

    func();

    write(handle, buffer.str().c_str(), buffer.str().length());

    std::cout.rdbuf(coutbuf);
    std::cerr.rdbuf(cerrbuf);
}

/// This macro is a shortcut for std::endl
///
#ifndef bfendl
#define bfendl std::endl
#endif

/// This macro is a shortcut for std::cout that adds some text and color.
/// Use it like std::cout
///
/// @code
/// bfinfo << "hello world" << bfend;
/// @endcode
///
#ifndef bfinfo
#define bfinfo \
    std::cout
#endif

/// This macro is a shortcut for std::cout that adds some text and color.
/// Use it like std::cout
///
/// @code
/// bfdebug << "hello world" << bfend;
/// @endcode
///
#ifndef bfdebug
#define bfdebug \
    std::cout << bfcolor_debug << "DEBUG" << bfcolor_end << ": "
#endif

/// This macro is a shortcut for std::cout that adds some text and color.
/// Use it like std::cout
///
/// @code
/// bfwarning << "hello world" << bfend;
/// @endcode
///
#ifndef bfwarning
#define bfwarning \
    std::cerr << bfcolor_warning << "WARNING" << bfcolor_end << ": "
#endif

/// This macro is a shortcut for std::cout that adds some text and color.
/// Use it like std::cout
///
/// @code
/// bferror << "hello world" << bfend;
/// @endcode
///
#ifndef bferror
#define bferror \
    std::cerr << bfcolor_error << "ERROR" << bfcolor_end << ": "
#endif

/// This macro is a shortcut for std::cout that adds some text and color.
/// Use it like std::cout
///
/// @code
/// bffatal << "hello world" << bfend;
/// @endcode
///
#ifndef bffatal
#define bffatal \
    std::cerr << bfcolor_error << "FATAL ERROR" << bfcolor_end << ": "
#endif

#endif
