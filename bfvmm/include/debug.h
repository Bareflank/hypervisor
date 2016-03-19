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

#include <iomanip>
#include <iostream>

#define bfcolor_green "\033[1;32m"
#define bfcolor_red "\033[1;31m"

#define bfcolor_end "\033[0m"
#define bfcolor_debug "\033[1;32m"
#define bfcolor_warning "\033[1;33m"
#define bfcolor_error "\033[1;31m"
#define bfcolor_func "\033[1;36m"
#define bfcolor_line "\033[1;35m"

#define bfendl std::endl

#define bfinfo \
    std::cout
#define bfdebug \
    std::cout << bfcolor_debug << "DEBUG" << bfcolor_end << ": "
#define bfwarning \
    std::cout << bfcolor_warning << "WARNING" << bfcolor_end << ": "
#define bferror \
    std::cout << bfcolor_error << "ERROR" << bfcolor_end << ": "
#define bffatal \
    std::cout << bfcolor_error << "FATAL ERROR" << bfcolor_end << ": "

#endif
