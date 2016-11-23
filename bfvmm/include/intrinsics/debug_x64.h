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

#ifndef DEBUG_X64_H
#define DEBUG_X64_H

extern "C" uint64_t __read_dr7(void) noexcept;
extern "C" void __write_dr7(uint64_t val) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace dr7
{
    using value_type = uint64_t;

    inline auto get() noexcept
    { return __read_dr7(); }

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) noexcept { __write_dr7(val); }
}
}

// *INDENT-ON*

#endif
