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
// MERCHANTABILITY or FITNESS FOR A PARTICULLAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef BFCALLONCE
#define BFCALLONCE

/// @cond

#include <mutex>

// TODO
//
// This code is only needed because there seems to be a bug with GCC that
// causes a system error when --coverage is enabled. The following was written
// to have the same names and implementation as std::call_once so that at
// some point this code can easily be removed.
//
namespace bfn
{

struct once_flag {
    bool m_value{false};
    mutable std::mutex m_mutex{};
};

template<typename FUNC>
void call_once(once_flag &flag, FUNC func)
{
    std::lock_guard<std::mutex> lock(flag.m_mutex);

    if (!flag.m_value) {
        func();
        flag.m_value = true;
    }
}

}

/// @endcond

#endif
