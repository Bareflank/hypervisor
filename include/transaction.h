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

#include <utility>
#include <functional>

class commit_or_rollback
{
public:
    commit_or_rollback(std::function<void()> &&fail_handler) :
        m_committed(false),
        m_fail_handler(std::move(fail_handler))
    {
    }

    ~commit_or_rollback()
    {
        if (!m_committed)
            m_fail_handler();
    }

    void commit() noexcept
    { m_committed = true; }

private:

    bool m_committed;
    std::function<void()> m_fail_handler;
};
