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
#include <guard_exceptions.h>

/// Commit Or Rollback
///
/// This class is used by a large portion of Bareflank for properly handling
/// execptions. When a failure occurs, and an exception is thrown, it's
/// possible that a function is partly into the process of creating state.
/// The exception will leave the state of the system "partially" created,
/// which can cause a lot of problems. The commit_or_rollback class provides
/// a means to rollback code when a failure occurs.
///
/// vmxon_intel_x64::start provides a good example of how this works. In
/// general, to rollback state changes, do the following:
///
/// @code
///
/// int a = 10;
/// int b = 10;
///
/// void foo()
/// {
///     auto cor1 = commit_or_rollback([&]
///     { a = 0 });
///
///     a = 10;
///
///     auto cor2 = commit_or_rollback([&]
///     { b = 0 });
///
///     b = 10;
///
///     cor1.commit();
///     cor2.commit();
/// }
///
/// @endcode
///
/// If an exception is thrown prior to the commit functions being executed,
/// the rollback lambda functions are executed. Note that the commit functions
/// are labeled noexcept, and should be the very last thing you do to ensure
/// that state is prorperly rolled back in a failure occurs.
///
class commit_or_rollback
{
public:
    commit_or_rollback(std::function<void()> &&fail_handler) :
        m_committed(false),
        m_fail_handler(std::move(fail_handler))
    {
    }

    ~commit_or_rollback() noexcept
    {
        guard_exceptions(-1, [&]
        {
            if (!m_committed)
                m_fail_handler();
        });
    }

    void commit() noexcept
    { m_committed = true; }

private:

    bool m_committed;
    std::function<void()> m_fail_handler;
};
