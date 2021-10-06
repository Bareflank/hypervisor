/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef MOCKS_VMEXIT_LOG_T_HPP
#define MOCKS_VMEXIT_LOG_T_HPP

#include <vmexit_log_record_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Stores a log of all VMExits that occur. Each PP has one log
    ///     that is shared between all of the VSs so that you get a consistent
    ///     view of what actually happened during execution, which is more
    ///     important when implementing guest support as VSs can swap between
    ///     execution on the same PP as the hypervisor is moving between VMs.
    ///
    class vmexit_log_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Adds a record in the VMExit log
        ///
        /// <!-- inputs/outputs -->
        ///   @param ppid the id of the PP whose log should be added to
        ///   @param rec the record to add to the log
        ///
        static constexpr void
        add(bsl::safe_u16 const &ppid, vmexit_log_record_t const &rec) noexcept
        {
            bsl::discard(ppid);
            bsl::discard(rec);
        }

        /// <!-- description -->
        ///   @brief Dumps the contents of the VMExit log for the requested PP
        ///
        /// <!-- inputs/outputs -->
        ///   @param ppid the ID of the PP whose log should be dumped
        ///
        static constexpr void
        dump(bsl::safe_u16 const &ppid) noexcept
        {
            bsl::discard(ppid);
        }
    };
}

#endif
