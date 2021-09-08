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

#ifndef VMEXIT_LOG_PP_T
#define VMEXIT_LOG_PP_T

#include <vmexit_log_record_t.hpp>

#include <bsl/array.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// @class mk::vmexit_log_pp_t
    ///
    /// <!-- description -->
    ///   @brief Stores information about each VMExit per PP
    ///
    struct vmexit_log_pp_t final
    {
        /// @brief stores the VMExit log
        bsl::array<vmexit_log_record_t, HYPERVISOR_VMEXIT_LOG_SIZE> log;
        /// @brief stores the VMExit log circular cursor
        bsl::safe_umx crsr;
    };
}

#endif
