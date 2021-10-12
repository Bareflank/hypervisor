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

#ifndef MOCKS_PROMOTE_HPP
#define MOCKS_PROMOTE_HPP

#include <bsl/cstdint.hpp>
#include <bsl/discard.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Promotes the current physical processor. Specifically,
    ///     this is called from the microkernel's POV and tells the microkernel
    ///     to transition the CPU's execution to the provided state, which
    ///     will conclude the execution of the microkernel in favor of whatever
    ///     is in the state, effectively stopping the hypervisor.
    ///
    /// <!-- inputs/outputs -->
    ///   @param state the state to promote to
    ///   @param ec the exit code to provide
    ///
    constexpr void
    promote(void const *const state, bsl::uintmx const ec = {}) noexcept
    {
        bsl::discard(state);
        bsl::discard(ec);
    }
}

#endif
