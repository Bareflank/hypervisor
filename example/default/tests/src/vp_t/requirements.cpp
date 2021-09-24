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

#include "../../../src/vp_t.hpp"

#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// @brief verify constinit it supported
    constinit example::vp_t const g_verify_constinit{};
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::ut_scenario{"verify supports constinit"} = []() noexcept {
        bsl::discard(g_verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            example::vp_t const vp{};
            example::vp_t mut_vp{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(example::vp_t{}));

                static_assert(noexcept(mut_vp.initialize({}, {}, {}, {}, {})));
                static_assert(noexcept(mut_vp.release({}, {}, {}, {})));
                static_assert(noexcept(mut_vp.id()));
                static_assert(noexcept(mut_vp.allocate({}, {}, {}, {}, {})));
                static_assert(noexcept(mut_vp.deallocate({}, {}, {}, {})));
                static_assert(noexcept(mut_vp.is_allocated()));
                static_assert(noexcept(mut_vp.is_deallocated()));
                static_assert(noexcept(mut_vp.assigned_vm()));

                static_assert(noexcept(vp.id()));
                static_assert(noexcept(vp.is_allocated()));
                static_assert(noexcept(vp.is_deallocated()));
                static_assert(noexcept(vp.assigned_vm()));
            };
        };
    };

    return bsl::ut_success();
}
