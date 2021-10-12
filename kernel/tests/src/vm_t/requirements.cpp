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

#include "../../../src/vm_t.hpp"

#include <ext_pool_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    /// @brief verify constinit it supported
    constinit mk::vm_t const g_verify_constinit{};
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
    bsl::ut_scenario{"verify supports constinit/constexpr"} = []() noexcept {
        bsl::discard(g_verify_constinit);
    };

    bsl::ut_scenario{"verify noexcept"} = []() noexcept {
        bsl::ut_given{} = []() noexcept {
            mk::vm_t mut_vm{};
            mk::vm_t const vm{};
            mk::tls_t mut_tls{};
            mk::page_pool_t mut_page_pool{};
            mk::ext_pool_t mut_ext_pool{};
            bsl::ut_then{} = []() noexcept {
                static_assert(noexcept(mk::vm_t{}));

                static_assert(noexcept(mut_vm.initialize({})));
                static_assert(noexcept(mut_vm.release(mut_tls, mut_page_pool, mut_ext_pool)));
                static_assert(noexcept(mut_vm.id()));
                static_assert(noexcept(mut_vm.allocate(mut_tls, mut_page_pool, mut_ext_pool)));
                static_assert(noexcept(mut_vm.deallocate(mut_tls, mut_page_pool, mut_ext_pool)));
                static_assert(noexcept(mut_vm.is_deallocated()));
                static_assert(noexcept(mut_vm.is_allocated()));
                static_assert(noexcept(mut_vm.set_active(mut_tls)));
                static_assert(noexcept(mut_vm.set_inactive(mut_tls)));
                static_assert(noexcept(mut_vm.is_active(mut_tls)));
                static_assert(noexcept(mut_vm.is_active_on_this_pp(mut_tls)));
                static_assert(noexcept(mut_vm.dump({})));

                static_assert(noexcept(vm.id()));
                static_assert(noexcept(vm.is_deallocated()));
                static_assert(noexcept(vm.is_allocated()));
                static_assert(noexcept(vm.is_active(mut_tls)));
                static_assert(noexcept(vm.is_active_on_this_pp(mut_tls)));
                static_assert(noexcept(vm.dump({})));
            };
        };
    };

    return bsl::ut_success();
}
