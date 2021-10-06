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

#include "../../../../src/x64/vmexit_log_t.hpp"

#include <vmexit_log_record_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"add"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vmexit_log_t log{};
                constexpr auto loops{10_umx};
                constexpr auto ppid0{0x0_u16};
                constexpr auto ppid1{0x1_u16};
                bsl::ut_then{} = [&]() noexcept {
                    for (bsl::safe_idx mut_i{}; mut_i < loops; ++mut_i) {
                        log.add(ppid0, {});
                    }

                    for (bsl::safe_idx mut_i{}; mut_i < loops; ++mut_i) {
                        log.add(ppid1, {});
                    }
                };
            };
        };

        bsl::ut_scenario{"dump"} = [&]() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                vmexit_log_t log{};
                constexpr auto loops{10_umx};
                constexpr auto ppid0{0x0_u16};
                constexpr auto ppid1{0x1_u16};
                vmexit_log_record_t mut_rec{};
                bsl::ut_then{} = [&]() noexcept {
                    log.dump(ppid0);
                    log.dump(ppid1);

                    for (bsl::safe_idx mut_i{}; mut_i < loops; ++mut_i) {
                        log.add(ppid0, mut_rec);
                    }

                    log.dump(ppid0);
                    log.dump(ppid1);

                    mut_rec.rip = bsl::safe_u64::magic_1();
                    for (bsl::safe_idx mut_i{}; mut_i < loops; ++mut_i) {
                        log.add(ppid1, mut_rec);
                    }

                    mut_rec.rax = bsl::safe_u64::magic_1();
                    log.dump(ppid0);
                    log.dump(ppid1);

                    for (bsl::safe_idx mut_i{}; mut_i < loops; ++mut_i) {
                        log.add(ppid0, mut_rec);
                    }

                    log.dump(ppid0);
                    log.dump(ppid1);
                };
            };
        };

        return bsl::ut_success();
    }
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
    bsl::enable_color();

    static_assert(mk::tests() == bsl::ut_success());
    return mk::tests();
}
