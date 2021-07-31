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

#include "../../../src/huge_pool_t.hpp"

#include <bsl/ut.hpp>

namespace mk
{
    /// @brief used by most of the tests
    constexpr auto POOL_SIZE{0x3000_umx};
    /// @brief only used by the dump test as this is too large for the stack
    constexpr auto LARGE_POOL_SIZE{0x1000000_umx};

    /// @brief used for dump to prevent the unit test from running out of stack
    bsl::array<bsl::uint8, LARGE_POOL_SIZE.get()> g_pool{};

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
        bsl::ut_scenario{"allocate invalid size"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                huge_pool_t huge_pool{};
                bsl::array<bsl::uint8, POOL_SIZE.get()> pool{};
                bsl::span view{pool};
                tls_t tls{};
                bsl::ut_when{} = [&]() noexcept {
                    huge_pool.initialize(view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(!huge_pool.allocate(tls, bsl::safe_umx::failure()));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate 4k pages"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                huge_pool_t huge_pool{};
                bsl::array<bsl::uint8, POOL_SIZE.get()> pool{};
                bsl::span view{pool};
                tls_t tls{};
                bsl::ut_when{} = [&]() noexcept {
                    huge_pool.initialize(view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(huge_pool.allocate(tls, 0x1000_umx).size() == 0x1000_umx);
                        bsl::ut_check(huge_pool.allocate(tls, 0x1000_umx).size() == 0x1000_umx);
                        bsl::ut_check(huge_pool.allocate(tls, 0x1000_umx).size() == 0x1000_umx);
                        bsl::ut_check(!huge_pool.allocate(tls, 0x1000_umx));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate 8k pages"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                huge_pool_t huge_pool{};
                bsl::array<bsl::uint8, POOL_SIZE.get()> pool{};
                bsl::span view{pool};
                tls_t tls{};
                bsl::ut_when{} = [&]() noexcept {
                    huge_pool.initialize(view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(huge_pool.allocate(tls, 0x2000_umx).size() == 0x2000_umx);
                        bsl::ut_check(!huge_pool.allocate(tls, 0x2000_umx));
                    };
                };
            };
        };

        bsl::ut_scenario{"allocate non page sizes"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                huge_pool_t huge_pool{};
                bsl::array<bsl::uint8, POOL_SIZE.get()> pool{};
                bsl::span view{pool};
                tls_t tls{};
                bsl::ut_when{} = [&]() noexcept {
                    huge_pool.initialize(view);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(huge_pool.allocate(tls, 0xFFF_umx).size() == 0x1000_umx);
                        bsl::ut_check(huge_pool.allocate(tls, 0x001_umx).size() == 0x1000_umx);
                        bsl::ut_check(huge_pool.allocate(tls, 0x800_umx).size() == 0x1000_umx);
                        bsl::ut_check(!huge_pool.allocate(tls, 0x001_umx));
                    };
                };
            };
        };

        bsl::ut_scenario{"quiet deallocate"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                huge_pool_t huge_pool{};
                tls_t tls{};
                huge_pool.deallocate(tls, {});
            };
        };

        bsl::ut_scenario{"dump"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                huge_pool_t huge_pool{};
                bsl::array<bsl::uint8, POOL_SIZE.get()> pool{};
                bsl::span view{pool};
                tls_t tls{};
                bsl::ut_when{} = [&]() noexcept {
                    huge_pool.initialize(view);
                    bsl::ut_required_step(!!huge_pool.allocate(tls, 0x1000_umx));
                    bsl::ut_required_step(!!huge_pool.allocate(tls, 0x1000_umx));
                    bsl::ut_required_step(!!huge_pool.allocate(tls, 0x1000_umx));
                    bsl::ut_then{} = [&]() noexcept {
                        huge_pool.dump();
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                huge_pool_t huge_pool{};
                bsl::span view{g_pool};
                tls_t tls{};
                bsl::ut_when{} = [&]() noexcept {
                    huge_pool.initialize(view);
                    for (bsl::safe_idx i{}; i < 1024_umx; ++i) {
                        bsl::ut_required_step(!!huge_pool.allocate(tls, 0x1000_umx));
                    }
                    bsl::ut_then{} = [&]() noexcept {
                        huge_pool.dump();
                    };
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
