/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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

#include <bsl/for_each.hpp>
#include <bsl/discard.hpp>
#include <bsl/numeric_limits.hpp>
#include <bsl/ut.hpp>

namespace
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunneeded-internal-declaration"

    constexpr void
    test_func1(bsl::int32 const &elem, bsl::uintmax index) noexcept
    {
        bsl::discard(elem);
        bsl::discard(index);
    }

    constexpr void
    test_func2(bsl::int32 const &elem, bsl::uintmax index)
    {
        bsl::discard(elem);
        bsl::discard(index);
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32                 // --
        test_array(bsl::int32 (&array)[N]) noexcept    // NOLINT
    {
        bsl::int32 answer{};
        bsl::for_each(array, [&answer](auto &elem, auto index) {
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32                                       // --
    test_array_p(bsl::int32 (&array)[N], bsl::uintmax const pos) noexcept    // NOLINT
    {
        bsl::int32 answer{};
        bsl::for_each(array, pos, [&answer](auto &elem, auto index) {
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32    // --
    test_array_pc(                        // --
        bsl::int32 (&array)[N],           // NOLINT
        bsl::uintmax const pos,           // --
        bsl::uintmax const count) noexcept
    {
        bsl::int32 answer{};
        bsl::for_each(array, pos, count, [&answer](auto &elem, auto index) {
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32                   // --
    test_array(bsl::int32 const (&array)[N]) noexcept    // NOLINT
    {
        bsl::int32 answer{};
        bsl::for_each(array, [&answer](auto const &elem, auto index) {
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32                                             // --
    test_array_p(bsl::int32 const (&array)[N], bsl::uintmax const pos) noexcept    // NOLINT
    {
        bsl::int32 answer{};
        bsl::for_each(array, pos, [&answer](auto const &elem, auto index) {
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32    // --
    test_array_pc(                        // --
        bsl::int32 const (&array)[N],     // NOLINT
        bsl::uintmax const pos,           // --
        bsl::uintmax const count) noexcept
    {
        bsl::int32 answer{};
        bsl::for_each(array, pos, count, [&answer](auto const &elem, auto index) {
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

#pragma clang diagnostic pop
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- contracts -->
///   @pre none
///   @post none
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    using namespace bsl;
    constexpr bsl::uintmax max{numeric_limits<bsl::uintmax>::max()};

    bsl::ut_scenario{"for_each array size 1"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[1]{42};                       // NOLINT
            bsl::ut_then{} = [&array]() {                  // NOLINT
                bsl::ut_check(test_array(array) == 42);    // NOLINT
                static_assert(test_array({42}) == 42);     // NOLINT
            };
        };
    };

    bsl::ut_scenario{"for_each array size 6"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                       // NOLINT
            bsl::ut_then{} = [&array]() {                                    // NOLINT
                bsl::ut_check(test_array(array) == 108);                     // NOLINT
                static_assert(test_array({4, 8, 15, 16, 23, 42}) == 108);    // NOLINT
            };
        };
    };

    bsl::ut_scenario{"for_each pos"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                            // NOLINT
            bsl::ut_then{} = [&array]() {                                         // NOLINT
                bsl::ut_check(test_array_p(array, 0) == 108);                     // NOLINT
                static_assert(test_array_p({4, 8, 15, 16, 23, 42}, 0) == 108);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                            // NOLINT
            bsl::ut_then{} = [&array]() {                                         // NOLINT
                bsl::ut_check(test_array_p(array, 1) == 104);                     // NOLINT
                static_assert(test_array_p({4, 8, 15, 16, 23, 42}, 1) == 104);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                           // NOLINT
            bsl::ut_then{} = [&array]() {                                        // NOLINT
                bsl::ut_check(test_array_p(array, 42) == 0);                     // NOLINT
                static_assert(test_array_p({4, 8, 15, 16, 23, 42}, 42) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                            // NOLINT
            bsl::ut_then{} = [&array]() {                                         // NOLINT
                bsl::ut_check(test_array_p(array, max) == 0);                     // NOLINT
                static_assert(test_array_p({4, 8, 15, 16, 23, 42}, max) == 0);    // NOLINT
            };
        };
    };

    bsl::ut_scenario{"for_each pos count"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                              // NOLINT
            bsl::ut_then{} = [&array]() {                                           // NOLINT
                bsl::ut_check(test_array_pc(array, 0, 0) == 0);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 0, 0) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                              // NOLINT
            bsl::ut_then{} = [&array]() {                                           // NOLINT
                bsl::ut_check(test_array_pc(array, 1, 0) == 0);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 1, 0) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                               // NOLINT
            bsl::ut_then{} = [&array]() {                                            // NOLINT
                bsl::ut_check(test_array_pc(array, 42, 0) == 0);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 42, 0) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                                // NOLINT
            bsl::ut_then{} = [&array]() {                                             // NOLINT
                bsl::ut_check(test_array_pc(array, max, 0) == 0);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, max, 0) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                              // NOLINT
            bsl::ut_then{} = [&array]() {                                           // NOLINT
                bsl::ut_check(test_array_pc(array, 0, 1) == 4);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 0, 1) == 4);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                              // NOLINT
            bsl::ut_then{} = [&array]() {                                           // NOLINT
                bsl::ut_check(test_array_pc(array, 1, 1) == 8);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 1, 1) == 8);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                               // NOLINT
            bsl::ut_then{} = [&array]() {                                            // NOLINT
                bsl::ut_check(test_array_pc(array, 42, 1) == 0);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 42, 0) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                                // NOLINT
            bsl::ut_then{} = [&array]() {                                             // NOLINT
                bsl::ut_check(test_array_pc(array, max, 1) == 0);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, max, 0) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                                // NOLINT
            bsl::ut_then{} = [&array]() {                                             // NOLINT
                bsl::ut_check(test_array_pc(array, 0, 6) == 108);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 0, 6) == 108);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                                // NOLINT
            bsl::ut_then{} = [&array]() {                                             // NOLINT
                bsl::ut_check(test_array_pc(array, 1, 5) == 104);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 1, 5) == 104);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                              // NOLINT
            bsl::ut_then{} = [&array]() {                                           // NOLINT
                bsl::ut_check(test_array_pc(array, 0, 7) == 0);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 0, 7) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                              // NOLINT
            bsl::ut_then{} = [&array]() {                                           // NOLINT
                bsl::ut_check(test_array_pc(array, 1, 6) == 0);                     // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 1, 6) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                              // NOLINT
            bsl::ut_then{} = [&array]() {                                           // NOLINT
                bsl::ut_check(test_array_pc(array, 0, max) == 0);                   // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 0, 7) == 0);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                                // NOLINT
            bsl::ut_then{} = [&array]() {                                             // NOLINT
                bsl::ut_check(test_array_pc(array, 1, 6) == 0);                       // NOLINT
                static_assert(test_array_pc({4, 8, 15, 16, 23, 42}, 1, max) == 0);    // NOLINT
            };
        };
    };

    bsl::ut_scenario{"except"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                       // NOLINT
            bsl::ut_then{} = []() {                                          // NOLINT
                static_assert(!noexcept(for_each(array, test_func2)));       // NOLINT
                static_assert(!noexcept(for_each(array, 6, test_func2)));    // NOLINT
            };
        };
    };

    bsl::ut_scenario{"noexcept"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                      // NOLINT
            bsl::ut_then{} = []() {                                         // NOLINT
                static_assert(noexcept(for_each(array, test_func1)));       // NOLINT
                static_assert(noexcept(for_each(array, 6, test_func1)));    // NOLINT
            };
        };
    };

    return bsl::ut_success();
}
