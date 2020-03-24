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

#include <bsl/move_if_noexcept.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunneeded-member-function"
#pragma clang diagnostic ignored "-Wunused-member-function"

    bool g_moved{};

    class myclass final
    {
    public:
        constexpr myclass() noexcept = default;
        ~myclass() noexcept = default;
        constexpr myclass(myclass const &) noexcept = default;
        constexpr myclass &operator=(myclass const &) &noexcept = default;

        myclass(myclass &&o) noexcept
        {
            bsl::discard(o);
            g_moved = true;
        }

        myclass &
            operator=(myclass &&o) &
            noexcept
        {
            bsl::discard(o);
            g_moved = true;

            return *this;
        }
    };

    class myclass_move_except final
    {
    public:
        constexpr myclass_move_except() noexcept = default;
        ~myclass_move_except() noexcept = default;
        constexpr myclass_move_except(myclass_move_except const &) noexcept = default;
        constexpr myclass_move_except &operator=(myclass_move_except const &) &noexcept = default;

        myclass_move_except(myclass_move_except &&o) noexcept(false)
        {
            bsl::discard(o);
            g_moved = true;
        }

        myclass_move_except &
            operator=(myclass_move_except &&o) &
            noexcept(false)
        {
            bsl::discard(o);
            g_moved = true;

            return *this;
        }
    };

    class myclass_move_except_nocopy final
    {
    public:
        constexpr myclass_move_except_nocopy() noexcept = default;
        ~myclass_move_except_nocopy() noexcept = default;
        constexpr myclass_move_except_nocopy(myclass_move_except_nocopy const &) noexcept = delete;
        constexpr myclass_move_except_nocopy &
        operator=(myclass_move_except_nocopy const &) &noexcept = delete;

        myclass_move_except_nocopy(myclass_move_except_nocopy &&o) noexcept
        {
            bsl::discard(o);
            g_moved = true;
        }

        myclass_move_except_nocopy &
            operator=(myclass_move_except_nocopy &&o) &
            noexcept
        {
            bsl::discard(o);
            g_moved = true;

            return *this;
        }
    };

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
    bsl::set_ut_reset_handler([]() {
        g_moved = false;
    });

    bsl::ut_scenario{"moves"} = []() {
        bsl::ut_given{} = []() {
            myclass c1{};
            bsl::ut_when{} = [&c1]() {
                myclass c2{bsl::move_if_noexcept(c1)};
                bsl::discard(c2);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_moved);
                };
            };
        };
    };

    bsl::ut_scenario{"copies due to noexcept move constructor"} = []() {
        bsl::ut_given{} = []() {
            myclass_move_except c1{};
            bsl::ut_when{} = [&c1]() {
                myclass_move_except c2{bsl::move_if_noexcept(c1)};
                bsl::discard(c2);
                bsl::ut_then{} = []() {
                    bsl::ut_check(!g_moved);
                };
            };
        };
    };

    bsl::ut_scenario{"copies due to missing copy constructor"} = []() {
        bsl::ut_given{} = []() {
            myclass_move_except_nocopy c1{};
            bsl::ut_when{} = [&c1]() {
                myclass_move_except_nocopy c2{bsl::move_if_noexcept(c1)};
                bsl::discard(c2);
                bsl::ut_then{} = []() {
                    bsl::ut_check(g_moved);
                };
            };
        };
    };

    return bsl::ut_success();
}
