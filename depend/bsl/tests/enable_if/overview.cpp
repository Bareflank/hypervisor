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

#include <bsl/enable_if.hpp>
#include <bsl/discard.hpp>
#include <bsl/is_same.hpp>

#include <bsl/ut.hpp>

namespace
{
    /// <!-- description -->
    ///   @brief Returns true if T is a bool, false otherwise
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type to query
    ///   @return Returns true if T is a bool, false otherwise
    ///
    template<typename T, bsl::enable_if_t<bsl::is_same<T, bool>::value> = true>
    constexpr bool
    foo1() noexcept
    {
        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if T is a bool, false otherwise
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type to query
    ///   @return Returns true if T is a bool, false otherwise
    ///
    template<typename T, bsl::enable_if_t<!bsl::is_same<T, bool>::value> = true>
    constexpr bool
    foo1() noexcept
    {
        return false;
    }

    /// <!-- description -->
    ///   @brief Returns true if T is a bool, false otherwise
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type to query
    ///   @return Returns true if T is a bool, false otherwise
    ///
    template<typename T, bsl::enable_if_t<bsl::is_same<T, bool>::value> * = nullptr>
    constexpr bool
    foo2() noexcept
    {
        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if T is a bool, false otherwise
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type to query
    ///   @return Returns true if T is a bool, false otherwise
    ///
    template<typename T, bsl::enable_if_t<!bsl::is_same<T, bool>::value> * = nullptr>
    constexpr bool
    foo2() noexcept
    {
        return false;
    }

    /// <!-- description -->
    ///   @brief Returns true if T is a bool, false otherwise
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type to query
    ///   @return Returns true if T is a bool, false otherwise
    ///
    template<typename T, bsl::enable_if_t<bsl::is_same<T, bool>::value, bsl::int32> = 0>
    constexpr bool
    foo3() noexcept
    {
        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if T is a bool, false otherwise
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T The type to query
    ///   @return Returns true if T is a bool, false otherwise
    ///
    template<typename T, bsl::enable_if_t<!bsl::is_same<T, bool>::value, bsl::int32> = 0>
    constexpr bool
    foo3() noexcept
    {
        return false;
    }
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

    bsl::discard(foo1<bool>());
    bsl::discard(foo1<void>());
    bsl::discard(foo2<bool>());
    bsl::discard(foo2<void>());
    bsl::discard(foo3<bool>());
    bsl::discard(foo3<void>());

    bsl::ut_scenario{"enable_if with default bool T"} = []() {
        bsl::ut_given{} = []() {
            bool which{foo1<bool>()};
            bsl::ut_then{} = [&which]() {
                bsl::ut_check(which);
            };
        };
    };

    bsl::ut_scenario{"enable_if with default bool T as a pointer"} = []() {
        bsl::ut_given{} = []() {
            bool which{foo2<bool>()};
            bsl::ut_then{} = [&which]() {
                bsl::ut_check(which);
            };
        };
    };

    bsl::ut_scenario{"enable_if with bsl::int32 T"} = []() {
        bsl::ut_given{} = []() {
            bool which{foo3<bool>()};
            bsl::ut_then{} = [&which]() {
                bsl::ut_check(which);
            };
        };
    };

    return bsl::ut_success();
}
