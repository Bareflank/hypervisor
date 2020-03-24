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

#include <bsl/swap.hpp>
#include <bsl/ut.hpp>

namespace
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunneeded-member-function"

    class myclass1 final
    {
    public:
        constexpr myclass1() noexcept = default;
        ~myclass1() noexcept = default;
        constexpr myclass1(myclass1 const &) noexcept = default;
        constexpr myclass1 &operator=(myclass1 const &) &noexcept = default;
        constexpr myclass1(myclass1 &&) noexcept = default;
        constexpr myclass1 &operator=(myclass1 &&) &noexcept = default;

        explicit constexpr myclass1(bool val) noexcept : data{val}
        {}

        bool data{};    // NOLINT
    };

    class myclass2 final
    {
    public:
        constexpr myclass2() noexcept = default;
        ~myclass2() noexcept = default;
        constexpr myclass2(myclass2 const &) noexcept = default;
        constexpr myclass2 &operator=(myclass2 const &) &noexcept = default;
        constexpr myclass2(myclass2 &&) noexcept(false) = default;
        constexpr myclass2 &operator=(myclass2 &&) &noexcept = default;

        explicit constexpr myclass2(bool val) noexcept : data{val}
        {}

        bool data{};    // NOLINT
    };

    class myclass3 final
    {
    public:
        constexpr myclass3() noexcept = default;
        ~myclass3() noexcept = default;
        constexpr myclass3(myclass3 const &) noexcept = default;
        constexpr myclass3 &operator=(myclass3 const &) &noexcept = default;
        constexpr myclass3(myclass3 &&) noexcept = default;
        constexpr myclass3 &operator=(myclass3 &&) & noexcept(false) = default;

        explicit constexpr myclass3(bool val) noexcept : data{val}
        {}

        bool data{};    // NOLINT
    };

    class myclass4 final
    {
    public:
        constexpr myclass4() noexcept = default;
        ~myclass4() noexcept = default;
        constexpr myclass4(myclass4 const &) noexcept = default;
        constexpr myclass4 &operator=(myclass4 const &) &noexcept = default;
        constexpr myclass4(myclass4 &&) noexcept(false) = default;
        constexpr myclass4 &operator=(myclass4 &&) & noexcept(false) = default;

        explicit constexpr myclass4(bool val) noexcept : data{val}
        {}

        bool data{};    // NOLINT
    };

    [[nodiscard]] constexpr bool
    test_bool() noexcept
    {
        bool val1{};
        bool val2{true};

        bsl::swap(val1, val2);
        static_assert(noexcept(bsl::swap(val1, val2)));

        return true;
    }

    [[nodiscard]] constexpr bool
    test_myclass1() noexcept
    {
        myclass1 val1{};
        myclass1 val2{true};

        bsl::swap(val1, val2);
        static_assert(noexcept(bsl::swap(val1, val2)));

        return val1.data;
    }

    [[nodiscard]] constexpr bool
    test_myclass2() noexcept
    {
        myclass2 val1{};
        myclass2 val2{true};

        bsl::swap(val1, val2);
        static_assert(!noexcept(bsl::swap(val1, val2)));

        return val1.data;
    }

    [[nodiscard]] constexpr bool
    test_myclass3() noexcept
    {
        myclass3 val1{};
        myclass3 val2{true};

        bsl::swap(val1, val2);
        static_assert(!noexcept(bsl::swap(val1, val2)));

        return val1.data;
    }

    [[nodiscard]] constexpr bool
    test_myclass4() noexcept
    {
        myclass4 val1{};
        myclass4 val2{true};

        bsl::swap(val1, val2);
        static_assert(!noexcept(bsl::swap(val1, val2)));

        return val1.data;
    }

#pragma clang diagnostic push
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

    static_assert(test_bool());
    static_assert(test_myclass1());
    static_assert(test_myclass2());
    static_assert(test_myclass3());
    static_assert(test_myclass4());

    return bsl::ut_success();
}
