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

#include <bsl/invoke.hpp>
#include <bsl/reference_wrapper.hpp>

#include <bsl/ut.hpp>

namespace
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-member-function"

    [[nodiscard]] constexpr bool
    test_func(bool val)
    {
        return val;
    }

    class test_base
    {
    public:
        constexpr test_base() noexcept = default;

        [[nodiscard]] constexpr bool
        operator()(bool val) const
        {
            return val;
        }

        bsl::int32 data{42};    // NOLINT
    };

    class test_final final : public test_base
    {
    public:
        constexpr test_final() noexcept = default;
    };

    class test_noexcept final
    {
    public:
        constexpr test_noexcept() noexcept = default;

        [[nodiscard]] constexpr bool
        operator()(bool val) const noexcept
        {
            return val;
        }

        bsl::int32 data{42};    // NOLINT
    };

    constexpr test_final g_test_final{};
    constexpr test_noexcept g_test_noexcept{};

    constexpr bsl::reference_wrapper<test_final const> g_rw_test_final{g_test_final};
    constexpr bsl::reference_wrapper<test_noexcept const> g_rw_test_noexcept{g_test_noexcept};

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

    // (1.1) If std::is_base_of<T, std::decay_t<decltype(t1)>>::value
    //       is true, then INVOKE(f, t1, t2, ..., tN) is equivalent to
    //       (t1.*f)(t2, ..., tN)
    static_assert(bsl::invoke(&test_base::operator(), g_test_final, true));
    static_assert(bsl::invoke(&test_final::operator(), g_test_final, true));
    static_assert(bsl::invoke(&test_noexcept::operator(), g_test_noexcept, true));

    // (1.2) If std::decay_t<decltype(t1)> is a specialization of
    //       std::reference_wrapper, then INVOKE(f, t1, t2, ..., tN) is
    //       equivalent to (t1.get().*f)(t2, ..., tN)
    static_assert(bsl::invoke(&test_base::operator(), g_rw_test_final, true));
    static_assert(bsl::invoke(&test_final::operator(), g_rw_test_final, true));
    static_assert(bsl::invoke(&test_noexcept::operator(), g_rw_test_noexcept, true));

    // (1.3) If t1 does not satisfy the previous items, then
    //       INVOKE(f, t1, t2, ..., tN) is equivalent to
    //       ((*t1).*f)(t2, ..., tN)
    static_assert(bsl::invoke(&test_base::operator(), &g_test_final, true));
    static_assert(bsl::invoke(&test_final::operator(), &g_test_final, true));
    static_assert(bsl::invoke(&test_noexcept::operator(), &g_test_noexcept, true));

    // (2.1) If std::is_base_of<T, std::decay_t<decltype(t1)>>::value is true,
    //       then INVOKE(f, t1) is equivalent to t1.*f
    static_assert(bsl::invoke(&test_base::data, g_test_final) == 42);
    static_assert(bsl::invoke(&test_final::data, g_test_final) == 42);
    static_assert(bsl::invoke(&test_noexcept::data, g_test_noexcept) == 42);

    // (2.2) If std::decay_t<decltype(t1)> is a specialization of
    //       std::reference_wrapper, then INVOKE(f, t1) is
    //       equivalent to t1.get().*f
    static_assert(bsl::invoke(&test_base::data, g_rw_test_final) == 42);
    static_assert(bsl::invoke(&test_final::data, g_rw_test_final) == 42);
    static_assert(bsl::invoke(&test_noexcept::data, g_rw_test_noexcept) == 42);

    // (2.3) If t1 does not satisfy the previous items, then INVOKE(f, t1)
    //       is equivalent to (*t1).*f
    static_assert(bsl::invoke(&test_base::data, &g_test_final) == 42);
    static_assert(bsl::invoke(&test_final::data, &g_test_final) == 42);
    static_assert(bsl::invoke(&test_noexcept::data, &g_test_noexcept) == 42);

    // (3.1) Otherwise, INVOKE(f, t1, t2, ..., tN) is equivalent to
    //       f(t1, t2, ..., tN)
    static_assert(bsl::invoke(&test_func, true));

    return bsl::ut_success();
}
