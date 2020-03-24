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

#include <bsl/is_nothrow_invocable_r.hpp>
#include <bsl/reference_wrapper.hpp>

#include <bsl/ut.hpp>

namespace
{
    class test_base
    {
    public:
        bsl::int32 data{42};    // NOLINT
    };

    class test_final final : public test_base
    {};

    class test_noexcept final
    {
    public:
        bsl::int32 data{42};    // NOLINT
    };
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

    // clang-format off

    // (1.1) If std::is_base_of<T, std::decay_t<decltype(t1)>>::value
    //       is true, then INVOKE(f, t1, t2, ..., tN) is equivalent to
    //       (t1.*f)(t2, ..., tN)
    static_assert(!is_nothrow_invocable_r<bool(), bool (test_base::*)(), test_final>::value);
    static_assert(!is_nothrow_invocable_r<bool(), bool (test_final::*)(), test_final>::value);
    static_assert(is_nothrow_invocable_r<bool(), bool (test_noexcept::*)() noexcept, test_noexcept>::value);

    // (1.2) If std::decay_t<decltype(t1)> is a specialization of
    //       std::reference_wrapper, then INVOKE(f, t1, t2, ..., tN) is
    //       equivalent to (t1.get().*f)(t2, ..., tN)
    static_assert(!is_nothrow_invocable_r<bool(), bool (test_base::*)(), reference_wrapper<test_final>>::value);
    static_assert(!is_nothrow_invocable_r<bool(), bool (test_final::*)(), reference_wrapper<test_final>>::value);
    static_assert(is_nothrow_invocable_r<bool(), bool (test_noexcept::*)() noexcept, reference_wrapper<test_noexcept>>::value);

    // (1.3) If t1 does not satisfy the previous items, then
    //       INVOKE(f, t1, t2, ..., tN) is equivalent to
    //       ((*t1).*f)(t2, ..., tN)
    static_assert(!is_nothrow_invocable_r<bool(), bool (test_base::*)(), test_final *>::value);
    static_assert(!is_nothrow_invocable_r<bool(), bool (test_final::*)(), test_final *>::value);
    static_assert(is_nothrow_invocable_r<bool(), bool (test_noexcept::*)() noexcept, test_noexcept *>::value);

    // (2.1) If std::is_base_of<T, std::decay_t<decltype(t1)>>::value is true,
    //       then INVOKE(f, t1) is equivalent to t1.*f
    static_assert(is_nothrow_invocable_r<bsl::int32 &&, decltype(&test_base::data), test_final>::value);
    static_assert(is_nothrow_invocable_r<bsl::int32 &&, decltype(&test_final::data), test_final>::value);
    static_assert(is_nothrow_invocable_r<bsl::int32 &&, decltype(&test_noexcept::data), test_noexcept>::value);

    // (2.2) If std::decay_t<decltype(t1)> is a specialization of
    //       std::reference_wrapper, then INVOKE(f, t1) is
    //       equivalent to t1.get().*f
    static_assert(is_nothrow_invocable_r<bsl::int32 &, decltype(&test_base::data), reference_wrapper<test_final>>::value);
    static_assert(is_nothrow_invocable_r<bsl::int32 &, decltype(&test_final::data), reference_wrapper<test_final>>::value);
    static_assert(is_nothrow_invocable_r<bsl::int32 &, decltype(&test_noexcept::data), reference_wrapper<test_noexcept>>::value);

    // (2.3) If t1 does not satisfy the previous items, then INVOKE(f, t1)
    //       is equivalent to (*t1).*f
    static_assert(is_nothrow_invocable_r<bsl::int32 &, decltype(&test_base::data), test_final *>::value);
    static_assert(is_nothrow_invocable_r<bsl::int32 &, decltype(&test_final::data), test_final *>::value);
    static_assert(is_nothrow_invocable_r<bsl::int32 &, decltype(&test_noexcept::data), test_noexcept *>::value);

    // (3.1) Otherwise, INVOKE(f, t1, t2, ..., tN) is equivalent to
    //       f(t1, t2, ..., tN)
    static_assert(!is_nothrow_invocable_r<bool (), bool ()>::value);
    static_assert(is_nothrow_invocable_r<bool (), bool () noexcept>::value);

    // clang-format on

    return bsl::ut_success();
}
