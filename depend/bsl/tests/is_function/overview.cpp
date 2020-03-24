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

#include <bsl/is_function.hpp>
#include <bsl/ut.hpp>

namespace
{
    class myclass final
    {};

    struct mystruct final
    {};

    union myunion final
    {};

    enum class myenum : bsl::int32
    {
    };

    class myclass_abstract    // NOLINT
    {
    public:
        virtual ~myclass_abstract() noexcept = default;
        virtual void foo() noexcept = 0;
    };

    class myclass_base
    {};

    class myclass_subclass : public myclass_base
    {};
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

    static_assert(is_function<bool(bool)>::value);

    static_assert(!is_function<bool>::value);
    static_assert(!is_function<bool const>::value);
    static_assert(!is_function<bsl::int8>::value);
    static_assert(!is_function<bsl::int8 const>::value);
    static_assert(!is_function<bsl::int16>::value);
    static_assert(!is_function<bsl::int16 const>::value);
    static_assert(!is_function<bsl::int32>::value);
    static_assert(!is_function<bsl::int32 const>::value);
    static_assert(!is_function<bsl::int64>::value);
    static_assert(!is_function<bsl::int64 const>::value);
    static_assert(!is_function<bsl::int_least8>::value);
    static_assert(!is_function<bsl::int_least8 const>::value);
    static_assert(!is_function<bsl::int_least16>::value);
    static_assert(!is_function<bsl::int_least16 const>::value);
    static_assert(!is_function<bsl::int_least32>::value);
    static_assert(!is_function<bsl::int_least32 const>::value);
    static_assert(!is_function<bsl::int_least64>::value);
    static_assert(!is_function<bsl::int_least64 const>::value);
    static_assert(!is_function<bsl::int_fast8>::value);
    static_assert(!is_function<bsl::int_fast8 const>::value);
    static_assert(!is_function<bsl::int_fast16>::value);
    static_assert(!is_function<bsl::int_fast16 const>::value);
    static_assert(!is_function<bsl::int_fast32>::value);
    static_assert(!is_function<bsl::int_fast32 const>::value);
    static_assert(!is_function<bsl::int_fast64>::value);
    static_assert(!is_function<bsl::int_fast64 const>::value);
    static_assert(!is_function<bsl::intptr>::value);
    static_assert(!is_function<bsl::intptr const>::value);
    static_assert(!is_function<bsl::intmax>::value);
    static_assert(!is_function<bsl::intmax const>::value);
    static_assert(!is_function<bsl::uint8>::value);
    static_assert(!is_function<bsl::uint8 const>::value);
    static_assert(!is_function<bsl::uint16>::value);
    static_assert(!is_function<bsl::uint16 const>::value);
    static_assert(!is_function<bsl::uint32>::value);
    static_assert(!is_function<bsl::uint32 const>::value);
    static_assert(!is_function<bsl::uint64>::value);
    static_assert(!is_function<bsl::uint64 const>::value);
    static_assert(!is_function<bsl::uint_least8>::value);
    static_assert(!is_function<bsl::uint_least8 const>::value);
    static_assert(!is_function<bsl::uint_least16>::value);
    static_assert(!is_function<bsl::uint_least16 const>::value);
    static_assert(!is_function<bsl::uint_least32>::value);
    static_assert(!is_function<bsl::uint_least32 const>::value);
    static_assert(!is_function<bsl::uint_least64>::value);
    static_assert(!is_function<bsl::uint_least64 const>::value);
    static_assert(!is_function<bsl::uint_fast8>::value);
    static_assert(!is_function<bsl::uint_fast8 const>::value);
    static_assert(!is_function<bsl::uint_fast16>::value);
    static_assert(!is_function<bsl::uint_fast16 const>::value);
    static_assert(!is_function<bsl::uint_fast32>::value);
    static_assert(!is_function<bsl::uint_fast32 const>::value);
    static_assert(!is_function<bsl::uint_fast64>::value);
    static_assert(!is_function<bsl::uint_fast64 const>::value);
    static_assert(!is_function<bsl::uintptr>::value);
    static_assert(!is_function<bsl::uintptr const>::value);
    static_assert(!is_function<bsl::uintmax>::value);
    static_assert(!is_function<bsl::uintmax const>::value);
    static_assert(!is_function<myclass_abstract>::value);
    static_assert(!is_function<myclass_abstract const>::value);
    static_assert(!is_function<myclass>::value);
    static_assert(!is_function<myclass const>::value);
    static_assert(!is_function<mystruct>::value);
    static_assert(!is_function<mystruct const>::value);
    static_assert(!is_function<myunion>::value);
    static_assert(!is_function<myunion const>::value);
    static_assert(!is_function<myenum>::value);
    static_assert(!is_function<myenum const>::value);
    static_assert(!is_function<myclass_base>::value);
    static_assert(!is_function<myclass_base const>::value);
    static_assert(!is_function<myclass_subclass>::value);
    static_assert(!is_function<myclass_subclass const>::value);
    static_assert(!is_function<bool[]>::value);              // NOLINT
    static_assert(!is_function<bool[1]>::value);             // NOLINT
    static_assert(!is_function<bool[][1]>::value);           // NOLINT
    static_assert(!is_function<bool[1][1]>::value);          // NOLINT
    static_assert(!is_function<bool const[]>::value);        // NOLINT
    static_assert(!is_function<bool const[1]>::value);       // NOLINT
    static_assert(!is_function<bool const[][1]>::value);     // NOLINT
    static_assert(!is_function<bool const[1][1]>::value);    // NOLINT
    static_assert(!is_function<void>::value);
    static_assert(!is_function<void const>::value);
    static_assert(!is_function<void *>::value);
    static_assert(!is_function<void const *>::value);
    static_assert(!is_function<void *const>::value);
    static_assert(!is_function<void const *const>::value);
    static_assert(!is_function<bool &>::value);
    static_assert(!is_function<bool &&>::value);
    static_assert(!is_function<bool const &>::value);
    static_assert(!is_function<bool const &&>::value);
    static_assert(!is_function<bool (*)(bool)>::value);

    return bsl::ut_success();
}
