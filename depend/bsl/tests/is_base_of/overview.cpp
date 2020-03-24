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

#include <bsl/is_base_of.hpp>
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

    static_assert(is_base_of<myclass_base, myclass_subclass>::value);
    static_assert(is_base_of<myclass_base const, myclass_subclass>::value);
    static_assert(is_base_of<myclass_subclass, myclass_subclass>::value);
    static_assert(is_base_of<myclass_subclass const, myclass_subclass>::value);

    static_assert(!is_base_of<bool, myclass_subclass>::value);
    static_assert(!is_base_of<bool const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int8, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int8 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int16, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int16 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int32, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int32 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int64, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int64 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_least8, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_least8 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_least16, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_least16 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_least32, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_least32 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_least64, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_least64 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_fast8, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_fast8 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_fast16, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_fast16 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_fast32, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_fast32 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_fast64, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::int_fast64 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::intptr, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::intptr const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::intmax, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::intmax const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint8, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint8 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint16, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint16 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint32, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint32 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint64, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint64 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_least8, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_least8 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_least16, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_least16 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_least32, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_least32 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_least64, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_least64 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_fast8, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_fast8 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_fast16, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_fast16 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_fast32, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_fast32 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_fast64, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uint_fast64 const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uintptr, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uintptr const, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uintmax, myclass_subclass>::value);
    static_assert(!is_base_of<bsl::uintmax const, myclass_subclass>::value);
    static_assert(!is_base_of<myclass, myclass_subclass>::value);
    static_assert(!is_base_of<myclass const, myclass_subclass>::value);
    static_assert(!is_base_of<mystruct, myclass_subclass>::value);
    static_assert(!is_base_of<mystruct const, myclass_subclass>::value);
    static_assert(!is_base_of<myunion, myclass_subclass>::value);
    static_assert(!is_base_of<myunion const, myclass_subclass>::value);
    static_assert(!is_base_of<myenum, myclass_subclass>::value);
    static_assert(!is_base_of<myenum const, myclass_subclass>::value);
    static_assert(!is_base_of<bool[], myclass_subclass>::value);              // NOLINT
    static_assert(!is_base_of<bool[1], myclass_subclass>::value);             // NOLINT
    static_assert(!is_base_of<bool[][1], myclass_subclass>::value);           // NOLINT
    static_assert(!is_base_of<bool[1][1], myclass_subclass>::value);          // NOLINT
    static_assert(!is_base_of<bool const[], myclass_subclass>::value);        // NOLINT
    static_assert(!is_base_of<bool const[1], myclass_subclass>::value);       // NOLINT
    static_assert(!is_base_of<bool const[][1], myclass_subclass>::value);     // NOLINT
    static_assert(!is_base_of<bool const[1][1], myclass_subclass>::value);    // NOLINT
    static_assert(!is_base_of<void, myclass_subclass>::value);
    static_assert(!is_base_of<void const, myclass_subclass>::value);
    static_assert(!is_base_of<void *, myclass_subclass>::value);
    static_assert(!is_base_of<void const *, myclass_subclass>::value);
    static_assert(!is_base_of<void *const, myclass_subclass>::value);
    static_assert(!is_base_of<void const *const, myclass_subclass>::value);
    static_assert(!is_base_of<bool &, myclass_subclass>::value);
    static_assert(!is_base_of<bool &&, myclass_subclass>::value);
    static_assert(!is_base_of<bool const &, myclass_subclass>::value);
    static_assert(!is_base_of<bool const &&, myclass_subclass>::value);
    static_assert(!is_base_of<bool(bool), myclass_subclass>::value);
    static_assert(!is_base_of<bool (*)(bool), myclass_subclass>::value);

    return bsl::ut_success();
}
