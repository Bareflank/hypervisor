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

#include <bsl/is_trivially_move_assignable.hpp>
#include <bsl/ut.hpp>

namespace
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-member-function"

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

    class myclass_copy_only final
    {
    public:
        constexpr myclass_copy_only() noexcept = default;
        ~myclass_copy_only() noexcept = default;
        constexpr myclass_copy_only(myclass_copy_only const &) noexcept = default;
        constexpr myclass_copy_only &operator=(myclass_copy_only const &) &noexcept = default;
        constexpr myclass_copy_only(myclass_copy_only &&) noexcept = delete;
        constexpr myclass_copy_only &operator=(myclass_copy_only &&) &noexcept = delete;
    };

    class myclass_move_only final
    {
    public:
        constexpr myclass_move_only() noexcept = default;
        ~myclass_move_only() noexcept = default;
        constexpr myclass_move_only(myclass_move_only const &) noexcept = delete;
        constexpr myclass_move_only &operator=(myclass_move_only const &) &noexcept = delete;
        constexpr myclass_move_only(myclass_move_only &&) noexcept = default;
        constexpr myclass_move_only &operator=(myclass_move_only &&) &noexcept = default;
    };

    class myclass_no_assign final
    {
    public:
        constexpr myclass_no_assign() noexcept = default;
        ~myclass_no_assign() noexcept = default;
        constexpr myclass_no_assign(myclass_no_assign const &) noexcept = delete;
        constexpr myclass_no_assign &operator=(myclass_no_assign const &) &noexcept = delete;
        constexpr myclass_no_assign(myclass_no_assign &&) noexcept = delete;
        constexpr myclass_no_assign &operator=(myclass_no_assign &&) &noexcept = delete;
    };

    class myclass_except final
    {
    public:
        constexpr myclass_except() noexcept(false) = default;
        ~myclass_except() noexcept(false) = default;
        constexpr myclass_except(myclass_except const &) noexcept(false) = delete;
        constexpr myclass_except &operator=(myclass_except const &) & noexcept(false) = delete;
        constexpr myclass_except(myclass_except &&) noexcept(false) = delete;
        constexpr myclass_except &operator=(myclass_except &&) & noexcept(false) = delete;
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

    static_assert(is_trivially_move_assignable<bool>::value);
    static_assert(is_trivially_move_assignable<bsl::int8>::value);
    static_assert(is_trivially_move_assignable<bsl::int16>::value);
    static_assert(is_trivially_move_assignable<bsl::int32>::value);
    static_assert(is_trivially_move_assignable<bsl::int64>::value);
    static_assert(is_trivially_move_assignable<bsl::int_least8>::value);
    static_assert(is_trivially_move_assignable<bsl::int_least16>::value);
    static_assert(is_trivially_move_assignable<bsl::int_least32>::value);
    static_assert(is_trivially_move_assignable<bsl::int_least64>::value);
    static_assert(is_trivially_move_assignable<bsl::int_fast8>::value);
    static_assert(is_trivially_move_assignable<bsl::int_fast16>::value);
    static_assert(is_trivially_move_assignable<bsl::int_fast32>::value);
    static_assert(is_trivially_move_assignable<bsl::int_fast64>::value);
    static_assert(is_trivially_move_assignable<bsl::intptr>::value);
    static_assert(is_trivially_move_assignable<bsl::intmax>::value);
    static_assert(is_trivially_move_assignable<bsl::uint8>::value);
    static_assert(is_trivially_move_assignable<bsl::uint16>::value);
    static_assert(is_trivially_move_assignable<bsl::uint32>::value);
    static_assert(is_trivially_move_assignable<bsl::uint64>::value);
    static_assert(is_trivially_move_assignable<bsl::uint_least8>::value);
    static_assert(is_trivially_move_assignable<bsl::uint_least16>::value);
    static_assert(is_trivially_move_assignable<bsl::uint_least32>::value);
    static_assert(is_trivially_move_assignable<bsl::uint_least64>::value);
    static_assert(is_trivially_move_assignable<bsl::uint_fast8>::value);
    static_assert(is_trivially_move_assignable<bsl::uint_fast16>::value);
    static_assert(is_trivially_move_assignable<bsl::uint_fast32>::value);
    static_assert(is_trivially_move_assignable<bsl::uint_fast64>::value);
    static_assert(is_trivially_move_assignable<bsl::uintptr>::value);
    static_assert(is_trivially_move_assignable<bsl::uintmax>::value);
    static_assert(is_trivially_move_assignable<myclass>::value);
    static_assert(is_trivially_move_assignable<mystruct>::value);
    static_assert(is_trivially_move_assignable<myunion>::value);
    static_assert(is_trivially_move_assignable<myenum>::value);
    static_assert(is_trivially_move_assignable<myclass_base>::value);
    static_assert(is_trivially_move_assignable<myclass_subclass>::value);
    static_assert(is_trivially_move_assignable<void *>::value);
    static_assert(is_trivially_move_assignable<void const *>::value);
    static_assert(is_trivially_move_assignable<bool &>::value);
    static_assert(is_trivially_move_assignable<bool &&>::value);
    static_assert(is_trivially_move_assignable<bool (*)(bool)>::value);
    static_assert(is_trivially_move_assignable<myclass_move_only>::value);

    static_assert(!is_trivially_move_assignable<bool const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int8 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int16 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int32 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int64 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int_least8 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int_least16 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int_least32 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int_least64 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int_fast8 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int_fast16 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int_fast32 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::int_fast64 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::intptr const>::value);
    static_assert(!is_trivially_move_assignable<bsl::intmax const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint8 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint16 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint32 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint64 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint_least8 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint_least16 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint_least32 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint_least64 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint_fast8 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint_fast16 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint_fast32 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uint_fast64 const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uintptr const>::value);
    static_assert(!is_trivially_move_assignable<bsl::uintmax const>::value);
    static_assert(!is_trivially_move_assignable<myclass_abstract>::value);
    static_assert(!is_trivially_move_assignable<myclass_abstract const>::value);
    static_assert(!is_trivially_move_assignable<myclass const>::value);
    static_assert(!is_trivially_move_assignable<mystruct const>::value);
    static_assert(!is_trivially_move_assignable<myunion const>::value);
    static_assert(!is_trivially_move_assignable<myenum const>::value);
    static_assert(!is_trivially_move_assignable<myclass_base const>::value);
    static_assert(!is_trivially_move_assignable<myclass_subclass const>::value);
    static_assert(!is_trivially_move_assignable<bool[]>::value);              // NOLINT
    static_assert(!is_trivially_move_assignable<bool[1]>::value);             // NOLINT
    static_assert(!is_trivially_move_assignable<bool[][1]>::value);           // NOLINT
    static_assert(!is_trivially_move_assignable<bool[1][1]>::value);          // NOLINT
    static_assert(!is_trivially_move_assignable<bool const[]>::value);        // NOLINT
    static_assert(!is_trivially_move_assignable<bool const[1]>::value);       // NOLINT
    static_assert(!is_trivially_move_assignable<bool const[][1]>::value);     // NOLINT
    static_assert(!is_trivially_move_assignable<bool const[1][1]>::value);    // NOLINT
    static_assert(!is_trivially_move_assignable<void>::value);
    static_assert(!is_trivially_move_assignable<void const>::value);
    static_assert(!is_trivially_move_assignable<void *const>::value);
    static_assert(!is_trivially_move_assignable<void const *const>::value);
    static_assert(!is_trivially_move_assignable<bool const &>::value);
    static_assert(!is_trivially_move_assignable<bool const &&>::value);
    static_assert(!is_trivially_move_assignable<bool(bool)>::value);
    static_assert(!is_trivially_move_assignable<myclass_copy_only>::value);
    static_assert(!is_trivially_move_assignable<myclass_no_assign>::value);
    static_assert(!is_trivially_move_assignable<myclass_except>::value);

    return bsl::ut_success();
}
