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

#include <bsl/is_aggregate.hpp>
#include <bsl/discard.hpp>
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

    class myclass_nonaggregate1 final
    {
    public:
        [[nodiscard]] constexpr bool
        get() const noexcept
        {
            return private_non_static_data_memeber;
        }

    private:
        bool private_non_static_data_memeber;
    };

    class myclass_nonaggregate2 final
    {
    public:
        myclass_nonaggregate2()    // NOLINT
        {}
    };

    class myclass_nonaggregate3 final : protected myclass_base
    {};

    class myclass_nonaggregate4 final : private myclass_base
    {};

    class myclass_nonaggregate5 final : virtual myclass_base
    {};

    class myclass_nonaggregate6 final    // NOLINT
    {
    public:
        virtual ~myclass_nonaggregate6() noexcept = default;
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
    bsl::discard(myclass_nonaggregate1{}.get());
    bsl::discard(myclass_nonaggregate2{});

    static_assert(is_aggregate<myclass>::value);
    static_assert(is_aggregate<myclass const>::value);
    static_assert(is_aggregate<mystruct>::value);
    static_assert(is_aggregate<mystruct const>::value);
    static_assert(is_aggregate<myunion>::value);
    static_assert(is_aggregate<myunion const>::value);
    static_assert(is_aggregate<myclass_base>::value);
    static_assert(is_aggregate<myclass_base const>::value);
    static_assert(is_aggregate<myclass_subclass>::value);
    static_assert(is_aggregate<myclass_subclass const>::value);
    static_assert(is_aggregate<bool[]>::value);              // NOLINT
    static_assert(is_aggregate<bool[1]>::value);             // NOLINT
    static_assert(is_aggregate<bool[][1]>::value);           // NOLINT
    static_assert(is_aggregate<bool[1][1]>::value);          // NOLINT
    static_assert(is_aggregate<bool const[]>::value);        // NOLINT
    static_assert(is_aggregate<bool const[1]>::value);       // NOLINT
    static_assert(is_aggregate<bool const[][1]>::value);     // NOLINT
    static_assert(is_aggregate<bool const[1][1]>::value);    // NOLINT

    static_assert(!is_aggregate<bool>::value);
    static_assert(!is_aggregate<bool const>::value);
    static_assert(!is_aggregate<bsl::int8>::value);
    static_assert(!is_aggregate<bsl::int8 const>::value);
    static_assert(!is_aggregate<bsl::int16>::value);
    static_assert(!is_aggregate<bsl::int16 const>::value);
    static_assert(!is_aggregate<bsl::int32>::value);
    static_assert(!is_aggregate<bsl::int32 const>::value);
    static_assert(!is_aggregate<bsl::int64>::value);
    static_assert(!is_aggregate<bsl::int64 const>::value);
    static_assert(!is_aggregate<bsl::int_least8>::value);
    static_assert(!is_aggregate<bsl::int_least8 const>::value);
    static_assert(!is_aggregate<bsl::int_least16>::value);
    static_assert(!is_aggregate<bsl::int_least16 const>::value);
    static_assert(!is_aggregate<bsl::int_least32>::value);
    static_assert(!is_aggregate<bsl::int_least32 const>::value);
    static_assert(!is_aggregate<bsl::int_least64>::value);
    static_assert(!is_aggregate<bsl::int_least64 const>::value);
    static_assert(!is_aggregate<bsl::int_fast8>::value);
    static_assert(!is_aggregate<bsl::int_fast8 const>::value);
    static_assert(!is_aggregate<bsl::int_fast16>::value);
    static_assert(!is_aggregate<bsl::int_fast16 const>::value);
    static_assert(!is_aggregate<bsl::int_fast32>::value);
    static_assert(!is_aggregate<bsl::int_fast32 const>::value);
    static_assert(!is_aggregate<bsl::int_fast64>::value);
    static_assert(!is_aggregate<bsl::int_fast64 const>::value);
    static_assert(!is_aggregate<bsl::intptr>::value);
    static_assert(!is_aggregate<bsl::intptr const>::value);
    static_assert(!is_aggregate<bsl::intmax>::value);
    static_assert(!is_aggregate<bsl::intmax const>::value);
    static_assert(!is_aggregate<bsl::uint8>::value);
    static_assert(!is_aggregate<bsl::uint8 const>::value);
    static_assert(!is_aggregate<bsl::uint16>::value);
    static_assert(!is_aggregate<bsl::uint16 const>::value);
    static_assert(!is_aggregate<bsl::uint32>::value);
    static_assert(!is_aggregate<bsl::uint32 const>::value);
    static_assert(!is_aggregate<bsl::uint64>::value);
    static_assert(!is_aggregate<bsl::uint64 const>::value);
    static_assert(!is_aggregate<bsl::uint_least8>::value);
    static_assert(!is_aggregate<bsl::uint_least8 const>::value);
    static_assert(!is_aggregate<bsl::uint_least16>::value);
    static_assert(!is_aggregate<bsl::uint_least16 const>::value);
    static_assert(!is_aggregate<bsl::uint_least32>::value);
    static_assert(!is_aggregate<bsl::uint_least32 const>::value);
    static_assert(!is_aggregate<bsl::uint_least64>::value);
    static_assert(!is_aggregate<bsl::uint_least64 const>::value);
    static_assert(!is_aggregate<bsl::uint_fast8>::value);
    static_assert(!is_aggregate<bsl::uint_fast8 const>::value);
    static_assert(!is_aggregate<bsl::uint_fast16>::value);
    static_assert(!is_aggregate<bsl::uint_fast16 const>::value);
    static_assert(!is_aggregate<bsl::uint_fast32>::value);
    static_assert(!is_aggregate<bsl::uint_fast32 const>::value);
    static_assert(!is_aggregate<bsl::uint_fast64>::value);
    static_assert(!is_aggregate<bsl::uint_fast64 const>::value);
    static_assert(!is_aggregate<bsl::uintptr>::value);
    static_assert(!is_aggregate<bsl::uintptr const>::value);
    static_assert(!is_aggregate<bsl::uintmax>::value);
    static_assert(!is_aggregate<bsl::uintmax const>::value);
    static_assert(!is_aggregate<myenum>::value);
    static_assert(!is_aggregate<myenum const>::value);
    static_assert(!is_aggregate<myclass_abstract>::value);
    static_assert(!is_aggregate<myclass_abstract const>::value);
    static_assert(!is_aggregate<void>::value);
    static_assert(!is_aggregate<void const>::value);
    static_assert(!is_aggregate<void *>::value);
    static_assert(!is_aggregate<void const *>::value);
    static_assert(!is_aggregate<void *const>::value);
    static_assert(!is_aggregate<void const *const>::value);
    static_assert(!is_aggregate<bool &>::value);
    static_assert(!is_aggregate<bool &&>::value);
    static_assert(!is_aggregate<bool const &>::value);
    static_assert(!is_aggregate<bool const &&>::value);
    static_assert(!is_aggregate<bool(bool)>::value);
    static_assert(!is_aggregate<bool (*)(bool)>::value);
    static_assert(!is_aggregate<myclass_nonaggregate1>::value);
    static_assert(!is_aggregate<myclass_nonaggregate2>::value);
    static_assert(!is_aggregate<myclass_nonaggregate3>::value);
    static_assert(!is_aggregate<myclass_nonaggregate4>::value);
    static_assert(!is_aggregate<myclass_nonaggregate5>::value);
    static_assert(!is_aggregate<myclass_nonaggregate6>::value);

    return bsl::ut_success();
}
