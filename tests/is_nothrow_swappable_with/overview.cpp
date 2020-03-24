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

#include <bsl/is_nothrow_swappable_with.hpp>
#include <bsl/ut.hpp>

namespace
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunneeded-internal-declaration"

    struct mystruct1 final
    {};

    struct mystruct2 final
    {};

    struct mystruct3 final
    {};

    struct mystruct4 final
    {};

    void swap(mystruct1, mystruct1) noexcept;
    void swap(mystruct1, mystruct2) noexcept;
    void swap(mystruct2, mystruct1) noexcept;

    void swap(mystruct3, mystruct3) noexcept = delete;
    void swap(mystruct3, mystruct4);
    void swap(mystruct4, mystruct3);
    void swap(mystruct1, mystruct3) noexcept;

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

    static_assert(is_nothrow_swappable_with<bool &, bool &>::value);
    static_assert(is_nothrow_swappable_with<mystruct1, mystruct1>::value);
    static_assert(is_nothrow_swappable_with<mystruct1, mystruct1 const>::value);
    static_assert(is_nothrow_swappable_with<mystruct2, mystruct1>::value);
    static_assert(is_nothrow_swappable_with<mystruct2, mystruct1 const>::value);
    static_assert(is_nothrow_swappable_with<mystruct1, mystruct2>::value);
    static_assert(is_nothrow_swappable_with<mystruct1, mystruct2 const>::value);

    static_assert(!is_nothrow_swappable_with<bool &, bool const &>::value);
    static_assert(!is_nothrow_swappable_with<mystruct3, mystruct3>::value);
    static_assert(!is_nothrow_swappable_with<mystruct3, mystruct3 const>::value);
    static_assert(!is_nothrow_swappable_with<mystruct4, mystruct3>::value);
    static_assert(!is_nothrow_swappable_with<mystruct4, mystruct3 const>::value);
    static_assert(!is_nothrow_swappable_with<mystruct3, mystruct4>::value);
    static_assert(!is_nothrow_swappable_with<mystruct3, mystruct4 const>::value);
    static_assert(!is_nothrow_swappable_with<mystruct1, mystruct3>::value);
    static_assert(!is_nothrow_swappable_with<mystruct1, mystruct3 const>::value);
    static_assert(!is_nothrow_swappable_with<mystruct3, mystruct1>::value);
    static_assert(!is_nothrow_swappable_with<mystruct3, mystruct1 const>::value);
    static_assert(!is_nothrow_swappable_with<mystruct2, mystruct3>::value);
    static_assert(!is_nothrow_swappable_with<mystruct2, mystruct3 const>::value);
    static_assert(!is_nothrow_swappable_with<mystruct3, mystruct2>::value);
    static_assert(!is_nothrow_swappable_with<mystruct3, mystruct2 const>::value);

    return bsl::ut_success();
}
