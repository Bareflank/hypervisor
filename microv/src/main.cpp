/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
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

#include <bsl/cstdint.hpp>
#include <bsl/climits.hpp>
#include <bsl/main.hpp>

extern "C"
{
    extern bsl::uintptr __stack_chk_guard;
    [[noreturn]] void __stack_chk_fail(void);

#if UINT32_MAX == UINTPTR_MAX
    bsl::uintptr __stack_chk_guard{0xBFBFBFBFU};
#else
    bsl::uintptr __stack_chk_guard{0xBFBFBFBFBFBFBFBFU};
#endif

    [[noreturn]] void
    __stack_chk_fail(void)
    {
        while(1);
    }
}

bsl::exit_code
main() noexcept
{
    return bsl::exit_success;
}
