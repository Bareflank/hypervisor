//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <catch/catch.hpp>
#include <test_real_elf.h>

std::array<char, 0x8000>fake_stack{};

TEST_CASE("bfelf_loader_resolve_symbol: real test (list)")
{
    binaries_info binaries{&g_file, g_filenames};

    std::array<const char *, 2> argv{{"1000", "2000"}};
    binaries.set_args(gsl::narrow_cast<int>(argv.size()), argv.data());

    auto func = reinterpret_cast<_start_t>(binaries.entry());
    CHECK(func(&fake_stack.at(0x7999), &binaries.info()) == 6000);
}

TEST_CASE("bfelf_loader_resolve_symbol: real test (needed)")
{
    binaries_info binaries{&g_file, g_filenames.back(), {VMM_PREFIX_PATH + "/lib/"_s}};

    std::array<const char *, 2> argv{{"1000", "2000"}};
    binaries.set_args(gsl::narrow_cast<int>(argv.size()), argv.data());

    auto func = reinterpret_cast<_start_t>(binaries.entry());
    CHECK(func(&fake_stack.at(0x7999), &binaries.info()) == 6000);
}
