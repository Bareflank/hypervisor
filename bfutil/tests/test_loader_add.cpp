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

#include <catch/catch.hpp>

#include <list>
#include <test_real_elf.h>
#include <test_fake_elf.h>

char dummy[10];

TEST_CASE("bfelf_loader_add: invalid loader")
{
    bfelf_file_t dummy_misc_ef = {};

    auto ret = bfelf_loader_add(nullptr, &dummy_misc_ef, static_cast<char *>(dummy), static_cast<char *>(dummy));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_add: invalid elf file")
{
    bfelf_loader_t loader = {};

    auto ret = bfelf_loader_add(&loader, nullptr, static_cast<char *>(dummy), static_cast<char *>(dummy));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_add: invalid addr")
{
    bfelf_loader_t loader = {};
    bfelf_file_t dummy_misc_ef = {};

    auto ret = bfelf_loader_add(&loader, &dummy_misc_ef, nullptr, static_cast<char *>(dummy));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_add: add twice")
{
    int64_t ret = 0;
    bfelf_loader_t loader = {};
    bfelf_file_t dummy_misc_ef = {};

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, static_cast<char *>(dummy), static_cast<char *>(dummy));
    CHECK(ret == BF_SUCCESS);

    ret = bfelf_loader_add(&loader, &dummy_misc_ef, static_cast<char *>(dummy), static_cast<char *>(dummy));
    CHECK(ret == BFELF_ERROR_INVALID_ARG);
}

TEST_CASE("bfelf_loader_add: too many files")
{
    bfelf_loader_t loader = {};
    std::vector<bfelf_file_t> efs(MAX_NUM_MODULES + 1);

    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);

    for (auto i = 0ULL; i < MAX_NUM_MODULES + 1; i++) {

        int64_t ret = 0;

        ret = bfelf_file_init(buf.get(), size, &gsl::at(efs, static_cast<std::ptrdiff_t>(i)));
        REQUIRE(ret == BFELF_SUCCESS);

        ret = bfelf_loader_add(
                  &loader,
                  &gsl::at(efs, static_cast<std::ptrdiff_t>(i)),
                  static_cast<char *>(dummy),
                  static_cast<char *>(dummy)
              );

        if (i < MAX_NUM_MODULES) {
            CHECK(ret == BF_SUCCESS);
        }
        else {
            CHECK(ret == BFELF_ERROR_LOADER_FULL);
        }
    }
}

TEST_CASE("bfelf_loader_add: add fake")
{
    int64_t ret = 0;
    bfelf_file_t ef = {};
    bfelf_loader_t loader = {};

    auto data = get_fake_elf();
    auto &buf = std::get<0>(data);
    auto size = std::get<1>(data);

    ret = bfelf_file_init(buf.get(), size, &ef);
    CHECK(ret == BFELF_SUCCESS);

    ret = bfelf_loader_add(&loader, &ef, static_cast<char *>(dummy), static_cast<char *>(dummy));
    CHECK(ret == BFELF_SUCCESS);
}
