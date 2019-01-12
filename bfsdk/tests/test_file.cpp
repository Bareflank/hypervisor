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

#include <hippomocks.h>
#include <catch/catch.hpp>

#include <bffile.h>
#include <bfstring.h>

#include <memory>

file g_file;

TEST_CASE("constructor / destructor")
{
    file f;
}

TEST_CASE("read with bad filename")
{
    std::string filename{"/blah/bad_filename.txt"};

    CHECK_THROWS(g_file.read_text(""));
    CHECK_THROWS(g_file.read_binary(""));

    CHECK_THROWS(g_file.read_text(filename));
    CHECK_THROWS(g_file.read_binary(filename));
}

TEST_CASE("write with bad filename")
{
    std::string filename{"/blah/bad_filename.txt"};

    std::string text_data{"hello"};
    bfn::buffer binary_data{'h', 'e', 'l', 'l', 'o'};

    CHECK_THROWS(g_file.write_text("", text_data));
    CHECK_THROWS(g_file.write_binary("", binary_data));

    CHECK_THROWS(g_file.write_text(filename, text_data));
    CHECK_THROWS(g_file.write_binary(filename, binary_data));
}

TEST_CASE("read / write success")
{
    std::string filename{"test.txt"};

    std::string text_data1{};
    std::string text_data2{"hello"};
    bfn::buffer binary_data1{};
    bfn::buffer binary_data2{'h', 'e', 'l', 'l', 'o'};

    REQUIRE_NOTHROW(g_file.write_text(filename, text_data1));
    CHECK(g_file.read_text(filename) == text_data1);

    REQUIRE_NOTHROW(g_file.write_binary(filename, binary_data1));
    CHECK(g_file.read_binary(filename) == binary_data1);

    REQUIRE_NOTHROW(g_file.write_text(filename, text_data2));
    CHECK(g_file.read_text(filename) == text_data2);

    REQUIRE_NOTHROW(g_file.write_binary(filename, binary_data2));
    CHECK(g_file.read_binary(filename) == binary_data2);

    REQUIRE(std::remove(filename.c_str()) == 0);
}

TEST_CASE("extension")
{
    CHECK(g_file.extension("").empty());
    CHECK(g_file.extension("no_extension").empty());
    CHECK(g_file.extension("no_extension.") == ".");
    CHECK(g_file.extension(".nofilename") == ".nofilename");
    CHECK(g_file.extension("no_path.ext") == ".ext");
    CHECK(g_file.extension("/with/path.ext") == ".ext");
    CHECK(g_file.extension("more.than.one.ext") == ".ext");
    CHECK(g_file.extension(R"(c:\windows\path.ext)") == ".ext");
}

TEST_CASE("exists")
{
    std::string filename{"test.txt"};

    CHECK(!g_file.exists(""));
    CHECK(!g_file.exists(filename));

    REQUIRE_NOTHROW(g_file.write_text(filename, "hello world"));
    CHECK(g_file.exists(filename));

    REQUIRE(std::remove(filename.c_str()) == 0);

    CHECK(!g_file.exists(filename));
}

TEST_CASE("find files")
{
    auto files = {"test1.txt"_s, "test2.txt"_s};
    auto paths = {"../bad/path"_s, "."_s};

    CHECK_NOTHROW(g_file.find_files({}, paths));
    CHECK_THROWS(g_file.find_files(files, {}));

    CHECK_THROWS(g_file.find_files(files, {"../file_not_found"_s}));

    for (const auto &file : files) {
        REQUIRE_NOTHROW(g_file.write_text(file, "hello world"));
    }

    auto results = g_file.find_files(files, paths);

    REQUIRE(results.size() == files.size());
    CHECK(results.at(0) == "./test1.txt");
    CHECK(results.at(1) == "./test2.txt");

    for (const auto &file : files) {
        REQUIRE(std::remove(file.c_str()) == 0);
    }
}

TEST_CASE("file size")
{
    std::string filename{"test.txt"};

    std::string text_data{"hello"};
    bfn::buffer binary_data{'h', 'e', 'l', 'l', 'o'};

    CHECK_THROWS(g_file.size(""));
    CHECK_THROWS(g_file.size("bad_filename"));

    REQUIRE_NOTHROW(g_file.write_text(filename, text_data));
    CHECK(g_file.size(filename) == 5);

    REQUIRE_NOTHROW(g_file.write_binary(filename, binary_data));
    CHECK(g_file.size(filename) == 5);

    REQUIRE(std::remove(filename.c_str()) == 0);
}

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("home")
{
    auto home = std::make_unique<char[]>(256);
    auto homepath = std::make_unique<char[]>(256);

    std::strncpy(home.get(), "home", 256);
    std::strncpy(homepath.get(), "homepath", 256);

    MockRepository mocks;

    mocks.OnCallFunc(std::getenv).Do([&](auto var) {
        if (std::string(var) == "HOME") {
            return static_cast<char *>(nullptr);
        }
        return homepath.get();
    });
    CHECK(g_file.home() == "homepath");

    mocks.OnCallFunc(std::getenv).Do([&](auto) {
        return home.get();
    });
    CHECK(g_file.home() == "home");

    mocks.OnCallFunc(std::getenv).Do([&](auto) {
        return static_cast<char *>(nullptr);
    });
    CHECK_THROWS(g_file.home());
}

#endif
