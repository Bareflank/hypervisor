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
#include <hippomocks.h>

#include <bftypes.h>
#include <bfmanager.h>

auto factory_throws = false;
auto factory_nullptr = false;

class not_a_test_base
{
public:
    not_a_test_base() = default;
    virtual ~not_a_test_base() = default;
};

class test_base
{
public:
    test_base() = default;
    virtual ~test_base() = default;
};

class test : public test_base
{
public:

    test() = default;
    ~test() override = default;

    using id_t = uint64_t;
};

class test_factory
{
public:
    std::unique_ptr<test>
    make(test::id_t id, void *obj)
    {
        bfignored(id);
        bfignored(obj);

        if (factory_throws) {
            throw std::runtime_error("error");
        }

        if (factory_nullptr) {
            return nullptr;
        }

        return std::make_unique<test>();
    }
};

#define g_test_manager bfmanager<test, test_factory, test::id_t>::instance()

TEST_CASE("test_manager: support")
{
    test_factory factory{};
    CHECK_NOTHROW(factory.make(0, nullptr));
}

TEST_CASE("test_manager: create_valid")
{
    CHECK_NOTHROW(g_test_manager->create(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: factory_throws")
{
    factory_throws = true;
    auto ___ = gsl::finally([&] {
        factory_throws = false;
    });

    CHECK_THROWS(g_test_manager->create(0));
}

TEST_CASE("test_manager: factory_nullptr")
{
    factory_nullptr = true;
    auto ___ = gsl::finally([&] {
        factory_nullptr = false;
    });

    CHECK_THROWS(g_test_manager->create(0));
}

TEST_CASE("test_manager: delete_valid")
{
    g_test_manager->create(0);
    CHECK_NOTHROW(g_test_manager->destroy(0));
}

TEST_CASE("test_manager: delete_valid_twice")
{
    g_test_manager->create(0);
    CHECK_NOTHROW(g_test_manager->destroy(0));
}

TEST_CASE("test_manager: get without creating")
{
    CHECK_THROWS(g_test_manager->get(0));
}

TEST_CASE("test_manager: get without creating with custom string")
{
    CHECK_THROWS(g_test_manager->get(0, "unable to find"));
}

TEST_CASE("test_manager: get success")
{
    g_test_manager->create(0);
    CHECK_NOTHROW(g_test_manager->get(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: get success custom type")
{
    g_test_manager->create(0);
    CHECK_NOTHROW(g_test_manager->get<test_base *>(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: get invalid type")
{
    not_a_test_base{};

    g_test_manager->create(0);
    CHECK_THROWS(g_test_manager->get<not_a_test_base *>(0));
    g_test_manager->destroy(0);
}
