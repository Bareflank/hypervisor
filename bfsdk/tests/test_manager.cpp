//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <bftypes.h>
#include <bfmanager.h>

auto factory_throws = false;
auto factory_nullptr = false;
auto init_throws = false;
auto fini_throws = false;
auto run_throws = false;
auto hlt_throws = false;

class test
{
public:

    using id_t = uint64_t;

    void init(bfobject *obj = nullptr)
    {
        bfignored(obj);

        if (init_throws) {
            throw std::runtime_error("error");
        }
    }

    void fini(bfobject *obj = nullptr)
    {
        bfignored(obj);

        if (fini_throws) {
            throw std::runtime_error("error");
        }
    }

    void run(bfobject *obj = nullptr)
    {
        bfignored(obj);

        if (run_throws) {
            throw std::runtime_error("error");
        }
    }

    void hlt(bfobject *obj = nullptr)
    {
        bfignored(obj);

        if (hlt_throws) {
            throw std::runtime_error("error");
        }
    }
};

class test_factory
{
public:
    std::unique_ptr<test>
    make(test::id_t id, bfobject *obj)
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

TEST_CASE("test_manager: create_valid_twice_overwrites")
{
    CHECK_NOTHROW(g_test_manager->create(0));
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
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: factory_nullptr")
{
    factory_nullptr = true;
    auto ___ = gsl::finally([&] {
        factory_nullptr = false;
    });

    CHECK_THROWS(g_test_manager->create(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: create_init_throws")
{
    init_throws = true;
    auto ___ = gsl::finally([&] {
        init_throws = false;
    });

    CHECK_THROWS(g_test_manager->create(0));
    g_test_manager->destroy(0);
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
    CHECK_NOTHROW(g_test_manager->destroy(0));
}

TEST_CASE("test_manager: delete_no_create")
{
    CHECK_NOTHROW(g_test_manager->destroy(0));
}

TEST_CASE("test_manager: delete_fini_throws")
{
    fini_throws = true;
    auto ___ = gsl::finally([&] {
        fini_throws = false;
    });

    g_test_manager->create(0);
    CHECK_THROWS(g_test_manager->destroy(0));
}

TEST_CASE("test_manager: run_valid")
{
    g_test_manager->create(0);
    CHECK_NOTHROW(g_test_manager->run(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: run_valid_twice")
{
    g_test_manager->create(0);
    CHECK_NOTHROW(g_test_manager->run(0));
    CHECK_NOTHROW(g_test_manager->run(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: run_throws")
{
    run_throws = true;
    auto ___ = gsl::finally([&] {
        run_throws = false;
    });

    g_test_manager->create(0);
    CHECK_THROWS(g_test_manager->run(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: run_no_create")
{
    CHECK_NOTHROW(g_test_manager->run(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: hlt_valid")
{
    g_test_manager->create(0);
    g_test_manager->run(0);

    CHECK_NOTHROW(g_test_manager->hlt(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: hlt_valid_twice")
{
    g_test_manager->create(0);
    g_test_manager->run(0);

    CHECK_NOTHROW(g_test_manager->hlt(0));
    CHECK_NOTHROW(g_test_manager->hlt(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: hlt_hlt_throws")
{
    hlt_throws = true;
    auto ___ = gsl::finally([&] {
        hlt_throws = false;
    });

    g_test_manager->create(0);
    g_test_manager->run(0);

    CHECK_THROWS(g_test_manager->hlt(0));
    g_test_manager->destroy(0);
}

TEST_CASE("test_manager: hlt_no_create")
{
    CHECK_NOTHROW(g_test_manager->hlt(0));
    g_test_manager->destroy(0);
}
