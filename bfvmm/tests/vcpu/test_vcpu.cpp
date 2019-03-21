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

#include <bftypes.h>

#include <catch/catch.hpp>
#include <vcpu/vcpu.h>

TEST_CASE("vcpu: invalid_id")
{
    CHECK_THROWS(std::make_unique<bfvmm::vcpu>(vcpuid::reserved));
}

TEST_CASE("vcpu: valid")
{
    CHECK_NOTHROW(std::make_unique<bfvmm::vcpu>(0));
}

TEST_CASE("vcpu: init_null_attr")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    CHECK_FALSE(vc->is_initialized());
    vc->init(nullptr);
    CHECK(vc->is_initialized());
}

TEST_CASE("vcpu: init_valid_attr")
{
    bfobject data{};
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    CHECK_FALSE(vc->is_initialized());
    vc->init(&data);
    CHECK(vc->is_initialized());
}

TEST_CASE("vcpu: fini_null_attr")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    vc->init();

    CHECK(vc->is_initialized());
    vc->fini(nullptr);
    CHECK_FALSE(vc->is_initialized());
}

TEST_CASE("vcpu: fini_valid_attr")
{
    bfobject data{};
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    vc->init();

    CHECK(vc->is_initialized());
    vc->fini(&data);
    CHECK_FALSE(vc->is_initialized());
}

TEST_CASE("vcpu: fini_without_init_without_run")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    CHECK_FALSE(vc->is_running());
    CHECK_FALSE(vc->is_initialized());
    vc->fini();
    CHECK_FALSE(vc->is_running());
    CHECK_FALSE(vc->is_initialized());
}

TEST_CASE("vcpu: fini_with_init_without_run")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    vc->init();

    CHECK_FALSE(vc->is_running());
    CHECK(vc->is_initialized());
    vc->fini();
    CHECK_FALSE(vc->is_running());
    CHECK_FALSE(vc->is_initialized());
}

TEST_CASE("vcpu: fini_without_init_with_run")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    vc->run();

    CHECK(vc->is_running());
    CHECK_FALSE(vc->is_initialized());
    vc->fini();
    CHECK_FALSE(vc->is_running());
    CHECK_FALSE(vc->is_initialized());
}

TEST_CASE("vcpu: fini_with_init_with_run")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    vc->init();
    vc->run();

    CHECK(vc->is_running());
    CHECK(vc->is_initialized());
    vc->fini();
    CHECK_FALSE(vc->is_running());
    CHECK_FALSE(vc->is_initialized());
}

TEST_CASE("vcpu: run_null_attr")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    CHECK_FALSE(vc->is_running());
    vc->run(nullptr);
    CHECK(vc->is_running());
}

TEST_CASE("vcpu: run_valid_attr")
{
    bfobject data{};
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    CHECK_FALSE(vc->is_running());
    vc->run(&data);
    CHECK(vc->is_running());
}

TEST_CASE("vcpu: run_without_init")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    CHECK_FALSE(vc->is_running());
    vc->run();
    CHECK(vc->is_running());
}

TEST_CASE("vcpu: run_with_init")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    vc->init();

    CHECK_FALSE(vc->is_running());
    vc->run();
    CHECK(vc->is_running());
}

TEST_CASE("vcpu: hlt_null_attr")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    CHECK_FALSE(vc->is_running());
    vc->hlt(nullptr);
    CHECK_FALSE(vc->is_running());
}

TEST_CASE("vcpu: hlt_valid_attr")
{
    bfobject data{};
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    CHECK_FALSE(vc->is_running());
    vc->hlt(&data);
    CHECK_FALSE(vc->is_running());
}

TEST_CASE("vcpu: hlt_without_run")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    CHECK_FALSE(vc->is_running());
    vc->hlt();
    CHECK_FALSE(vc->is_running());
}

TEST_CASE("vcpu: hlt_with_run")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    vc->run();

    CHECK(vc->is_running());
    vc->hlt();
    CHECK_FALSE(vc->is_running());
}

TEST_CASE("vcpu: id")
{
    auto vc = std::make_unique<bfvmm::vcpu>(1);
    CHECK(vc->id() == 1);
}

TEST_CASE("vcpu: is_bootstrap_vcpu")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);
    CHECK(vc->is_bootstrap_vcpu());
}

TEST_CASE("vcpu: is_not_bootstrap_vcpu")
{
    auto vc = std::make_unique<bfvmm::vcpu>(1);
    CHECK_FALSE(vc->is_bootstrap_vcpu());
}

TEST_CASE("vcpu: is_host_vm_vcpu")
{
    auto vc = std::make_unique<bfvmm::vcpu>(1);
    CHECK(vc->is_host_vm_vcpu());
}

TEST_CASE("vcpu: is_guest_vm_vcpu")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0x0000000100000000);
    CHECK(vc->is_guest_vm_vcpu());
}

TEST_CASE("vcpu: is_running_vm_vcpu")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    vc->run();
    CHECK(vc->is_running());
}

TEST_CASE("vcpu: is_not_running_vm_vcpu")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);
    CHECK_FALSE(vc->is_running());
}

TEST_CASE("vcpu: is_initialized_vm_vcpu")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);

    vc->init();
    CHECK(vc->is_initialized());
}

TEST_CASE("vcpu: is_not_initialized_vm_vcpu")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);
    CHECK_FALSE(vc->is_initialized());
}

void
test_delegate(bfobject *data)
{ bfignored(data); }

void
test_delegate_throws(bfobject *data)
{ bfignored(data); throw std::runtime_error("error"); }

TEST_CASE("vcpu: run_delegate")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);
    CHECK_NOTHROW(vc->add_run_delegate(vcpu_delegate_t::create<test_delegate>()));
    CHECK_NOTHROW(vc->run());
}

TEST_CASE("vcpu: hlt_delegate")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);
    CHECK_NOTHROW(vc->add_hlt_delegate(vcpu_delegate_t::create<test_delegate>()));
    CHECK_NOTHROW(vc->hlt());
}

TEST_CASE("vcpu: init_delegate")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);
    CHECK_NOTHROW(vc->add_init_delegate(vcpu_delegate_t::create<test_delegate>()));
    CHECK_NOTHROW(vc->init());
}

TEST_CASE("vcpu: fini_delegate")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);
    CHECK_NOTHROW(vc->add_fini_delegate(vcpu_delegate_t::create<test_delegate>()));
    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("vcpu: run_delegate throws")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);
    CHECK_NOTHROW(vc->add_run_delegate(vcpu_delegate_t::create<test_delegate_throws>()));
    CHECK_THROWS(vc->run());
}

TEST_CASE("vcpu: init_delegate throws")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0);
    CHECK_NOTHROW(vc->add_init_delegate(vcpu_delegate_t::create<test_delegate_throws>()));
    CHECK_THROWS(vc->init());
}
