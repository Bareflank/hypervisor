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

TEST_CASE("vcpu: is_host_vcpu")
{
    auto vc = std::make_unique<bfvmm::vcpu>(1);
    CHECK(vc->is_host_vcpu());
}

TEST_CASE("vcpu: is_guest_vcpu")
{
    auto vc = std::make_unique<bfvmm::vcpu>(0x0000000100000000);
    CHECK(vc->is_guest_vcpu());
}
