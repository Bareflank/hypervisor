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

#include <test/support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

static bool
test_handler(vcpu_t *vcpu)
{ bfignored(vcpu); return true; }

TEST_CASE("quiet")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);

    test_handler(vcpu);
}

TEST_CASE("exit_handler: construct / destruct")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);

    g_mm->add_md(0x1000, 0x1000, MEMORY_TYPE_R | MEMORY_TYPE_E);
    g_mm->add_md(0x2000, 0x2000, MEMORY_TYPE_R | MEMORY_TYPE_W);

    CHECK_NOTHROW(bfvmm::intel_x64::exit_handler{vcpu});
}

TEST_CASE("exit_handler: add_handler")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_NOTHROW(
        ehlr.add_handler(0, test_handler)
    );
}

TEST_CASE("exit_handler: add_handler invalid reason")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_THROWS(
        ehlr.add_handler(1000, test_handler)
    );
}

TEST_CASE("exit_handler: unhandled exit reason")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_NOTHROW(handle_exit(vcpu, &ehlr));
}

TEST_CASE("exit_handler: unhandled exit reason, invalid guest state")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, ::intel_x64::vmcs::exit_reason::vm_entry_failure::mask);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_NOTHROW(handle_exit(vcpu, &ehlr));
}

TEST_CASE("exit_handler: unhandled exit reason, invalid reason")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0000BEEF);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_NOTHROW(handle_exit(vcpu, &ehlr));
}

TEST_CASE("exit_handler: add_exit_handler")
{
    setup_test_support();

    MockRepository mocks;
    auto &&vcpu = setup_vcpu(mocks, 0x0);
    auto &&ehlr = bfvmm::intel_x64::exit_handler{vcpu};

    CHECK_NOTHROW(
        ehlr.add_exit_handler(test_handler)
    );

    CHECK_NOTHROW(handle_exit(vcpu, &ehlr));
}

#endif
