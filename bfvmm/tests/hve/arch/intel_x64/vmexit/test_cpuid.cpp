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
#include <hve/arch/intel_x64/vmexit/cpuid.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace bfvmm::intel_x64;

bool
test_emulator(vcpu_t *vcpu)
{
    vcpu->set_rax(42);
    vcpu->set_rbx(42);
    vcpu->set_rcx(42);
    vcpu->set_rdx(42);

    return vcpu->advance();
}

bool
test_emulator_returns_false(vcpu_t *vcpu)
{
    bfignored(vcpu);
    return false;
}

bool
test_handler(vcpu_t *vcpu)
{
    bfignored(vcpu);
    return false;
}

bool
test_handler_returns_true(vcpu_t *vcpu)
{
    bfignored(vcpu);
    return vcpu->advance();
}

TEST_CASE("constructor/destruction")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);

    CHECK_NOTHROW(cpuid_handler(vcpu));
}

TEST_CASE("add handlers")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = cpuid_handler(vcpu);

    CHECK_NOTHROW(
        handler.add_handler(42, test_handler)
    );
}

TEST_CASE("cpuid exit")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks, 0);
    auto handler = cpuid_handler(vcpu);

    g_state.rax = 42;
    g_state.rbx = 0;
    g_state.rcx = 0;
    g_state.rdx = 0;

    handler.add_handler(
        42, test_handler
    );

    CHECK(handler.handle(vcpu) == true);
    CHECK(g_state.rax == 42);
    CHECK(g_state.rbx == 42);
    CHECK(g_state.rcx == 42);
    CHECK(g_state.rdx == 42);
}

// TEST_CASE("cpuid exit, ignore write")
// {
//     MockRepository mocks;
//     auto vcpu = setup_vcpu(mocks, 0);
//     auto handler = cpuid_handler(vcpu);

//     g_state.rax = 42;
//     g_state.rbx = 0;
//     g_state.rcx = 0;
//     g_state.rdx = 0;

//     handler.add_handler(
//         42, test_handler_ignore_write
//     );

//     CHECK(handler.handle(vcpu) == true);
//     CHECK(g_state.rax == 42);
//     CHECK(g_state.rbx == 0);
//     CHECK(g_state.rcx == 0);
//     CHECK(g_state.rdx == 0);
// }

// TEST_CASE("cpuid exit, ignore advance")
// {
//     MockRepository mocks;
//     auto vcpu = setup_vcpu(mocks, 0);
//     auto handler = cpuid_handler(vcpu);

//     g_state.rip = 0;
//     g_state.rax = 42;

//     ::intel_x64::vm::write(
//         vmcs_n::vm_exit_instruction_length::addr, 42
//     );

//     handler.add_handler(
//         42, test_handler_ignore_advance
//     );

//     CHECK(handler.handle(vcpu) == true);
//     CHECK(g_state.rip == 0);
// }

// TEST_CASE("cpuid exit, no handler")
// {
//     MockRepository mocks;
//     auto vcpu = setup_vcpu(mocks, 0);
//     auto handler = cpuid_handler(vcpu);

//     g_state.rax = 0;
//     CHECK(handler.handle(vcpu) == true);
// }

// TEST_CASE("cpuid exit, returns false")
// {
//     MockRepository mocks;
//     auto vcpu = setup_vcpu(mocks, 0);
//     auto handler = cpuid_handler(vcpu);

//     g_state.rax = 42;

//     handler.add_handler(
//         42, test_handler_returns_false
//     );

//     CHECK(handler.handle(vcpu) == true);
// }

// TEST_CASE("exit_handler: handle_cpuid ack")
// {
//     MockRepository mocks;
//     auto vcpu = setup_vcpu(mocks, 0);
//     auto handler = cpuid_handler(vcpu);

//     g_state.rax = 0x4BF00000;
//     g_state.rip = 0;

//     CHECK(handler.handle(vcpu) == true);
//     CHECK(g_state.rip != 0);
//     CHECK(g_state.rax == 0x4BF00001);
// }

// TEST_CASE("exit_handler: handle_cpuid start")
// {
//     MockRepository mocks;
//     auto vcpu = setup_vcpu(mocks, 0);
//     auto handler = cpuid_handler(vcpu);

//     g_state.rax = 0x4BF00011;
//     g_state.rip = 0;

//     CHECK(handler.handle(vcpu) == true);
//     CHECK(g_state.rip != 0);
// }

// TEST_CASE("exit_handler: handle_cpuid stop")
// {
//     MockRepository mocks;
//     auto vcpu = setup_vcpu(mocks, 0);
//     auto handler = cpuid_handler(vcpu);

//     g_state.rax = 0x4BF00021;
//     g_state.rip = 0;

//     CHECK(handler.handle(vcpu) == true);
//     CHECK(g_state.rip != 0);
// }

#endif
