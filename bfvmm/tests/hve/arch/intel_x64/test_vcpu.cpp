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

TEST_CASE("vcpu: construct / destruct")
{
    setup_test_support();
    CHECK_NOTHROW(bfvmm::intel_x64::vcpu{0});
}

TEST_CASE("vcpu: run")
{
    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    CHECK_NOTHROW(vcpu.run());
}

TEST_CASE("vcpu: run throws")
{
    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    g_vmload_fails = true;
    auto ___ = gsl::finally([] {
        g_vmload_fails = false;
    });

    CHECK_THROWS(vcpu.run());
}

TEST_CASE("vcpu: resume")
{
    setup_test_support();

    MockRepository mocks;
    mocks.OnCallFunc(bfvmm::intel_x64::check::all);

    bfvmm::intel_x64::vcpu vcpu{0};

    CHECK_NOTHROW(vcpu.run());
    CHECK_THROWS(vcpu.run());
}

TEST_CASE("vcpu: hlt")
{
    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    CHECK_NOTHROW(vcpu.run());
    CHECK_NOTHROW(vcpu.hlt());
}

TEST_CASE("vcpu: load")
{
    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    CHECK_NOTHROW(vcpu.load());
}

TEST_CASE("vcpu: promote")
{
    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    CHECK_THROWS(vcpu.promote());
}

static bool
test_handler(vcpu_t *vcpu)
{ bfignored(vcpu); return true; }

TEST_CASE("vcpu: add handlers")
{
    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    test_handler(&vcpu);
    CHECK_NOTHROW(vcpu.add_handler(0, test_handler));
    CHECK_NOTHROW(vcpu.add_exit_handler(test_handler));
}

TEST_CASE("vcpu: dump")
{
    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    CHECK_NOTHROW(vcpu.dump("test"));
}

TEST_CASE("vcpu: halt")
{
    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    CHECK_NOTHROW(vcpu.halt("test"));
}

TEST_CASE("vcpu: advance")
{
    using namespace ::intel_x64::vmcs;

    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    vcpu.set_rip(0);
    ::intel_x64::vm::write(vm_exit_instruction_length::addr, 42, "");

    vcpu.advance();
    CHECK(vcpu.rip() == 42);
}

TEST_CASE("vcpu: registers")
{
    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    vcpu.set_rax(42);
    CHECK(vcpu.rax() == 42);
    vcpu.set_rbx(42);
    CHECK(vcpu.rbx() == 42);
    vcpu.set_rcx(42);
    CHECK(vcpu.rcx() == 42);
    vcpu.set_rdx(42);
    CHECK(vcpu.rdx() == 42);
    vcpu.set_rbp(42);
    CHECK(vcpu.rbp() == 42);
    vcpu.set_rsi(42);
    CHECK(vcpu.rsi() == 42);
    vcpu.set_rdi(42);
    CHECK(vcpu.rdi() == 42);
    vcpu.set_r08(42);
    CHECK(vcpu.r08() == 42);
    vcpu.set_r09(42);
    CHECK(vcpu.r09() == 42);
    vcpu.set_r10(42);
    CHECK(vcpu.r10() == 42);
    vcpu.set_r11(42);
    CHECK(vcpu.r11() == 42);
    vcpu.set_r12(42);
    CHECK(vcpu.r12() == 42);
    vcpu.set_r13(42);
    CHECK(vcpu.r13() == 42);
    vcpu.set_r14(42);
    CHECK(vcpu.r14() == 42);
    vcpu.set_r15(42);
    CHECK(vcpu.r15() == 42);
    vcpu.set_rip(42);
    CHECK(vcpu.rip() == 42);
    vcpu.set_rsp(42);
    CHECK(vcpu.rsp() == 42);
    vcpu.set_gdt_base(42);
    CHECK(vcpu.gdt_base() == 42);
    vcpu.set_gdt_limit(42);
    CHECK(vcpu.gdt_limit() == 42);
    vcpu.set_idt_base(42);
    CHECK(vcpu.idt_base() == 42);
    vcpu.set_idt_limit(42);
    CHECK(vcpu.idt_limit() == 42);
    vcpu.set_cr0(42);
    CHECK(vcpu.cr0() == 42);
    vcpu.set_cr3(42);
    CHECK(vcpu.cr3() == 42);
    vcpu.set_cr4(42);
    CHECK(vcpu.cr4() == 42);
    vcpu.set_ia32_efer(42);
    CHECK(vcpu.ia32_efer() == 42);
    vcpu.set_ia32_pat(42);
    CHECK(vcpu.ia32_pat() == 42);

    vcpu.set_es_selector(42);
    CHECK(vcpu.es_selector() == 42);
    vcpu.set_es_base(42);
    CHECK(vcpu.es_base() == 42);
    vcpu.set_es_limit(42);
    CHECK(vcpu.es_limit() == 42);
    vcpu.set_es_access_rights(42);
    CHECK(vcpu.es_access_rights() == 42);
    vcpu.set_cs_selector(42);
    CHECK(vcpu.cs_selector() == 42);
    vcpu.set_cs_base(42);
    CHECK(vcpu.cs_base() == 42);
    vcpu.set_cs_limit(42);
    CHECK(vcpu.cs_limit() == 42);
    vcpu.set_cs_access_rights(42);
    CHECK(vcpu.cs_access_rights() == 42);
    vcpu.set_ss_selector(42);
    CHECK(vcpu.ss_selector() == 42);
    vcpu.set_ss_base(42);
    CHECK(vcpu.ss_base() == 42);
    vcpu.set_ss_limit(42);
    CHECK(vcpu.ss_limit() == 42);
    vcpu.set_ss_access_rights(42);
    CHECK(vcpu.ss_access_rights() == 42);
    vcpu.set_ds_selector(42);
    CHECK(vcpu.ds_selector() == 42);
    vcpu.set_ds_base(42);
    CHECK(vcpu.ds_base() == 42);
    vcpu.set_ds_limit(42);
    CHECK(vcpu.ds_limit() == 42);
    vcpu.set_ds_access_rights(42);
    CHECK(vcpu.ds_access_rights() == 42);
    vcpu.set_fs_selector(42);
    CHECK(vcpu.fs_selector() == 42);
    vcpu.set_fs_base(42);
    CHECK(vcpu.fs_base() == 42);
    vcpu.set_fs_limit(42);
    CHECK(vcpu.fs_limit() == 42);
    vcpu.set_fs_access_rights(42);
    CHECK(vcpu.fs_access_rights() == 42);
    vcpu.set_gs_selector(42);
    CHECK(vcpu.gs_selector() == 42);
    vcpu.set_gs_base(42);
    CHECK(vcpu.gs_base() == 42);
    vcpu.set_gs_limit(42);
    CHECK(vcpu.gs_limit() == 42);
    vcpu.set_gs_access_rights(42);
    CHECK(vcpu.gs_access_rights() == 42);
    vcpu.set_tr_selector(42);
    CHECK(vcpu.tr_selector() == 42);
    vcpu.set_tr_base(42);
    CHECK(vcpu.tr_base() == 42);
    vcpu.set_tr_limit(42);
    CHECK(vcpu.tr_limit() == 42);
    vcpu.set_tr_access_rights(42);
    CHECK(vcpu.tr_access_rights() == 42);
    vcpu.set_ldtr_selector(42);
    CHECK(vcpu.ldtr_selector() == 42);
    vcpu.set_ldtr_base(42);
    CHECK(vcpu.ldtr_base() == 42);
    vcpu.set_ldtr_limit(42);
    CHECK(vcpu.ldtr_limit() == 42);
    vcpu.set_ldtr_access_rights(42);
    CHECK(vcpu.ldtr_access_rights() == 42);
}

TEST_CASE("vcpu: save state")
{
    setup_test_support();
    bfvmm::intel_x64::vcpu vcpu{0};

    CHECK_NOTHROW(vcpu.state());
}

#endif
