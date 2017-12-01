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

#include <cstdlib>

#include <vcpu/vcpu_intel_x64.h>
#include <memory_manager/memory_manager_x64.h>
#include <memory_manager/root_page_table_x64.h>

#include <intrinsics/x86/common_x64.h>
using namespace x64;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

gdt_reg_x64_t test_gdtr{};
idt_reg_x64_t test_idtr{};

std::vector<gdt_x64::segment_descriptor_type> test_gdt = {
    0x0,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF
};

std::vector<idt_x64::interrupt_descriptor_type> test_idt{512};

void
setup_gdt()
{
    auto limit = test_gdt.size() * sizeof(gdt_x64::segment_descriptor_type);

    test_gdtr.base = &test_gdt.at(0);
    test_gdtr.limit = gsl::narrow_cast<gdt_reg_x64_t::limit_type>(limit);
}

void
setup_idt()
{
    auto limit = test_idt.size() * sizeof(idt_x64::interrupt_descriptor_type);

    test_idtr.base = &test_idt.at(0);
    test_idtr.limit = gsl::narrow_cast<idt_reg_x64_t::limit_type>(limit);
}

static uint64_t
test_read_msr(uint32_t addr) noexcept
{ bfignored(addr); return 0; }

static uint64_t
test_read_cr0() noexcept
{ return 0; }

static uint64_t
test_read_cr3() noexcept
{ return 0; }

static uint64_t
test_read_cr4() noexcept
{ return 0; }

static uint64_t
test_read_rflags() noexcept
{ return 0; }

static uint64_t
test_read_dr7() noexcept
{ return 0; }

static void
test_read_gdt(gdt_reg_x64_t *gdt_reg) noexcept
{ *gdt_reg = test_gdtr; }

static void
test_read_idt(idt_reg_x64_t *idt_reg) noexcept
{ *idt_reg = test_idtr; }

static uint16_t
test_read_es() noexcept
{ return 0; }

static uint16_t
test_read_cs() noexcept
{ return 0; }

static uint16_t
test_read_ss() noexcept
{ return 0; }

static uint16_t
test_read_ds() noexcept
{ return 0; }

static uint16_t
test_read_fs() noexcept
{ return 0; }

static uint16_t
test_read_gs() noexcept
{ return 0; }

static uint16_t
test_read_ldtr() noexcept
{ return 0; }

static uint16_t
test_read_tr() noexcept
{ return 0; }

static uint32_t
test_cpuid_ecx(uint32_t val) noexcept
{ bfignored(val); return 0x04000000U; }

static uint32_t
test_cpuid_eax(uint32_t val) noexcept
{ bfignored(val); return 0x00000000U; }

static uint32_t
test_cpuid_subebx(uint32_t addr, uint32_t leaf)
{
    bfignored(addr);
    bfignored(leaf);

    return 0x00000000U;
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_read_cr0).Do(test_read_cr0);
    mocks.OnCallFunc(_read_cr3).Do(test_read_cr3);
    mocks.OnCallFunc(_read_cr4).Do(test_read_cr4);
    mocks.OnCallFunc(_read_rflags).Do(test_read_rflags);
    mocks.OnCallFunc(_read_dr7).Do(test_read_dr7);
    mocks.OnCallFunc(_read_gdt).Do(test_read_gdt);
    mocks.OnCallFunc(_read_idt).Do(test_read_idt);
    mocks.OnCallFunc(_read_es).Do(test_read_es);
    mocks.OnCallFunc(_read_cs).Do(test_read_cs);
    mocks.OnCallFunc(_read_ss).Do(test_read_ss);
    mocks.OnCallFunc(_read_ds).Do(test_read_ds);
    mocks.OnCallFunc(_read_fs).Do(test_read_fs);
    mocks.OnCallFunc(_read_gs).Do(test_read_gs);
    mocks.OnCallFunc(_read_ldtr).Do(test_read_ldtr);
    mocks.OnCallFunc(_read_tr).Do(test_read_tr);
    mocks.OnCallFunc(_cpuid_ecx).Do(test_cpuid_ecx);
    mocks.OnCallFunc(_cpuid_eax).Do(test_cpuid_eax);
    mocks.OnCallFunc(_cpuid_subebx).Do(test_cpuid_subebx);

    setup_gdt();
    setup_idt();
}

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Return(0x000000ABCDEF0000);

    return mm;
}

static auto
setup_pt(MockRepository &mocks)
{
    auto pt = mocks.Mock<root_page_table_x64>();
    mocks.OnCallFunc(root_pt).Return(pt);
    mocks.OnCall(pt, root_page_table_x64::cr3).Return(0x000000ABCDEF0000);

    return pt;
}

template<typename T> auto
mock_no_delete(MockRepository &mocks)
{
    auto ptr = mocks.Mock<T>();
    mocks.OnCallDestructor(ptr);

    return ptr;
}

template <typename T> auto
mock_unique(MockRepository &mocks)
{
    return std::unique_ptr<T>(mock_no_delete<T>(mocks));
}

TEST_CASE("vcpu_intel_x64: invalid_id")
{
    CHECK_THROWS(std::make_unique<vcpu_intel_x64>(vcpuid::reserved));
}

TEST_CASE("vcpu_intel_x64: valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    auto test = [&] {
        auto on = mock_unique<vmxon_intel_x64>(mocks);
        auto cs = mock_unique<vmcs_intel_x64>(mocks);
        auto eh = mock_unique<exit_handler_intel_x64>(mocks);
        auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
        auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);
        std::make_unique<vcpu_intel_x64>(
            0,
            std::move(on),
            std::move(cs),
            std::move(eh),
            std::move(vs),
            std::move(gs)
        );
    };

    CHECK_NOTHROW(test());
}

TEST_CASE("vcpu_intel_x64: init_null_params")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  nullptr,
                  nullptr,
                  nullptr,
                  nullptr,
                  nullptr
              );

    CHECK_NOTHROW(vc->init());
}

TEST_CASE("vcpu_intel_x64: init_valid_params")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->init());
}

TEST_CASE("vcpu_intel_x64: init_valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->init());
}

TEST_CASE("vcpu_intel_x64: init_vmcs_throws")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save).Throw(std::logic_error("error"));
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_THROWS(vc->init());
}

TEST_CASE("vcpu_intel_x64: fini_null_params")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  nullptr,
                  nullptr,
                  nullptr,
                  nullptr
              );

    vc->init();
    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("vcpu_intel_x64: fini_valid_params")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("vcpu_intel_x64: fini_valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("vcpu_intel_x64: fini_no_init")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->fini());
}

TEST_CASE("vcpu_intel_x64: run_launch")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0x0001000000000000,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_NOTHROW(vc->run());
}

TEST_CASE("vcpu_intel_x64: run_launch_is_host_vcpu")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_NOTHROW(vc->run());
}

TEST_CASE("vcpu_intel_x64: run_resume")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    vc->run();
    CHECK_NOTHROW(vc->run());
}

TEST_CASE("vcpu_intel_x64: run_no_init")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_THROWS(vc->run());
}

TEST_CASE("vcpu_intel_x64: run_vmxon_throws")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start).Throw(std::runtime_error("error"));
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_THROWS(vc->run());
}

TEST_CASE("vcpu_intel_x64: run_vmcs_throws")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch).Throw(std::runtime_error("error"));
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_THROWS(vc->run());
}

TEST_CASE("vcpu_intel_x64: hlt_no_init")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0x0001000000000000,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    CHECK_NOTHROW(vc->hlt());
}

TEST_CASE("vcpu_intel_x64: hlt_no_run")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0x0001000000000000,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    CHECK_NOTHROW(vc->hlt());
}

TEST_CASE("vcpu_intel_x64: hlt_valid")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0x0001000000000000,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    vc->run();
    CHECK_NOTHROW(vc->hlt());
}

TEST_CASE("vcpu_intel_x64: hlt_valid_is_host_vcpu")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop);

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    vc->run();
    CHECK_NOTHROW(vc->hlt());
}

TEST_CASE("vcpu_intel_x64: hlt_vmxon_throws")
{
    MockRepository mocks;
    setup_intrinsics(mocks);
    setup_mm(mocks);
    setup_pt(mocks);

    auto on = mock_unique<vmxon_intel_x64>(mocks);
    auto cs = mock_unique<vmcs_intel_x64>(mocks);
    auto eh = mock_unique<exit_handler_intel_x64>(mocks);
    auto vs = mock_unique<vmcs_intel_x64_vmm_state>(mocks);
    auto gs = mock_unique<vmcs_intel_x64_host_vm_state>(mocks);

    mocks.OnCall(cs.get(), vmcs_intel_x64::set_state_save);
    mocks.OnCall(cs.get(), vmcs_intel_x64::set_exit_handler_entry);
    mocks.OnCall(cs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(cs.get(), vmcs_intel_x64::load);
    mocks.OnCall(cs.get(), vmcs_intel_x64::resume);

    mocks.OnCall(on.get(), vmxon_intel_x64::start);
    mocks.OnCall(on.get(), vmxon_intel_x64::stop).Throw(std::runtime_error("error"));

    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_vmcs);
    mocks.OnCall(eh.get(), exit_handler_intel_x64::set_state_save);

    auto vc = std::make_unique<vcpu_intel_x64>(
                  0,
                  std::move(on),
                  std::move(cs),
                  std::move(eh),
                  std::move(vs),
                  std::move(gs)
              );

    vc->init();
    vc->run();

    CHECK_THROWS(vc->hlt());
}

#endif
