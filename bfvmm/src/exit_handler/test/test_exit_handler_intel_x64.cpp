//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <test.h>
#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_check.h>
#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>
#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_support.h>
#include <memory_manager/memory_manager_x64.h>
#include <memory_manager/root_page_table_x64.h>

#include <intrinsics/msrs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_guest_state_fields.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

vmcs::field_type g_field = 0;
vmcs::value_type g_value = 0;
vmcs::value_type g_exit_reason = 0;
vmcs::value_type g_exit_qualification = 0;
vmcs::value_type g_exit_instruction_length = 8;
vmcs::value_type g_exit_instruction_information = 0;

static std::map<msrs::field_type, msrs::value_type> g_msrs;

uint64_t g_rip = 0;

static void vmcs_check_all()
{
}

extern "C" bool
__vmread(uint64_t field, uint64_t *val) noexcept
{
    switch (field)
    {
        case vmcs::exit_reason::addr:
            *val = g_exit_reason;
            break;
        case vmcs::exit_qualification::addr:
            *val = g_exit_qualification;
            break;
        case vmcs::vm_exit_instruction_length::addr:
            *val = g_exit_instruction_length;
            break;
        case vmcs::vm_exit_instruction_information::addr:
            *val = g_exit_instruction_information;
            break;
        default:
            g_field = field;
            *val = g_value;
            break;
    }

    return true;
}

extern "C"  bool
__vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_field = field;
    g_value = val;

    return true;
}

extern "C" uint64_t
__read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
__write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

extern "C" void
__stop(void) noexcept
{ }

extern "C" void
__wbinvd(void) noexcept
{ }

extern "C" void
__cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept
{ (void) eax; (void) ebx; (void) ecx; (void) edx; }

auto
setup_vmcs_unhandled(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::launch);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::promote);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::load);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::clear);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_exit_reason = reason;
    return vmcs;
}

auto
setup_vmcs_handled(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    mocks.OnCall(vmcs.get(), vmcs_intel_x64::launch);
    mocks.OnCall(vmcs.get(), vmcs_intel_x64::promote);
    mocks.OnCall(vmcs.get(), vmcs_intel_x64::load);
    mocks.OnCall(vmcs.get(), vmcs_intel_x64::clear);
    mocks.ExpectCall(vmcs.get(), vmcs_intel_x64::resume);

    g_exit_reason = reason;
    return vmcs;
}

auto
setup_vmcs_halt(MockRepository &mocks, vmcs::value_type reason)
{
    auto vmcs = bfn::mock_shared<vmcs_intel_x64>(mocks);

    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::launch);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::promote);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::load);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::clear);
    mocks.NeverCall(vmcs.get(), vmcs_intel_x64::resume);

    g_exit_reason = reason;
    return vmcs;
}

exit_handler_intel_x64
setup_ehlr(const std::shared_ptr<vmcs_intel_x64> &vmcs)
{
    auto ehlr = exit_handler_intel_x64{};
    ehlr.set_vmcs(vmcs);
    ehlr.set_state_save(std::make_shared<state_save_intel_x64>());

    g_rip = ehlr.m_state_save->rip + g_exit_instruction_length;
    return ehlr;
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_unknown()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, 0x0000BEEF);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_cpuid()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::cpuid);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_invd()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::invd);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_invalid_opcode()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = 0x0000BEEF;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_invalid_magic()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = 0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_protocol_version()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 0;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);

        this->expect_true(ehlr.m_state_save->rbx == VMCALL_VERSION);
        this->expect_true(ehlr.m_state_save->rsi == 0);
        this->expect_true(ehlr.m_state_save->r08 == 0);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_bareflank_version()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 1;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);

        this->expect_true(ehlr.m_state_save->rbx == BAREFLANK_VERSION_MAJOR);
        this->expect_true(ehlr.m_state_save->rsi == BAREFLANK_VERSION_MINOR);
        this->expect_true(ehlr.m_state_save->r08 == BAREFLANK_VERSION_PATCH);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_user_version()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 10;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);

        this->expect_true(ehlr.m_state_save->rbx == USER_VERSION_MAJOR);
        this->expect_true(ehlr.m_state_save->rsi == USER_VERSION_MINOR);
        this->expect_true(ehlr.m_state_save->r08 == USER_VERSION_PATCH);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_unknown_version()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_VERSIONS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 0x0000BEEF;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_registers()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_REGISTERS;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;
    ehlr.m_state_save->rcx = 1;
    ehlr.m_state_save->rbx = 2;
    ehlr.m_state_save->rsi = 3;
    ehlr.m_state_save->r08 = 4;
    ehlr.m_state_save->r09 = 5;
    ehlr.m_state_save->r10 = 6;
    ehlr.m_state_save->r11 = 7;
    ehlr.m_state_save->r12 = 8;
    ehlr.m_state_save->r13 = 9;
    ehlr.m_state_save->r14 = 10;
    ehlr.m_state_save->r15 = 11;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_unittest()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_UNITTEST;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_event()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rax = VMCALL_EVENT;
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

auto g_msg = "{\"msg\":\"hello world\"}"_s;
auto g_map = std::make_unique<char[]>(100);

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);

    mocks.OnCall(mm, memory_manager_x64::alloc_map).Return(g_map.get());
    mocks.OnCall(mm, memory_manager_x64::free_map);

    return mm;
}

static auto
setup_pt(MockRepository &mocks)
{
    auto pt = mocks.Mock<root_page_table_x64>();
    mocks.OnCallFunc(root_page_table_x64::instance).Return(pt);

    mocks.OnCall(pt, root_page_table_x64::map);
    mocks.OnCall(pt, root_page_table_x64::unmap);

    return pt;
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_unknown()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = 0x0000BEEF;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    __builtin_memcpy(g_map.get(), g_msg.data(), g_msg.size());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_input_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0;                                  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_output_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0;                                  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_input_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = 0;                                  // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_output_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 0;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_output_size_too_small()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 5;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_input_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = VMCALL_IN_BUFFER_SIZE + 1;          // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_IN_BUFFER_SIZE + 1;          // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_output_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_OUT_BUFFER_SIZE + 1;         // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_map_fails()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0xDEADBEEF;                         // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_unformatted_success()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    __builtin_memcpy(g_map.get(), g_msg.data(), g_msg.size());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_input_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0;                                  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_output_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0;                                  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_input_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = 0;                                  // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_output_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 0;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_output_size_too_small()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 5;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_input_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = VMCALL_IN_BUFFER_SIZE + 1;          // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_IN_BUFFER_SIZE + 1;          // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_output_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_OUT_BUFFER_SIZE + 1;         // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_map_fails()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0xDEADBEEF;                         // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_invalid()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    auto msg = "hello world"_s;
    __builtin_memcpy(g_map.get(), msg.data(), msg.size());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_string_json_success()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_STRING_JSON;            // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    __builtin_memcpy(g_map.get(), g_msg.data(), g_msg.size());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_input_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0;                                  // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_output_nullptr()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0;                                  // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_input_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = 0;                                  // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_output_size_0()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 0;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_output_size_too_small()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = 5;                                  // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_input_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = VMCALL_IN_BUFFER_SIZE + 1;          // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_IN_BUFFER_SIZE + 1;          // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_output_size_too_big()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = VMCALL_OUT_BUFFER_SIZE + 1;         // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_map_fails()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0xDEADBEEF;                         // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_FAILURE);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmcall_data_data_unformatted_success()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmcall);
    auto &&ehlr = setup_ehlr(vmcs);
    setup_mm(mocks);
    setup_pt(mocks);

    ehlr.m_state_save->rax = VMCALL_DATA;                        // r00
    ehlr.m_state_save->rdx = VMCALL_MAGIC_NUMBER;                // r01
    ehlr.m_state_save->rsi = VMCALL_DATA_BINARY_UNFORMATTED;     // r04
    ehlr.m_state_save->r08 = 0x1234U;                            // r05
    ehlr.m_state_save->r09 = g_msg.size();                       // r06
    ehlr.m_state_save->r11 = 0x1234U;                            // r08
    ehlr.m_state_save->r12 = g_msg.size();                       // r09

    __builtin_memcpy(g_map.get(), g_msg.data(), g_msg.size());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(ehlr.m_state_save->rip == g_rip);
        this->expect_true(ec_sign(ehlr.m_state_save->rdx) == BF_VMCALL_SUCCESS);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_vmxoff()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::vmxoff);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_debug_ctl()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000200000001;
    ehlr.m_state_save->rcx = msrs::ia32_debugctl::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_debugctl::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x1);
        this->expect_true(ehlr.m_state_save->rdx == 0x2);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_pat()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000300000002;
    ehlr.m_state_save->rcx = msrs::ia32_pat::addr;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_pat::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x2);
        this->expect_true(ehlr.m_state_save->rdx == 0x3);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_efer()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000400000003;
    ehlr.m_state_save->rcx = msrs::ia32_efer::addr;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_efer::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x3);
        this->expect_true(ehlr.m_state_save->rdx == 0x4);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_perf()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000400000003;
    ehlr.m_state_save->rcx = msrs::ia32_perf_global_ctrl::addr;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask << 32;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_perf_global_ctrl::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x3);
        this->expect_true(ehlr.m_state_save->rdx == 0x4);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_cs()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000500000004;
    ehlr.m_state_save->rcx = msrs::ia32_sysenter_cs::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_sysenter_cs::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x4);
        this->expect_true(ehlr.m_state_save->rdx == 0x5);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_esp()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000600000005;
    ehlr.m_state_save->rcx = msrs::ia32_sysenter_esp::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_sysenter_esp::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x5);
        this->expect_true(ehlr.m_state_save->rdx == 0x6);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_eip()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000700000006;
    ehlr.m_state_save->rcx = msrs::ia32_sysenter_eip::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_sysenter_eip::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x6);
        this->expect_true(ehlr.m_state_save->rdx == 0x7);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_fs_base()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000800000007;
    ehlr.m_state_save->rcx = msrs::ia32_fs_base::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_fs_base::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x7);
        this->expect_true(ehlr.m_state_save->rdx == 0x8);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_gs_base()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_value = 0x0000000900000008;
    ehlr.m_state_save->rcx = msrs::ia32_gs_base::addr;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_gs_base::addr);
        this->expect_true(ehlr.m_state_save->rax == 0x8);
        this->expect_true(ehlr.m_state_save->rdx == 0x9);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_default()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_msrs[0x10] = 0x0000000A00000009;
    ehlr.m_state_save->rcx = 0x10;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(ehlr.m_state_save->rax == 0x9);
        this->expect_true(ehlr.m_state_save->rdx == 0xA);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_rdmsr_ignore()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::rdmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    g_msrs[0x31] = 0x0;
    ehlr.m_state_save->rcx = 0x31;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(ehlr.m_state_save->rax == 0);
        this->expect_true(ehlr.m_state_save->rdx == 0);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_debug_ctrl()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_debugctl::addr;
    ehlr.m_state_save->rax = 0x1;
    ehlr.m_state_save->rdx = 0x2;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_debugctl::addr);
        this->expect_true(g_value == 0x0000000200000001);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_pat()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_pat::addr;
    ehlr.m_state_save->rax = 0x2;
    ehlr.m_state_save->rdx = 0x3;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_pat::addr);
        this->expect_true(g_value == 0x0000000300000002);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_efer()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_efer::addr;
    ehlr.m_state_save->rax = 0x3;
    ehlr.m_state_save->rdx = 0x4;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_efer::addr);
        this->expect_true(g_value == 0x0000000400000003);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_perf()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_perf_global_ctrl::addr;
    ehlr.m_state_save->rax = 0x3;
    ehlr.m_state_save->rdx = 0x4;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask << 32;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_perf_global_ctrl::addr);
        this->expect_true(g_value == 0x0000000400000003);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_cs()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_sysenter_cs::addr;
    ehlr.m_state_save->rax = 0x4;
    ehlr.m_state_save->rdx = 0x5;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_sysenter_cs::addr);
        this->expect_true(g_value == 0x0000000500000004);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_esp()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_sysenter_esp::addr;
    ehlr.m_state_save->rax = 0x5;
    ehlr.m_state_save->rdx = 0x6;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_sysenter_esp::addr);
        this->expect_true(g_value == 0x0000000600000005);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_eip()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_sysenter_eip::addr;
    ehlr.m_state_save->rax = 0x6;
    ehlr.m_state_save->rdx = 0x7;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_ia32_sysenter_eip::addr);
        this->expect_true(g_value == 0x0000000700000006);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_fs_base()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_fs_base::addr;
    ehlr.m_state_save->rax = 0x7;
    ehlr.m_state_save->rdx = 0x8;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_fs_base::addr);
        this->expect_true(g_value == 0x0000000800000007);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_gs_base()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = msrs::ia32_gs_base::addr;
    ehlr.m_state_save->rax = 0x8;
    ehlr.m_state_save->rdx = 0x9;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });

        this->expect_true(g_field == vmcs::guest_gs_base::addr);
        this->expect_true(g_value == 0x0000000900000008);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_reason_wrmsr_default()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_handled(mocks, exit_reason::basic_exit_reason::wrmsr);
    auto &&ehlr = setup_ehlr(vmcs);

    ehlr.m_state_save->rcx = 0x10;
    ehlr.m_state_save->rax = 0x9;
    ehlr.m_state_save->rdx = 0xA;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
        this->expect_true(g_msrs[0x10] = 0x0000000A00000009);
        this->expect_true(ehlr.m_state_save->rip == g_rip);
    });
}

void
exit_handler_intel_x64_ut::test_vm_exit_failure_check()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_unhandled(mocks, exit_reason::basic_exit_reason::xrstors | 0x80000000);
    auto &&ehlr = setup_ehlr(vmcs);

    mocks.OnCallFunc(vmcs::check::all).Do(vmcs_check_all);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.dispatch(); });
    });
}

void
exit_handler_intel_x64_ut::test_halt()
{
    MockRepository mocks;
    auto &&vmcs = setup_vmcs_halt(mocks, exit_reason::basic_exit_reason::xrstors);
    auto &&ehlr = setup_ehlr(vmcs);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        this->expect_no_exception([&]{ ehlr.halt(); });
    });
}
