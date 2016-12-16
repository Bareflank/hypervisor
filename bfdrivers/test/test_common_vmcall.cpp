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

#include <gsl/gsl>

#include <test.h>

#include <common.h>
#include <platform.h>

extern uint64_t g_set_afinity_fails;

void
driver_entry_ut::test_common_vmcall_invalid_args()
{
    vmcall_registers_t regs{};

    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_start_vmm() == BF_SUCCESS);

    this->expect_true(common_vmcall(nullptr, 0) == BF_ERROR_INVALID_ARG);
    this->expect_true(common_vmcall(&regs, 10) == BF_ERROR_INVALID_ARG);

    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_vmcall_set_affinity_failure()
{
    vmcall_registers_t regs{};

    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_start_vmm() == BF_SUCCESS);

    g_set_afinity_fails = 1;
    auto ___ = gsl::finally([&] { g_set_afinity_fails = 0; });

    this->expect_true(common_vmcall(&regs, 0) == -1);

    g_set_afinity_fails = 0;

    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_vmcall_success()
{
    vmcall_registers_t regs{};

    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_start_vmm() == BF_SUCCESS);

    this->expect_true(common_vmcall(&regs, 0) == BF_SUCCESS);
    this->expect_true(common_vmcall(&regs, 0xFFFFFFFFFFFFFFFF) == BF_SUCCESS);

    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_vmcall_success_event()
{
    vmcall_registers_t regs{};
    regs.r00 = VMCALL_EVENT;

    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_start_vmm() == BF_SUCCESS);

    this->expect_true(common_vmcall(&regs, 0) == BF_SUCCESS);
    this->expect_true(common_vmcall(&regs, 0xFFFFFFFFFFFFFFFF) == BF_SUCCESS);

    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_vmcall_vmcall_when_unloaded()
{
    vmcall_registers_t regs{};

    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_get_drr_success.get(), m_dummy_get_drr_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_vmcall(&regs, 0) == BF_ERROR_VMM_INVALID_STATE);
    this->expect_true(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_vmcall_vmcall_when_corrupt()
{
    vmcall_registers_t regs{};

    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_failure.get(), m_dummy_stop_vmm_failure_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_get_drr_success.get(), m_dummy_get_drr_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_start_vmm() == BF_SUCCESS);
    this->expect_true(common_stop_vmm() == ENTRY_ERROR_VMM_STOP_FAILED);
    this->expect_true(common_vmcall(&regs, 0) == BF_ERROR_VMM_CORRUPTED);
    this->expect_true(common_fini() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

void
driver_entry_ut::test_common_vmcall_vmcall_when_loaded()
{
    vmcall_registers_t regs{};

    this->expect_true(common_add_module(m_dummy_start_vmm_success.get(), m_dummy_start_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_stop_vmm_success.get(), m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_add_md_success.get(), m_dummy_add_md_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_get_drr_success.get(), m_dummy_get_drr_success_length) == BF_SUCCESS);
    this->expect_true(common_add_module(m_dummy_misc.get(), m_dummy_misc_length) == BF_SUCCESS);
    this->expect_true(common_load_vmm() == BF_SUCCESS);
    this->expect_true(common_vmcall(&regs, 0) == BF_ERROR_VMM_INVALID_STATE);
    this->expect_true(common_fini() == BF_SUCCESS);
}
