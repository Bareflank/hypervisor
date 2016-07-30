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

#include <entry.h>
#include <common.h>
#include <platform.h>
#include <driver_entry_interface.h>

debug_ring_resources_t *g_drr;

void
driver_entry_ut::test_common_dump_invalid_drr()
{
    EXPECT_TRUE(common_dump_vmm(0, 0) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_common_dump_invalid_vcpuid()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_failure, m_dummy_stop_vmm_failure_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_get_drr_success, m_dummy_get_drr_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_dump_vmm(&g_drr, 100000) == BF_SUCCESS);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_dump_dump_when_unloaded()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_get_drr_success, m_dummy_get_drr_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_dump_vmm(&g_drr, 0) == BF_ERROR_VMM_INVALID_STATE);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_dump_dump_when_corrupt()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_failure, m_dummy_stop_vmm_failure_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_get_drr_success, m_dummy_get_drr_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_stop_vmm() == ENTRY_ERROR_VMM_STOP_FAILED);
    EXPECT_TRUE(common_dump_vmm(&g_drr, 0) == BF_SUCCESS);
    EXPECT_TRUE(common_fini() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

void
driver_entry_ut::test_common_dump_dump_when_loaded()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_get_drr_success, m_dummy_get_drr_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_dump_vmm(&g_drr, 0) == BF_SUCCESS);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_dump_get_drr_missing()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_dump_vmm(&g_drr, 0) == BFELF_ERROR_NO_SUCH_SYMBOL);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_dump_get_drr_failure()
{
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_md_success, m_dummy_add_md_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_get_drr_failure, m_dummy_get_drr_failure_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_dump_vmm(&g_drr, 0) == GET_DRR_FAILURE);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}
