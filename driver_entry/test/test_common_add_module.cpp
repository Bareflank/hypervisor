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

#include <common.h>
#include <platform.h>
#include <constants.h>

void
driver_entry_ut::test_common_add_module_invalid_file()
{
    EXPECT_TRUE(common_add_module(0, m_dummy_misc_length) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_common_add_module_invalid_file_size()
{
    EXPECT_TRUE(common_add_module(m_dummy_misc, 0) == BF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_common_add_module_garbage_module()
{
    char file[] = "this is clearly not an ELF file!!!";

    EXPECT_TRUE(common_add_module(file, strlen(file)) == BFELF_ERROR_INVALID_ARG);
}

void
driver_entry_ut::test_common_add_module_add_when_already_loaded()
{
    EXPECT_TRUE(common_add_module(m_dummy_add_mdl_success, m_dummy_add_mdl_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_LOADED);
    EXPECT_TRUE(common_add_module(m_dummy_get_drr_success, m_dummy_get_drr_success_length) == BF_ERROR_VMM_INVALID_STATE);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_add_module_add_when_already_running()
{
    EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_success, m_dummy_stop_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_mdl_success, m_dummy_add_mdl_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_vmm_status() == VMM_RUNNING);
    EXPECT_TRUE(common_add_module(m_dummy_get_drr_success, m_dummy_get_drr_success_length) == BF_ERROR_VMM_INVALID_STATE);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}

void
driver_entry_ut::test_common_add_module_add_when_corrupt()
{
    EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_start_vmm_success, m_dummy_start_vmm_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_stop_vmm_failure, m_dummy_stop_vmm_failure_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_add_mdl_success, m_dummy_add_mdl_success_length) == BF_SUCCESS);
    EXPECT_TRUE(common_add_module(m_dummy_misc, m_dummy_misc_length) == BF_SUCCESS);
    EXPECT_TRUE(common_load_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_start_vmm() == BF_SUCCESS);
    EXPECT_TRUE(common_fini() == BF_ERROR_VMM_CORRUPTED);
    EXPECT_TRUE(common_vmm_status() == VMM_CORRUPT);
    EXPECT_TRUE(common_add_module(m_dummy_get_drr_success, m_dummy_get_drr_success_length) == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

void
driver_entry_ut::test_common_add_module_add_too_many()
{
    for (auto i = 0U; i < MAX_NUM_MODULES; i++)
        EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_SUCCESS);

    EXPECT_TRUE(common_add_module(m_dummy_init_vmm_success, m_dummy_init_vmm_success_length) == BF_ERROR_MAX_MODULES_REACHED);
    EXPECT_TRUE(common_fini() == BF_SUCCESS);
}
