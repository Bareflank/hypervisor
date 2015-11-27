/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <common.h>

#include <debug.h>
#include <platform.h>

#include <bfelf_loader.h>
#include <abi_conversion.h>

/* ========================================================================== */
/* Macros                                                                     */
/* ========================================================================== */

#define VMM_STARTED 1
#define VMM_STOPPED 0

/* ========================================================================== */
/* Global                                                                     */
/* ========================================================================== */

uint32_t g_vmm_status = VMM_STOPPED;

uint32_t g_num_bfelf_files = 0;
struct bfelf_file_t g_bfelf_files[MAX_NUM_MODULES] = {0};

uint32_t g_num_bfelf_execs = 0;
void *g_bfelf_execs[MAX_NUM_MODULES] = {0};

/* ========================================================================== */
/* Implementation                                                             */
/* ========================================================================== */

int32_t
add_module(char *file, int32_t fsize)
{
    int ret;
    int size;
    void *exec;
    struct bfelf_file_t bfelf_file = {0};

    if(g_vmm_status == VMM_STARTED)
    {
        ALERT("add_module: vmm already running\n");
        return BF_ERROR_VMM_ALREADY_STARTED;
    }

    if(g_num_bfelf_files == MAX_NUM_MODULES)
        return BF_ERROR_REACHED_MAX_MODULES;

    ret = bfelf_file_init(file, fsize, &bfelf_file);
    if(ret != BFELF_SUCCESS)
    {
        ALERT("add_module: failed to initialize elf file: %d - %s\n", ret, bfelf_error(ret));
        goto failed;
    }

    size = bfelf_total_exec_size(&bfelf_file);
    if(ret < BFELF_SUCCESS)
    {
        ALERT("add_module: failed to get the module's exec size %d - %s\n", size, bfelf_error(size));
        goto failed;
    }

    exec = platform_alloc_exec(size);
    if(exec == NULL)
    {
        ALERT("add_module: failed alloc memory for exec\n");
        goto failed;
    }

    ret = bfelf_file_load(&bfelf_file, exec, size);
    if(ret != BFELF_SUCCESS)
    {
        ALERT("add_module: failed to load the elf module: %d - %s\n", ret, bfelf_error(ret));
        goto failed_load;
    }

    g_bfelf_execs[g_num_bfelf_execs] = exec;
    g_bfelf_files[g_num_bfelf_files] = bfelf_file;

    g_num_bfelf_execs++;
    g_num_bfelf_files++;

    return BF_SUCCESS;

failed_load:

    platform_free(exec);

failed:

    ALERT("IOCTL_ADD_MODULE: failed\n");
    return ret;
}

void
clear_modules(void)
{
    int i;
    struct bfelf_file_t bfelf_file = {0};

    for(i = 0; i < g_num_bfelf_execs; i++)
        platform_free_exec(g_bfelf_execs[i]);

    for(i = 0; i < MAX_NUM_MODULES; i++)
    {
        g_bfelf_execs[i] = 0;
        g_bfelf_files[i] = bfelf_file;
    }

    g_num_bfelf_execs = 0;
    g_num_bfelf_files = 0;
}

int32_t
start_vmm(void)
{
    int i;
    int ret;
    void *entry = 0;
    struct bfelf_loader_t loader = {0};
    struct e_string entry_str = {"_Z9start_vmmi", 13};

    if(g_vmm_status == VMM_STARTED)
    {
        ALERT("start_vmm: cannot start vmm. vmm already started\n");
        return BF_ERROR_VMM_ALREADY_STARTED;
    }

    if(g_num_bfelf_files <= 0)
    {
        ALERT("start_vmm: cannot start vmm. no modules were added\n");
        return BF_ERROR_NO_MODULES_ADDED;
    }

    ret = bfelf_loader_init(&loader);
    if(ret != BFELF_SUCCESS)
    {
        ALERT("start_vmm: failed to initialize the elf loader: %d - %s\n", ret, bfelf_error(ret));
        return ret;
    }

    for(i = 0; i < g_num_bfelf_files; i++)
    {
        ret = bfelf_loader_add(&loader, &(g_bfelf_files[i]));
        if(ret != BFELF_SUCCESS)
        {
            ALERT("start_vmm: failed to add elf file to the elf loader: %d - %s\n", ret, bfelf_error(ret));
            return ret;
        }
    }

    ret = bfelf_loader_relocate(&loader);
    if(ret != BFELF_SUCCESS)
    {
        ALERT("start_vmm: failed to relocate the elf loader: %d - %s\n", ret, bfelf_error(ret));
        return ret;
    }

    ret = bfelf_resolve_symbol(&g_bfelf_files[0], &entry_str, &entry);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("start_vmm: failed to resolve entry point: %d - %s\n", ret, bfelf_error(ret));
        return ret;
    }
    else
    {
        int64_t ret;
        entry_point_t entry_point = (entry_point_t)entry;

        if((ret = (int64_t)entry_point((void *)0)) == 0)
        {
            DEBUG("\n");
            DEBUG("vmm started successfully:\n");
            DEBUG("    - exit code: %lld\n", ret);
            DEBUG("\n");

            g_vmm_status = VMM_STARTED;
        }
        else
        {
            DEBUG("\n");
            DEBUG("vmm failed to start:\n");
            DEBUG("    - exit code: %lld\n", ret);
            DEBUG("\n");
        }
    }

    return BF_SUCCESS;
}

int32_t
stop_vmm(void)
{
    int ret;
    void *entry = 0;
    struct e_string entry_str = {"_Z8stop_vmmi", 12};

    if(g_vmm_status == VMM_STOPPED)
        return BF_SUCCESS;

    if(g_num_bfelf_files <= 0)
    {
        ALERT("stop_vmm: cannot stop vmm. no modules were added\n");
        return BF_ERROR_NO_MODULES_ADDED;
    }

    ret = bfelf_resolve_symbol(&g_bfelf_files[0], &entry_str, &entry);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("stop_vmm: failed to resolve entry point: %d - %s\n", ret, bfelf_error(ret));
        return ret;
    }
    else
    {
        int64_t ret;
        entry_point_t entry_point = (entry_point_t)entry;

        if((ret = (int64_t)entry_point((void *)0)) == 0)
        {
            DEBUG("\n");
            DEBUG("vmm stopped successfully:\n");
            DEBUG("    - exit code: %lld\n", ret);
            DEBUG("\n");

            clear_modules();

            g_vmm_status = VMM_STOPPED;
        }
        else
        {
            DEBUG("\n");
            DEBUG("vmm failed to stop:\n");
            DEBUG("    - exit code: %lld\n", ret);
            DEBUG("\n");
        }
    }

    return BF_SUCCESS;
}
