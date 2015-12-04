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
#include <debug_ring_interface.h>

/* ========================================================================== */
/* Macros                                                                     */
/* ========================================================================== */

#ifndef DEBUG_RING_SIZE
#define DEBUG_RING_SIZE (10 * 4096)
#endif

/* ========================================================================== */
/* Global                                                                     */
/* ========================================================================== */

uint64_t g_vmm_status = VMM_STOPPED;

void *g_drr = 0;
struct vmm_resources_t g_vmmr = {0};

uint64_t g_num_bfelf_files = 0;
struct bfelf_file_t g_bfelf_files[MAX_NUM_MODULES] = {0};

uint64_t g_num_bfelf_execs = 0;
void *g_bfelf_execs[MAX_NUM_MODULES] = {0};

/* ========================================================================== */
/* Helpers                                                                    */
/* ========================================================================== */

void
clear_modules(void)
{
    int i;
    struct bfelf_file_t bfelf_file = {0};

    for (i = 0; i < g_num_bfelf_execs; i++)
        platform_free_exec(g_bfelf_execs[i]);

    for (i = 0; i < MAX_NUM_MODULES; i++)
    {
        g_bfelf_execs[i] = 0;
        g_bfelf_files[i] = bfelf_file;
    }

    g_num_bfelf_execs = 0;
    g_num_bfelf_files = 0;
}

uint64_t
vmm_status(void)
{
    return g_vmm_status;
}

uint64_t
num_elf_files(void)
{
    return g_num_bfelf_files;
}

struct bfelf_file_t *
elf_file(uint64_t index)
{
    if (index >= g_num_bfelf_files)
        ALERT("elf file index out of range\n");

    return &g_bfelf_files[index];
}

/* ========================================================================== */
/* Implementation                                                             */
/* ========================================================================== */

int64_t
common_init(void)
{
    g_drr = platform_alloc(DEBUG_RING_SIZE);
    if (g_drr == NULL)
    {
        ALERT("start_vmm: failed to allocate memory for the debug ring\n");
        return BF_ERROR_FAILED_TO_ALLOC_DRR;
    }

    g_vmmr.drr = g_drr;
    g_vmmr.drr->len = DEBUG_RING_SIZE - sizeof(struct debug_ring_resources);

    return BF_SUCCESS;
}

int64_t
common_fini(void)
{
    if (common_stop_vmm() != BF_SUCCESS)
        ALERT("common_fini: failed to stop vmm\n");

    if (g_drr != 0)
    {
        platform_free(g_drr);
        g_drr = 0;
    }

    return BF_SUCCESS;
}

int64_t
common_add_module(char *file, int64_t fsize)
{
    int ret;
    int size;
    void *exec;
    struct bfelf_file_t bfelf_file = {0};

    if (g_vmm_status == VMM_STARTED)
    {
        ALERT("add_module: vmm already running\n");
        return BF_ERROR_VMM_ALREADY_STARTED;
    }

    if (g_num_bfelf_files == MAX_NUM_MODULES)
        return BF_ERROR_REACHED_MAX_MODULES;

    ret = bfelf_file_init(file, fsize, &bfelf_file);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("add_module: failed to initialize elf file: %d - %s\n", ret, bfelf_error(ret));
        goto failed;
    }

    size = bfelf_total_exec_size(&bfelf_file);
    if (ret < BFELF_SUCCESS)
    {
        ALERT("add_module: failed to get the module's exec size %d - %s\n", size, bfelf_error(size));
        goto failed;
    }

    exec = platform_alloc_exec(size);
    if (exec == NULL)
    {
        ALERT("add_module: failed alloc memory for exec\n");
        goto failed;
    }

    ret = bfelf_file_load(&bfelf_file, exec, size);
    if (ret != BFELF_SUCCESS)
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

int64_t
common_start_vmm(void)
{
    int i;
    int ret;
    void *entry = 0;
    struct bfelf_loader_t loader = {0};
    struct e_string_t entry_str = {"_Z9start_vmmPv", 14};

    if (g_vmm_status == VMM_STARTED)
    {
        ALERT("start_vmm: cannot start vmm. vmm already started\n");
        return BF_ERROR_VMM_ALREADY_STARTED;
    }

    if (g_num_bfelf_files <= 0)
    {
        ALERT("start_vmm: cannot start vmm. no modules were added\n");
        return BF_ERROR_NO_MODULES_ADDED;
    }

    ret = bfelf_loader_init(&loader);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("start_vmm: failed to initialize the elf loader: %d - %s\n", ret, bfelf_error(ret));
        return ret;
    }

    for (i = 0; i < g_num_bfelf_files; i++)
    {
        ret = bfelf_loader_add(&loader, &(g_bfelf_files[i]));
        if (ret != BFELF_SUCCESS)
        {
            ALERT("start_vmm: failed to add elf file to the elf loader: %d - %s\n", ret, bfelf_error(ret));
            return ret;
        }
    }

    ret = bfelf_loader_relocate(&loader);
    if (ret != BFELF_SUCCESS)
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
        void *ret;
        entry_point_t entry_point = (entry_point_t)entry;

        if ((ret = entry_point(&g_vmmr)) == VMM_SUCCESS)
        {
            DEBUG("\n");
            DEBUG("vmm started successfully:\n");
            DEBUG("    - exit code: %p\n", ret);
            DEBUG("\n");

            goto success;
        }
        else
        {
            DEBUG("\n");
            DEBUG("vmm failed to start:\n");
            DEBUG("    - exit code: %p\n", ret);
            DEBUG("\n");

            return BF_ERROR_FAILED_TO_START_VMM;
        }
    }

success:

    g_vmm_status = VMM_STARTED;
    return BF_SUCCESS;
}

int64_t
common_stop_vmm(void)
{
    int ret;
    void *entry = 0;
    struct e_string_t entry_str = {"_Z8stop_vmmPv", 13};

    if (vmm_status() == VMM_STOPPED)
        goto success;

    if (num_elf_files() <= 0)
    {
        ALERT("stop_vmm: cannot stop vmm. no modules were added\n");
        return BF_ERROR_NO_MODULES_ADDED;
    }

    ret = bfelf_resolve_symbol(elf_file(0), &entry_str, &entry);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("stop_vmm: failed to resolve entry point: %d - %s\n", ret, bfelf_error(ret));
        return ret;
    }
    else
    {
        void *ret;
        entry_point_t entry_point = (entry_point_t)entry;

        if ((ret = entry_point(0)) == VMM_SUCCESS)
        {
            DEBUG("\n");
            DEBUG("vmm stopped successfully:\n");
            DEBUG("    - exit code: %p\n", ret);
            DEBUG("\n");

            if (common_dump_vmm() != BF_SUCCESS)
                ALERT("common_fini: failed to dump vmm\n");

            goto success;
        }
        else
        {
            DEBUG("\n");
            DEBUG("vmm failed to stop:\n");
            DEBUG("    - exit code: %p\n", ret);
            DEBUG("\n");

            if (common_dump_vmm() != BF_SUCCESS)
                ALERT("common_fini: failed to dump vmm\n");

            return BF_ERROR_FAILED_TO_STOP_VMM;
        }
    }

success:

    clear_modules();

    g_vmm_status = VMM_STOPPED;
    return BF_SUCCESS;
}

int64_t
common_dump_vmm(void)
{
    int i;
    int ret;
    char *rb;

    rb = platform_alloc(DEBUG_RING_SIZE);
    if (rb == NULL)
    {
        ALERT("dump_vmm: failed to allocate memory for the read buffer\n");
        return BF_ERROR_FAILED_TO_ALLOC_RB;
    }

    for (i = 0; i < DEBUG_RING_SIZE; i++)
        rb[i] = 0;

    if ((ret = debug_ring_read(g_drr, rb, DEBUG_RING_SIZE)) < 0)
    {
        ALERT("dump_vmm: failed to dump debug ring\n");
        return BF_ERROR_FAILED_TO_DUMP_DR;
    }

    INFO("\n");
    INFO("VMM DUMP:\n");
    INFO("============================================================\n");
    INFO("%s\n", rb);
    INFO("============================================================\n");
    INFO("\n");

    return BF_SUCCESS;
}
