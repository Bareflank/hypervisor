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

#include <memory.h>
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
void *g_bfelf_execs[MAX_NUM_MODULES] = {0};
uint64_t g_bfelf_sizes[MAX_NUM_MODULES] = {0};
struct bfelf_file_t g_bfelf_files[MAX_NUM_MODULES] = {0};

/* ========================================================================== */
/* Helpers                                                                    */
/* ========================================================================== */

uint64_t
vmm_status(void)
{
    return g_vmm_status;
}

struct vmm_resources_t *
get_vmmr(void)
{
    return &g_vmmr;
}

struct bfelf_file_t *
get_file(uint64_t index)
{
    if (index >= g_num_bfelf_files)
        return 0;

    return &g_bfelf_files[index];
}

struct bfelf_file_t *
get_next_file(void)
{
    if (g_num_bfelf_files >= MAX_NUM_MODULES)
        return 0;

    return &g_bfelf_files[g_num_bfelf_files];
}

void *
add_elf_file(uint64_t size)
{
    void *exec;
    struct bfelf_file_t *file;

    if (size == 0)
    {
        ALERT("add_elf_file: invalid arg\n");
        return 0;
    }

    file = get_next_file();
    if (file == 0)
    {
        ALERT("add_elf_file: failed to get the next file to add\n");
        return 0;
    }

    exec = platform_alloc_exec(size);
    if (exec == 0)
    {
        ALERT("add_elf_file: out of memory\n");
        return 0;
    }

    g_bfelf_execs[g_num_bfelf_files] = exec;
    g_bfelf_sizes[g_num_bfelf_files] = size;

    g_num_bfelf_files++;

    return exec;
}

void
remove_elf_files(void)
{
    int i;
    struct bfelf_file_t file = {0};

    for (i = 0; i < g_num_bfelf_files; i++)
    {
        platform_free_exec(g_bfelf_execs[i], g_bfelf_sizes[i]);

        g_bfelf_execs[i] = 0;
        g_bfelf_sizes[i] = 0;
        g_bfelf_files[i] = file;
    }

    g_num_bfelf_files = 0;
}

int64_t
symbol_length(const char *sym)
{
    int64_t len = 0;

    if (sym == 0)
        return 0;

    while (sym[len] != '\0')
        len++;

    return len;
}

int64_t
execute_symbol(const char *sym, void *arg)
{
    int ret = 0;
    void *entry = 0;
    struct e_string_t entry_str = {0};
    struct bfelf_file_t *bfelf_file = 0;

    entry_str.buf = sym;
    entry_str.len = symbol_length(sym);

    if (sym == 0)
    {
        ALERT("execute_symbol: invalid arguments\n");
        return BF_ERROR_INVALID_ARG;
    }

    bfelf_file = get_file(0);
    if (bfelf_file == 0)
    {
        ALERT("execute_symbol: failed because no modules were loaded\n");
        return BF_ERROR_NO_MODULES_ADDED;
    }

    ret = bfelf_resolve_symbol(bfelf_file, &entry_str, &entry);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("start_vmm: failed to resolve entry point: %d - %s\n", ret, bfelf_error(ret));
        return ret;
    }
    else
    {
        void *ret;
        entry_point_t entry_point = (entry_point_t)entry;

        if ((ret = entry_point(arg)) == VMM_SUCCESS)
        {
            DEBUG("\n");
            DEBUG("%s executed successfully:\n", sym);
            DEBUG("    - exit code: %p\n", ret);
            DEBUG("\n");

            return BF_SUCCESS;
        }
        else
        {
            DEBUG("\n");
            DEBUG("%s failed:\n", sym);
            DEBUG("    - exit code: %p\n", ret);
            DEBUG("\n");

            return BF_ERROR_FAILED_TO_EXECUTE_SYMBOL;
        }
    }

    return BF_ERROR_UNKNOWN;
}

/* ========================================================================== */
/* Implementation                                                             */
/* ========================================================================== */

int64_t
common_init(void)
{
    int i;
    struct vmm_resources_t *vmmr = get_vmmr();

    if (vmmr == 0)
        return BF_ERROR_INVALID_ARG;

    if (g_drr == 0)
    {
        g_drr = platform_alloc(DEBUG_RING_SIZE);
        if (g_drr == 0)
        {
            ALERT("start_vmm: failed to allocate memory for the debug ring\n");
            return BF_ERROR_FAILED_TO_ALLOC_DRR;
        }

        vmmr->drr = g_drr;
        vmmr->drr->len = DEBUG_RING_SIZE - sizeof(struct debug_ring_resources);
    }

    for (i = 0; i < MAX_PAGES; i++)
    {
        if (vmmr->pages[i].virt == 0)
        {
            struct page_t pg = platform_alloc_page();

            if (pg.virt == 0 || pg.phys == 0)
                return BF_ERROR_OUT_OF_MEMORY;

            vmmr->pages[i] = pg;
        }
    }

    return BF_SUCCESS;
}

int64_t
common_fini(void)
{
    int i;
    struct page_t blank_pg = {0};
    struct vmm_resources_t *vmmr = get_vmmr();

    if (vmmr == 0)
        return BF_ERROR_INVALID_ARG;

    if (common_stop_vmm() != BF_SUCCESS)
        ALERT("common_fini: failed to stop vmm\n");

    if (g_drr != 0)
    {
        platform_free(g_drr);
        g_drr = 0;
    }

    for (i = 0; i < MAX_PAGES; i++)
    {
        platform_free_page(vmmr->pages[i]);
        vmmr->pages[i] = blank_pg;
    }

    return BF_SUCCESS;
}

int64_t
common_add_module(char *file, int64_t fsize)
{
    int ret;
    int size;
    void *exec;
    struct bfelf_file_t *bfelf_file;

    if (file == 0 || fsize == 0)
    {
        ALERT("add_module: invalid arguments\n");
        return BF_ERROR_INVALID_ARG;
    }

    if (vmm_status() == VMM_STARTED)
    {
        ALERT("add_module: vmm already running\n");
        return BF_ERROR_VMM_ALREADY_STARTED;
    }

    bfelf_file = get_next_file();
    if (bfelf_file == 0)
    {
        ALERT("add_module: failed to get the next file to add\n");
        return BF_ERROR_MAX_MODULES_REACHED;
    }

    ret = bfelf_file_init(file, fsize, bfelf_file);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("add_module: failed to initialize elf file: %d - %s\n", ret, bfelf_error(ret));
        return ret;
    }

    size = bfelf_total_exec_size(bfelf_file);
    if (ret < BFELF_SUCCESS)
    {
        ALERT("add_module: failed to get the module's exec size %d - %s\n", size, bfelf_error(size));
        return ret;
    }

    exec = add_elf_file(size);
    if (exec == 0)
    {
        ALERT("add_module: failed to add file: %d\n", ret);
        return BF_ERROR_FAILED_TO_ADD_FILE;
    }

    ret = bfelf_file_load(bfelf_file, exec, size);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("add_module: failed to load the elf module: %d - %s\n", ret, bfelf_error(ret));
        return ret;
    }

    return BF_SUCCESS;
}

int64_t
common_start_vmm(void)
{
    int i = 0;
    int ret = 0;
    struct bfelf_loader_t loader = {0};
    struct bfelf_file_t *bfelf_file = 0;

    if (vmm_status() == VMM_STARTED)
        return BF_SUCCESS;

    ret = bfelf_loader_init(&loader);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("start_vmm: failed to initialize the elf loader: %d - %s\n", ret, bfelf_error(ret));
        return ret;
    }

    while ((bfelf_file = get_file(i++)) != 0)
    {
        ret = bfelf_loader_add(&loader, bfelf_file);
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

    ret = execute_symbol("_Z9start_vmmPv", get_vmmr());
    if (ret != BF_SUCCESS)
    {
        ALERT("start_vmm: failed to execute symbol: %d\n", ret);
        return ret;
    }

    g_vmm_status = VMM_STARTED;
    return BF_SUCCESS;
}

int64_t
common_stop_vmm(void)
{
    int ret;

    if (vmm_status() == VMM_STARTED)
    {
        ret = execute_symbol("_Z8stop_vmmPv", 0);
        if (ret != BFELF_SUCCESS)
        {
            ALERT("stop_vmm: failed to execute symbol: %d\n", ret);
            return ret;
        }
    }

    remove_elf_files();

    g_vmm_status = VMM_STOPPED;
    return BF_SUCCESS;
}

int64_t
common_dump_vmm(void)
{
    int i;
    char *rb;

    rb = platform_alloc(DEBUG_RING_SIZE);
    if (rb == 0)
    {
        ALERT("dump_vmm: failed to allocate memory for the read buffer\n");
        return BF_ERROR_FAILED_TO_ALLOC_RB;
    }

    for (i = 0; i < DEBUG_RING_SIZE; i++)
        rb[i] = 0;

    if (debug_ring_read(g_drr, rb, DEBUG_RING_SIZE) < 0)
        ALERT("dump_vmm: failed to read debug ring\n");

    INFO("\n");
    INFO("VMM DUMP:\n");
    INFO("============================================================\n");
    INFO("\n%s\n", rb);
    INFO("============================================================\n");
    INFO("\n");

    if (rb != 0)
        platform_free(rb);

    return BF_SUCCESS;
}
