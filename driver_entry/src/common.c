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

#include <debug.h>
#include <common.h>
#include <platform.h>

#include <bfelf_loader.h>

#include <entry.h>
#include <memory.h>
#include <constants.h>
#include <debug_ring_interface.h>

/* ========================================================================== */
/* Global                                                                     */
/* ========================================================================== */

int64_t g_vmm_status = VMM_UNLOADED;

uint64_t g_num_bfelf_files = 0;
void *g_bfelf_execs[MAX_NUM_MODULES] = {0};
uint64_t g_bfelf_sizes[MAX_NUM_MODULES] = {0};
struct bfelf_file_t g_bfelf_files[MAX_NUM_MODULES] = {0};

// struct page_t page_pool[MAX_PAGES] = {0};

/* ========================================================================== */
/* Helpers                                                                    */
/* ========================================================================== */

int64_t
set_vmm_status(int64_t status)
{
    int64_t old_status = g_vmm_status;
    g_vmm_status = status;
    return old_status;
}

uint64_t
vmm_status(void)
{
    return g_vmm_status;
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
    int i;
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

    DEBUG("adding module of size: 0x%x    at: %p\n", (int)size, exec);

    for (i = 0; i < size; i++)
        ((char *)exec)[i] = 0;

    g_bfelf_execs[g_num_bfelf_files] = exec;
    g_bfelf_sizes[g_num_bfelf_files] = size;

    g_num_bfelf_files++;

    return exec;
}

int64_t
remove_elf_files(void)
{
    int i, j;
    struct bfelf_file_t file = {0};

    for (i = 0; i < g_num_bfelf_files; i++)
    {
        for (j = 0; j < g_bfelf_sizes[i]; j++)
            ((char *)g_bfelf_execs[i])[j] = 0;

        DEBUG("removing module of size: 0x%x\n", (int)g_bfelf_sizes[i]);

        platform_free_exec(g_bfelf_execs[i], g_bfelf_sizes[i]);

        g_bfelf_execs[i] = 0;
        g_bfelf_sizes[i] = 0;
        g_bfelf_files[i] = file;
    }

    g_num_bfelf_files = 0;

    return BF_SUCCESS;
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
resolve_symbol(const char *name, void **sym)
{
    int ret;
    struct e_string_t str = {0};
    struct bfelf_file_t *bfelf_file = get_file(0);

    if (name == 0 || sym == 0)
        return BF_ERROR_INVALID_ARG;

    str.buf = name;
    str.len = symbol_length(name);

    ret = bfelf_resolve_symbol(bfelf_file, &str, sym);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("%s could not be found: %d - %s\n", name, ret, bfelf_error(ret));
        return ret;
    }

    return BF_SUCCESS;
}

int64_t
execute_symbol(const char *sym)
{
    int ret = 0;
    entry_point_t entry_point;

    if (sym == 0)
        return BF_ERROR_INVALID_ARG;

    ret = resolve_symbol(sym, (void **)&entry_point);
    if (ret != BF_SUCCESS)
    {
        ALERT("execute_symbol: failed to resolve entry point: %d\n", ret);
        return ret;
    }

    ret = entry_point(0);
    if (ret != ENTRY_SUCCESS)
    {
        DEBUG("\n");
        DEBUG("%s failed:\n", sym);
        DEBUG("    - exit code: %ld\n", (long)ret);
        DEBUG("\n");

        return ret;
    }

    DEBUG("\n");
    DEBUG("%s executed successfully:\n", sym);
    DEBUG("    - exit code: %ld\n", (long)ret);
    DEBUG("\n");

    return BF_SUCCESS;
}

int64_t
allocate_page_pool(void)
{
    // int i;
    // int ret;
    // add_page_t add_page;

    // ret = resolve_symbol("add_page", (void **)&add_page);
    // if (ret != BF_SUCCESS)
    // {
    //     ALERT("allocate_page_pool: failed to locate add_page. the symbol is missing or not loaded\n");
    //     return ret;
    // }

    // for (i = 0; i < MAX_PAGES; i++)
    // {
    //     if (page_pool[i].virt != 0)
    //         continue;

    //     page_pool[i] = platform_alloc_page();

    //     if (page_pool[i].virt == 0)
    //         return BF_ERROR_OUT_OF_MEMORY;

    //     ret = add_page(&page_pool[i]);
    //     if (ret != MEMORY_MANAGER_SUCCESS)
    //     {
    //         ALERT("allocate_page_pool: failed to add page to memory manager\n");
    //         return ret;
    //     }
    // }

    return BF_SUCCESS;
}

int64_t
free_page_pool(void)
{
    // int i;
    // int ret;
    // remove_page_t remove_page;

    // ret = resolve_symbol("remove_page", (void **)&remove_page);
    // if (ret != BF_SUCCESS)
    // {
    //     ALERT("free_page_pool: failed to locate remove_page. the symbol is missing or not loaded\n");
    //     return ret;
    // }

    // for (i = 0; i < MAX_PAGES; i++)
    // {
    //     struct page_t blank_page = {0};

    //     if (page_pool[i].virt == 0)
    //         continue;

    //     ret = remove_page(&page_pool[i]);
    //     if (ret != MEMORY_MANAGER_SUCCESS)
    //     {
    //         ALERT("free_page_pool: failed to remove page from memory manager\n");
    //         return ret;
    //     }

    //     platform_free_page(page_pool[i]);
    //     page_pool[i] = blank_page;
    // }

    return BF_SUCCESS;
}

/* ========================================================================== */
/* Implementation                                                             */
/* ========================================================================== */

int64_t
common_init(void)
{
    return BF_SUCCESS;
}

int64_t
common_fini(void)
{
    if (common_stop_vmm() != BF_SUCCESS)
        ALERT("common_fini: failed to stop vmm\n");

    if (common_unload_vmm() != BF_SUCCESS)
        ALERT("common_fini: failed to unload vmm\n");

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

    if (vmm_status() == VMM_CORRUPT)
    {
        ALERT("add_module: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (vmm_status() != VMM_UNLOADED)
    {
        ALERT("add_module: failed to add module. the vmm must be stopped, and unloaded prior to adding modules\n");
        return BF_ERROR_VMM_INVALID_STATE;
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
    if (size < BFELF_SUCCESS)
    {
        ALERT("add_module: failed to get the module's exec size %d - %s\n", size, bfelf_error(size));
        return size;
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
common_load_vmm(void)
{
    int i = 0;
    int ret = 0;
    struct bfelf_loader_t loader = {0};
    struct bfelf_file_t *bfelf_file = 0;

    if (vmm_status() == VMM_CORRUPT)
    {
        ALERT("load_vmm: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (vmm_status() == VMM_LOADED)
        return BF_SUCCESS;

    if (vmm_status() == VMM_RUNNING)
    {
        ALERT("load_vmm: failed to load vmm. vmm cannot be loaded while another vmm is running\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

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

    ret = allocate_page_pool();
    if (ret != BF_SUCCESS)
    {
        ALERT("start_vmm: failed to allocate page pool: %d\n", ret);
        return ret;
    }

    g_vmm_status = VMM_LOADED;
    return BF_SUCCESS;
}

int64_t
common_unload_vmm(void)
{
    int ret;

    if (vmm_status() == VMM_CORRUPT)
    {
        ALERT("unload_vmm: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (vmm_status() == VMM_RUNNING)
    {
        ALERT("unload_vmm: failed to unload vmm. cannot unload a vmm that is still running\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    if (vmm_status() == VMM_LOADED)
    {
        ret = free_page_pool();
        if (ret != BF_SUCCESS)
        {
            ALERT("unload_vmm: failed to free page pool: %d\n", ret);
            goto corrupted;
        }
    }

    ret = remove_elf_files();
    if (ret != BF_SUCCESS)
    {
        ALERT("stop_vmm: failed to remove elf files: %d\n", ret);
        goto corrupted;
    }

    g_vmm_status = VMM_UNLOADED;
    return BF_SUCCESS;

corrupted:

    g_vmm_status = VMM_CORRUPT;
    return ret;
}

int64_t
common_start_vmm(void)
{
    int ret = 0;

    if (vmm_status() == VMM_CORRUPT)
    {
        ALERT("start_vmm: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (vmm_status() == VMM_RUNNING)
        return BF_SUCCESS;

    if (vmm_status() == VMM_UNLOADED)
    {
        ALERT("start_vmm: failed to start vmm. the vmm must be loaded prior to starting\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    ret = execute_symbol("init_vmm");
    if (ret != BF_SUCCESS)
    {
        ALERT("start_vmm: failed to execute init_vmm: %d\n", ret);
        return ret;
    }

    ret = execute_symbol("start_vmm");
    if (ret != BF_SUCCESS)
    {
        ALERT("start_vmm: failed to execute start_vmm: %d\n", ret);
        return ret;
    }

    g_vmm_status = VMM_RUNNING;
    return BF_SUCCESS;
}

int64_t
common_stop_vmm(void)
{
    int ret;

    if (vmm_status() == VMM_CORRUPT)
    {
        ALERT("stop_vmm: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (vmm_status() == VMM_LOADED)
        return BF_SUCCESS;

    if (vmm_status() == VMM_UNLOADED)
    {
        ALERT("start_vmm: failed to stop vmm. the vmm must be loaded and running prior to stoping\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    ret = execute_symbol("stop_vmm");
    if (ret != BFELF_SUCCESS)
    {
        ALERT("stop_vmm: failed to execute symbol: %d\n", ret);
        goto corrupted;
    }

    g_vmm_status = VMM_LOADED;
    return BF_SUCCESS;

corrupted:

    g_vmm_status = VMM_CORRUPT;
    return ret;
}

int64_t
common_dump_vmm(void)
{
    int i;
    int j;
    int ret;
    char *rb1;
    char *rb2;
    get_drr_t get_drr;
    struct debug_ring_resources_t *drr = 0;

    if (vmm_status() == VMM_CORRUPT)
    {
        ALERT("dump_vmm: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (vmm_status() == VMM_UNLOADED)
    {
        ALERT("dump_vmm: failed to dump vmm as it has not been loaded yet\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    rb1 = platform_alloc(DEBUG_RING_SIZE);
    rb2 = platform_alloc(DEBUG_RING_SIZE + 1);
    if (rb1 == 0 || rb2 == 0)
    {
        ALERT("dump_vmm: failed to allocate memory for the read buffer\n");
        return BF_ERROR_OUT_OF_MEMORY;
    }

    for (i = 0; i < DEBUG_RING_SIZE; i++)
    {
        rb1[i] = 0;
        rb2[i] = 0;
    }

    ret = resolve_symbol("get_drr", (void **)&get_drr);
    if (ret != BF_SUCCESS)
    {
        ALERT("dump_vmm: failed to locate get_drr. the symbol is missing or not loaded\n");
        goto failure;
    }

    drr = get_drr(0);
    if (drr == 0)
    {
        ALERT("dump_vmm: failed to get debug ring resources\n");
        goto failure;
    }

    if (debug_ring_read(drr, rb1, DEBUG_RING_SIZE) < 0)
    {
        ALERT("dump_vmm: failed to read debug ring\n");
        goto failure;
    }

    DEBUG("\n");
    DEBUG("VMM DUMP:\n");
    DEBUG("================================================================================\n");
    DEBUG("\n");

    for (i = 0, j = 0; i < DEBUG_RING_SIZE; i++, j++)
    {
        rb2[j] = rb1[i];

        /**
         * In this case, the user got to the end of the buffer, and they
         * had a new line, which means that we can stop.
         */
        if (rb1[i] == '\0' && j == 0)
            break;

        /**
         * In this case, we are at the end of the ring buffer, but the user
         * forgot to add a newline at the end, so we add one instead.
         */
        if (rb1[i] == '\0')
            rb2[j] = '\n';

        /**
         * On each newline, we print out the next string. We do not need to
         * add a newline as it already exists in the buffer itself.
         */
        if (rb2[j] == '\n')
        {
            rb2[j + 1] = '\0';
            DEBUG("%s", rb2);

            j = -1;
        }
    }

    DEBUG("\n");
    DEBUG("================================================================================\n");
    DEBUG("\n");

    platform_free(rb1);
    platform_free(rb2);
    return BF_SUCCESS;

failure:

    platform_free(rb1);
    platform_free(rb2);
    return BF_ERROR_FAILED_TO_DUMP_DR;
}
