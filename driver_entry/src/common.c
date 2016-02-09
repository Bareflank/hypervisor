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

#include <entry.h>
#include <memory.h>
#include <constants.h>
#include <driver_entry_interface.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

int64_t g_vmm_status = VMM_UNLOADED;

uint64_t g_num_modules = 0;
struct module_t g_modules[MAX_NUM_MODULES] = {0};

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

struct module_t *
get_module(uint64_t index)
{
    if (index >= g_num_modules)
        return 0;

    return &(g_modules[index]);
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
    int64_t ret;
    struct e_string_t str = {0};
    struct module_t *module = get_module(0);

    if (name == 0 || sym == 0)
        return BF_ERROR_INVALID_ARG;

    if (module == 0)
        return BF_ERROR_NO_MODULES_ADDED;

    str.buf = name;
    str.len = symbol_length(name);

    ret = bfelf_resolve_symbol(&module->file, &str, sym);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("%s could not be found: %" PRId64 " - %s\n", name, ret, bfelf_error(ret));
        return ret;
    }

    return BF_SUCCESS;
}

int64_t
execute_symbol(const char *sym, int64_t arg)
{
    int64_t ret = 0;
    entry_point_t entry_point;

    if (sym == 0)
        return BF_ERROR_INVALID_ARG;

    ret = resolve_symbol(sym, (void **)&entry_point);
    if (ret != BF_SUCCESS)
    {
        ALERT("execute_symbol: failed to resolve entry point: %" PRId64 "\n", ret);
        return ret;
    }

    ret = entry_point(arg);
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
execute_ctors(struct bfelf_file_t *bfelf_file)
{
    int64_t i = 0;
    int64_t ret = 0;

    if (bfelf_file == 0)
        return BF_ERROR_INVALID_ARG;

    for (i = 0; i < bfelf_ctor_num(bfelf_file); i++)
    {
        ctor_func func;

        ret = bfelf_resolve_ctor(bfelf_file, i, (void **)&func);
        if (ret != BF_SUCCESS)
        {
            ALERT("execute_ctors: failed to resolve ctor: %" PRId64 "\n", ret);
            return ret;
        }

        func();
    }

    return BF_SUCCESS;
}

int64_t
execute_dtors(struct bfelf_file_t *bfelf_file)
{
    int64_t i = 0;
    int64_t ret = 0;

    if (bfelf_file == 0)
        return BF_ERROR_INVALID_ARG;

    for (i = 0; i < bfelf_dtor_num(bfelf_file); i++)
    {
        dtor_func func;

        ret = bfelf_resolve_dtor(bfelf_file, i, (void **)&func);
        if (ret != BF_SUCCESS)
        {
            ALERT("execute_dtors: failed to resolve dtor: %" PRId64 "\n", ret);
            return ret;
        }

        func();
    }

    return BF_SUCCESS;
}

int64_t
execute_inits(struct bfelf_file_t *bfelf_file)
{
    int64_t i = 0;
    int64_t ret = 0;

    if (bfelf_file == 0)
        return BF_ERROR_INVALID_ARG;

    for (i = 0; i < bfelf_init_num(bfelf_file); i++)
    {
        init_func func;

        ret = bfelf_resolve_init(bfelf_file, i, (void **)&func);
        if (ret != BF_SUCCESS)
        {
            ALERT("execute_inits: failed to resolve init: %" PRId64 "\n", ret);
            return ret;
        }

        func();
    }

    return BF_SUCCESS;
}

int64_t
execute_finis(struct bfelf_file_t *bfelf_file)
{
    int64_t i = 0;
    int64_t ret = 0;

    if (bfelf_file == 0)
        return BF_ERROR_INVALID_ARG;

    for (i = 0; i < bfelf_fini_num(bfelf_file); i++)
    {
        fini_func func;

        ret = bfelf_resolve_fini(bfelf_file, i, (void **)&func);
        if (ret != BF_SUCCESS)
        {
            ALERT("execute_finis: failed to resolve fini: %" PRId64 "\n", ret);
            return ret;
        }

        func();
    }

    return BF_SUCCESS;
}

int64_t
add_mdl_to_memory_manager(char *exec, uint64_t size)
{
    int64_t i = 0;
    int64_t ret = 0;
    int64_t num = 0;
    uint64_t page = 0;
    add_mdl_t add_mdl = 0;
    struct memory_descriptor *mdl;

    if (exec == 0 || size == 0)
        return BF_ERROR_INVALID_ARG;

    num = (size / MAX_PAGE_SIZE);
    if (size % MAX_PAGE_SIZE != 0)
        num++;

    mdl = (struct memory_descriptor *)platform_alloc(num * sizeof(struct memory_descriptor));
    if (mdl == 0)
    {
        ALERT("add_mdl_to_memory_manager: failed to allocate mdl\n");
        return BF_ERROR_OUT_OF_MEMORY;
    }

    for (i = 0; i < num; i++, page += MAX_PAGE_SIZE)
    {
        mdl[i].virt = exec + page;
        mdl[i].phys = platform_virt_to_phys(mdl[i].virt);
        mdl[i].size = MAX_PAGE_SIZE;
        mdl[i].type = 0;
    }

    ret = resolve_symbol("add_mdl", (void **)&add_mdl);
    if (ret != BF_SUCCESS)
    {
        ALERT("add_mdl_to_memory_manager: failed to locate add_mdl. "
              "the symbol is missing or not loaded\n");
        goto failure;
    }

    ret = add_mdl(mdl, num);
    if (ret != MEMORY_MANAGER_SUCCESS)
    {
        ALERT("add_mdl_to_memory_manager: failed to add mdl.\n");
        goto failure;
    }

    platform_free(mdl);
    return BF_SUCCESS;

failure:

    platform_free(mdl);
    return ret;
}

/* -------------------------------------------------------------------------- */
/* Implementation                                                             */
/* -------------------------------------------------------------------------- */

int64_t
common_vmm_status(void)
{
    return g_vmm_status;
}

int64_t
common_reset(void)
{
    uint64_t i;
    struct bfelf_file_t file = {0};

    for (i = 0; i < g_num_modules; i++)
    {
        platform_free_exec(g_modules[i].exec, g_modules[i].size);

        g_modules[i].exec = 0;
        g_modules[i].size = 0;
        g_modules[i].file = file;
    }

    g_num_modules = 0;
    g_vmm_status = VMM_UNLOADED;

    return BF_SUCCESS;
}

int64_t
common_init(void)
{
    return BF_SUCCESS;
}

int64_t
common_fini(void)
{
    int64_t ret = 0;

    if (common_vmm_status() == VMM_RUNNING)
    {
        ret = common_stop_vmm();
        if (ret != BF_SUCCESS)
            ALERT("common_fini: failed to stop vmm\n");
    }

    if (common_vmm_status() == VMM_LOADED)
    {
        ret = common_unload_vmm();
        if (ret != BF_SUCCESS)
            ALERT("common_fini: failed to unload vmm\n");
    }

    if (common_vmm_status() == VMM_CORRUPT)
        return BF_ERROR_VMM_CORRUPTED;

    if (common_vmm_status() == VMM_UNLOADED && g_num_modules > 0)
    {
        ret = common_reset();
        if (ret != BF_SUCCESS)
            ALERT("common_fini: failed to reset\n");
    }

    return ret;
}

int64_t
common_add_module(char *file, int64_t fsize)
{
    int64_t ret = 0;
    struct module_t *module = 0;

    /*
     * TODO: Might not be a bad idea to add the ability to detect when a
     * module is alreayed added. Since we want the ability to have signed
     * modules, we could combine the two and kill two birds with one stone.
     */

    if (file == 0 || fsize == 0)
    {
        ALERT("add_module: invalid arguments\n");
        return BF_ERROR_INVALID_ARG;
    }

    if (common_vmm_status() == VMM_CORRUPT)
    {
        ALERT("add_module: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (common_vmm_status() != VMM_UNLOADED)
    {
        ALERT("add_module: failed to add module. the vmm must be stopped, "
              "and unloaded prior to adding modules\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    if (g_num_modules >= MAX_NUM_MODULES)
    {
        ALERT("add_module: too many modules loaded\n");
        return BF_ERROR_MAX_MODULES_REACHED;
    }

    module = &(g_modules[g_num_modules]);

    ret = bfelf_file_init(file, fsize, &module->file);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("add_module: failed to initialize elf file: %" PRId64 " - %s\n",
              ret, bfelf_error(ret));
        return ret;
    }

    module->size = bfelf_total_exec_size(&module->file);
    if (module->size < BFELF_SUCCESS)
    {
        ALERT("add_module: failed to get the module's exec size %" PRId64 " - %s\n",
              module->size, bfelf_error(module->size));
        return module->size;
    }

    module->exec = platform_alloc_exec(module->size);
    if (module->exec == 0)
    {
        ALERT("add_module: out of memory\n");
        return 0;
    }

    ret = bfelf_file_load(&module->file, module->exec, module->size);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("add_module: failed to load the elf module: %" PRId64 " - %s\n",
              ret, bfelf_error(ret));
        goto failure;
    }

    g_num_modules++;
    return BF_SUCCESS;

failure:

    platform_free_exec(module->exec, module->size);
    return ret;
}

int64_t
common_load_vmm(void)
{
    int64_t i = 0;
    int64_t ret = 0;
    struct module_t *module = 0;
    struct bfelf_loader_t loader = {0};

    if (common_vmm_status() == VMM_CORRUPT)
    {
        ALERT("load_vmm: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (common_vmm_status() == VMM_LOADED)
        return BF_SUCCESS;

    if (common_vmm_status() == VMM_RUNNING)
    {
        ALERT("load_vmm: failed to load vmm. vmm cannot be loaded while "
              "another vmm is running\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    if (g_num_modules == 0)
    {
        ALERT("load_vmm: failed to load vmm. no modules were added\n");
        return BF_ERROR_NO_MODULES_ADDED;
    }

    ret = bfelf_loader_init(&loader);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("load_vmm: failed to initialize the elf loader: %" PRId64 " - %s\n",
              ret, bfelf_error(ret));
        goto failure;
    }

    i = 0;
    while ((module = get_module(i++)) != 0)
    {
        ret = bfelf_loader_add(&loader, &module->file);
        if (ret != BFELF_SUCCESS)
        {
            ALERT("load_vmm: failed to add elf file to the elf loader: "
                  "%" PRId64 " - %s\n", ret, bfelf_error(ret));
            goto failure;
        }
    }

    ret = bfelf_loader_relocate(&loader);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("load_vmm: failed to relocate the elf loader: %" PRId64 " - %s\n",
              ret, bfelf_error(ret));
        goto failure;
    }

    i = 0;
    while ((module = get_module(i++)) != 0)
    {
        ret = execute_ctors(&module->file);
        if (ret != BF_SUCCESS)
        {
            ALERT("load_vmm: failed to execute ctors: %" PRId64 "\n", ret);
            goto failure;
        }

        ret = execute_inits(&module->file);
        if (ret != BF_SUCCESS)
        {
            ALERT("load_vmm: failed to execute inits: %" PRId64 "\n", ret);
            goto failure;
        }
    }

    i = 0;
    while ((module = get_module(i++)) != 0)
    {
        ret = add_mdl_to_memory_manager(module->exec, module->size);
        if (ret != BF_SUCCESS)
        {
            ALERT("load_vmm: failed to add memory descriptors: %" PRId64 "\n", ret);
            goto failure;
        }
    }

    g_vmm_status = VMM_LOADED;
    return BF_SUCCESS;

failure:

    common_unload_vmm();
    return ret;
}

int64_t
common_unload_vmm(void)
{
    int64_t i = 0;
    int64_t ret = 0;
    struct module_t *module = 0;

    if (common_vmm_status() == VMM_CORRUPT)
    {
        ALERT("unload_vmm: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (common_vmm_status() == VMM_RUNNING)
    {
        ALERT("unload_vmm: failed to unload vmm. cannot unload a vmm that "
              "is still running\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    if (common_vmm_status() == VMM_LOADED)
    {
        i = 0;
        while ((module = get_module(i++)) != 0)
        {
            ret = execute_finis(&module->file);
            if (ret != BF_SUCCESS)
            {
                ALERT("unload_vmm: failed to execute finis: %" PRId64 "\n", ret);
                goto corrupted;
            }

            ret = execute_dtors(&module->file);
            if (ret != BF_SUCCESS)
            {
                ALERT("unload_vmm: failed to execute dtors: %" PRId64 "\n", ret);
                goto corrupted;
            }
        }
    }

    common_reset();

    return BF_SUCCESS;

corrupted:

    g_vmm_status = VMM_CORRUPT;
    return ret;
}

int64_t
common_start_vmm(void)
{
    int64_t ret = 0;

    if (common_vmm_status() == VMM_CORRUPT)
    {
        ALERT("start_vmm: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (common_vmm_status() == VMM_RUNNING)
        return BF_SUCCESS;

    if (common_vmm_status() == VMM_UNLOADED)
    {
        ALERT("start_vmm: failed to start vmm. the vmm must be loaded "
              "prior to starting\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    ret = execute_symbol("init_vmm", 0);
    if (ret != BF_SUCCESS)
    {
        ALERT("start_vmm: failed to execute init_vmm: %" PRId64 "\n", ret);
        goto failure;
    }

    ret = execute_symbol("start_vmm", 0);
    if (ret != BF_SUCCESS)
    {
        ALERT("start_vmm: failed to execute start_vmm: %" PRId64 "\n", ret);
        goto failure;
    }

    g_vmm_status = VMM_RUNNING;
    return BF_SUCCESS;

failure:

    common_stop_vmm();
    return ret;
}

int64_t
common_stop_vmm(void)
{
    int64_t ret;

    if (common_vmm_status() == VMM_CORRUPT)
    {
        ALERT("stop_vmm: unable to service request, vmm corrupted\n");
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (common_vmm_status() == VMM_LOADED)
        return BF_SUCCESS;

    if (common_vmm_status() == VMM_UNLOADED)
    {
        ALERT("stop_vmm: failed to stop vmm. the vmm must be loaded and "
              "running prior to stoping\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    ret = execute_symbol("stop_vmm", 0);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("stop_vmm: failed to execute symbol: %" PRId64 "\n", ret);
        goto corrupted;
    }

    g_vmm_status = VMM_LOADED;
    return BF_SUCCESS;

corrupted:

    g_vmm_status = VMM_CORRUPT;
    return ret;
}

int64_t
common_dump_vmm(struct debug_ring_resources_t *user_drr)
{
    int64_t ret = 0;
    get_drr_t get_drr = 0;
    struct debug_ring_resources_t *drr = 0;

    if (user_drr == 0)
        return BF_ERROR_INVALID_ARG;

    if (common_vmm_status() == VMM_UNLOADED)
    {
        ALERT("dump_vmm: failed to dump vmm as it has not been loaded yet\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    ret = resolve_symbol("get_drr", (void **)&get_drr);
    if (ret != BF_SUCCESS)
    {
        ALERT("dump_vmm: failed to locate get_drr. the symbol is missing "
              "or not loaded\n");
        return ret;
    }

    drr = get_drr(0);
    if (drr == 0)
    {
        ALERT("dump_vmm: failed to get debug ring resources\n");
        return BF_ERROR_FAILED_TO_DUMP_DR;
    }

    *user_drr = *drr;
    return BF_SUCCESS;
}
