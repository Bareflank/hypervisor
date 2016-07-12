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
struct module_t g_modules[MAX_NUM_MODULES] = {{0}};

struct bfelf_loader_t g_loader;

int64_t g_num_cpus_started = 0;

void *g_stack = 0;
void *g_stack_loc = 0;

/* -------------------------------------------------------------------------- */
/* Entry Points                                                               */
/* -------------------------------------------------------------------------- */

execute_entry_t execute_entry = 0;

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
resolve_symbol(const char *name, void **sym, struct module_t *module)
{
    int64_t ret;
    struct e_string_t str = {0};

    if (name == 0 || sym == 0)
        return BF_ERROR_INVALID_ARG;

    if (module == 0 && g_num_modules == 0)
        return BF_ERROR_NO_MODULES_ADDED;

    str.buf = name;
    str.len = (bfelf64_sword)symbol_length(name);

    if (module == 0)
    {
        ret = bfelf_loader_resolve_symbol(&g_loader, &str, sym);
        if (ret != BFELF_SUCCESS)
        {
            ALERT("%s could not be found: %" PRId64 " - %s\n", name, ret,
                  bfelf_error((bfelf64_sword)ret));
            return ret;
        }
    }
    else
    {
        ret = bfelf_file_resolve_symbol(&module->file, &str, sym);
        if (ret != BFELF_SUCCESS)
        {
            ALERT("%s could not be found: %" PRId64 " - %s\n", name, ret,
                  bfelf_error((bfelf64_sword)ret));
            return ret;
        }
    }

    return BF_SUCCESS;
}

int64_t
execute_symbol(const char *sym, uint64_t arg1, uint64_t arg2, struct module_t *module)
{
    int64_t ret = 0;
    void *entry_point = 0;

    if (sym == 0)
        return BF_ERROR_INVALID_ARG;

    ret = resolve_symbol(sym, &entry_point, module);
    if (ret != BF_SUCCESS)
    {
        ALERT("execute_symbol: failed to resolve entry point: %" PRId64 "\n",
              ret);
        return ret;
    }

    ret = execute_entry(g_stack_loc, entry_point, arg1, arg2);
    if (ret != ENTRY_SUCCESS)
    {
        ALERT("%s failed:\n", sym);
        ALERT("    - exit code: %p\n", (void *)ret);

        return ret;
    }

    return BF_SUCCESS;
}

int64_t
add_md_to_memory_manager(struct module_t *module)
{
    int64_t ret = 0;
    bfelf64_word s = 0;

    if (module == 0)
        return BF_ERROR_INVALID_ARG;

    for (s = 0; s < bfelf_file_num_segments(&module->file); s++)
    {
        uint64_t exec_s = 0;
        uint64_t exec_e = 0;
        struct bfelf_phdr *phdr = 0;

        ret = bfelf_file_get_segment(&module->file, s, &phdr);
        if (ret != BFELF_SUCCESS)
        {
            ALERT("bfelf_file_get_segment failed: %d\n", (int)ret);
            return 0;
        }

        exec_s = (uint64_t)module->exec + phdr->p_vaddr;
        exec_e = (uint64_t)module->exec + phdr->p_vaddr + phdr->p_memsz;
        exec_s &= ~(MAX_PAGE_SIZE - 1);
        exec_e &= ~(MAX_PAGE_SIZE - 1);

        for (; exec_s <= exec_e; exec_s += MAX_PAGE_SIZE)
        {
            struct memory_descriptor md;

            md.virt = (void *)exec_s;
            md.phys = platform_virt_to_phys(md.virt);

            if ((phdr->p_flags & bfpf_x) != 0)
                md.type = MEMORY_TYPE_R | MEMORY_TYPE_E;
            else
                md.type = MEMORY_TYPE_R | MEMORY_TYPE_W;

            ret = execute_symbol("add_md", (uint64_t)&md, 0, 0);
            if (ret != MEMORY_MANAGER_SUCCESS)
            {
                ALERT("add_md_to_memory_manager: failed to add md: %p, %p, 0x%x\n",
                      md.virt, md.phys, md.type);
                return ret;
            }
        }
    }

    return BF_SUCCESS;
}

uint64_t
get_elf_file_size(struct module_t *module)
{
    bfelf64_word s = 0;
    bfelf64_xword total = 0;

    if (module == 0)
        return 0;

    for (s = 0; s < bfelf_file_num_segments(&module->file); s++)
    {
        int64_t ret = 0;
        struct bfelf_phdr *phdr = 0;

        ret = bfelf_file_get_segment(&module->file, s, &phdr);
        if (ret != BFELF_SUCCESS)
        {
            ALERT("bfelf_file_get_segment failed: %d\n", (int)ret);
            return 0;
        }

        if (total < phdr->p_vaddr + phdr->p_memsz)
            total = phdr->p_vaddr + phdr->p_memsz;
    }

    return total;
}

int64_t
load_elf_file(struct module_t *module)
{
    bfelf64_word s = 0;

    if (module == 0)
        return BF_ERROR_INVALID_ARG;

    platform_memset(module->exec, 0, module->size);

    for (s = 0; s < bfelf_file_num_segments(&module->file); s++)
    {
        int64_t ret = 0;
        struct bfelf_phdr *phdr = 0;

        char *dst = 0;
        char *src = 0;
        int64_t len = 0;

        ret = bfelf_file_get_segment(&module->file, s, &phdr);
        if (ret != BFELF_SUCCESS)
            return ret;

        dst = module->exec + phdr->p_vaddr;
        src = module->file.file + phdr->p_offset;
        len = phdr->p_filesz;

        platform_memcpy(dst, src, len);
    }

    return BF_SUCCESS;
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
        if (g_modules[i].exec != 0)
            platform_free_rwe(g_modules[i].exec, g_modules[i].size);

        g_modules[i].exec = 0;
        g_modules[i].size = 0;
        g_modules[i].file = file;
    }

    g_num_modules = 0;
    g_vmm_status = VMM_UNLOADED;

    platform_memset(&g_loader, 0, sizeof(struct bfelf_loader_t));

    execute_entry = 0;
    g_num_cpus_started = 0;

    if (g_stack != 0)
        platform_free_rw(g_stack, STACK_SIZE);

    g_stack = 0;
    g_stack_loc = 0;

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
              ret, bfelf_error((bfelf64_sword)ret));
        return ret;
    }

    module->size = get_elf_file_size(module);
    if (module->size == 0)
    {
        ALERT("add_module: failed to get the module's exec size\n");
        return BF_ERROR_FAILED_TO_ADD_FILE;
    }

    module->exec = platform_alloc_rwe(module->size);
    if (module->exec == 0)
    {
        ALERT("add_module: out of memory\n");
        return 0;
    }

    ret = load_elf_file(module);
    if (ret != BF_SUCCESS)
    {
        ALERT("add_module: failed to load the elf module: %" PRId64 "\n", ret);
        goto failure;
    }

    DEBUG("common_add_module [%d]:\n", (int)g_num_modules);
    DEBUG("    addr = %p\n", (void *)module->exec);
    DEBUG("    size = %p\n", (void *)module->size);

    g_num_modules++;
    return BF_SUCCESS;

failure:

    platform_free_rwe(module->exec, module->size);
    return ret;
}

int64_t
common_load_vmm(void)
{
    int64_t i = 0;
    int64_t ret = 0;
    struct module_t *module = 0;

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

    platform_memset(&g_loader, 0, sizeof(struct bfelf_loader_t));

    for (i = 0; (module = get_module(i)) != 0; i++)
    {
        ret = bfelf_loader_add(&g_loader, &module->file, module->exec);
        if (ret != BFELF_SUCCESS)
        {
            ALERT("load_vmm: failed to add elf file to the elf loader: "
                  "%" PRId64 " - %s\n", ret, bfelf_error((bfelf64_sword)ret));
            goto failure;
        }
    }

    ret = bfelf_loader_relocate(&g_loader);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("load_vmm: failed to relocate the elf loader: %" PRId64 " - %s\n",
              ret, bfelf_error((bfelf64_sword)ret));
        goto failure;
    }

    g_stack = platform_alloc_rw(STACK_SIZE);
    g_stack_loc = (void *)(((uintptr_t)g_stack + STACK_SIZE - 1) & ~0x0F);

    if (g_stack == 0)
    {
        ALERT("load_vmm: failed to allocate stack space\n");
        ret = BF_ERROR_OUT_OF_MEMORY;
        goto failure;
    }

    ret = resolve_symbol("execute_entry", (void **)&execute_entry, 0);
    if (ret != BF_SUCCESS)
    {
        ALERT("load_vmm: failed to locate execute_entry. the symbol is missing "
              "which means the misc module is missing\n");
        goto failure;
    }

    for (i = 0; (module = get_module(i)) != 0; i++)
    {
        struct section_info_t info = {0};

        ret = bfelf_loader_get_info(&g_loader, &module->file, &info);
        if (ret != BF_SUCCESS)
        {
            ALERT("load_vmm: failed to get info: %" PRId64 "\n", ret);
            goto failure;
        }

        ret = execute_symbol("local_init", (uint64_t)&info, 0, module);
        if (ret != BF_SUCCESS)
        {
            ALERT("load_vmm: failed to locate local_init. the symbol is missing "
                  "which means the modules was not compiled with the wrapper\n");
            goto failure;
        }
    }

    for (i = 0; (module = get_module(i)) != 0; i++)
    {
        ret = add_md_to_memory_manager(module);
        if (ret != BF_SUCCESS)
        {
            ALERT("load_vmm: failed to add memory descriptors: %" PRId64 "\n",
                  ret);
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
        for (i = g_num_modules - 1; (module = get_module(i)) != 0; i--)
        {
            struct section_info_t info = {0};

            ret = bfelf_loader_get_info(&g_loader, &module->file, &info);
            if (ret != BF_SUCCESS)
            {
                ALERT("unload_vmm: failed to get info: %" PRId64 "\n", ret);
                goto corrupted;
            }

            ret = execute_symbol("local_fini", (uint64_t)&info, 0, module);
            if (ret != BF_SUCCESS)
            {
                ALERT("unload_vmm: failed to locate local_init. the symbol is missing "
                      "which means the modules was not compiled with the wrapper\n");
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

	uint64_t caller_affinity = 0;

    for (g_num_cpus_started = 0; g_num_cpus_started < platform_num_cpus(); g_num_cpus_started++)
    {
        ret = platform_set_affinity(g_num_cpus_started);
		
		if (g_num_cpus_started == 0)
			caller_affinity = ret;

        if (ret != BFELF_SUCCESS)
        {
            ALERT("start_vmm: failed to set affinity: %" PRId64 "\n", ret);
            goto failure;
        }

        ret = execute_symbol("init_vmm", g_num_cpus_started, 0, 0);
        if (ret != BF_SUCCESS)
        {
            ALERT("start_vmm: failed to execute init_vmm: %p\n", (void *)ret);
            goto failure;
        }

        ret = execute_symbol("start_vmm", g_num_cpus_started, 0, 0);
        if (ret != BF_SUCCESS)
        {
            ALERT("start_vmm: failed to execute start_vmm: %p\n", (void *)ret);
            goto failure;
        }

        platform_start();
    }

    g_vmm_status = VMM_RUNNING;
	
	platform_restore_affinity(caller_affinity);
    
	return BF_SUCCESS;

failure:

    common_stop_vmm();
    return ret;
}

int64_t
common_stop_vmm(void)
{
    int64_t i = 0;
    int64_t ret = 0;

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

    for (i = g_num_cpus_started - 1; i >= 0 ; i--)
    {
        ret = platform_set_affinity(i);
        if (ret != BFELF_SUCCESS)
        {
            ALERT("stop_vmm: failed to set affinity: %" PRId64 "\n", ret);
            goto corrupted;
        }

        ret = execute_symbol("stop_vmm", i, 0, 0);
        if (ret != BFELF_SUCCESS)
        {
            ALERT("stop_vmm: failed to execute symbol: %p\n", (void *)ret);
            goto corrupted;
        }

        platform_stop();
    }

    g_vmm_status = VMM_LOADED;
    return BF_SUCCESS;

corrupted:

    g_vmm_status = VMM_CORRUPT;
    return ret;
}

int64_t
common_dump_vmm(struct debug_ring_resources_t **drr, int64_t vcpuid)
{
    int64_t ret = 0;

    if (drr == 0)
        return BF_ERROR_INVALID_ARG;

    if (common_vmm_status() == VMM_UNLOADED)
    {
        ALERT("dump_vmm: failed to dump vmm as it has not been loaded yet\n");
        return BF_ERROR_VMM_INVALID_STATE;
    }

    ret = execute_symbol("get_drr", (uint64_t)vcpuid, (uint64_t)drr, 0);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("dump_vmm: failed to execute symbol: %p\n", (void *)ret);
        return ret;
    }

    return BF_SUCCESS;
}
