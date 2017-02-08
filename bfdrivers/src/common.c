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
#include <thread_context.h>
#include <driver_entry_interface.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

int64_t g_vmm_status = VMM_UNLOADED;

int64_t g_num_modules = 0;
struct module_t g_modules[MAX_NUM_MODULES];

struct bfelf_loader_t g_loader;

int64_t g_num_cpus_started = 0;

void *g_tls = 0;
void *g_stack = 0;

uint64_t g_tls_size = 0;
uint64_t g_stack_size = 0;
uint64_t g_stack_top = 0;

/* -------------------------------------------------------------------------- */
/* Entry Points                                                               */
/* -------------------------------------------------------------------------- */

execute_entry_t execute_entry = 0;

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

struct module_t *
get_module(int64_t index)
{
    if (index < 0 || index >= g_num_modules)
        return 0;

    return &(g_modules[index]);
}

uint64_t
symbol_length(const char *sym)
{
    uint64_t len = 0;

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

    if (name == 0 || sym == 0)
        return BF_ERROR_INVALID_ARG;

    if (g_num_modules == 0)
        return BF_ERROR_NO_MODULES_ADDED;

    ret = bfelf_loader_resolve_symbol(&g_loader, name, sym);
    if (ret != BFELF_SUCCESS)
    {
        ALERT("Failed to find: %s\n", name);
        return ret;
    }

    return BF_SUCCESS;
}

int64_t
execute_symbol(const char *sym, uint64_t arg1, uint64_t arg2, uint64_t cpuid)
{
    int64_t ret = 0;
    void *entry_point = 0;
    struct thread_context_t *tc = (struct thread_context_t *)(g_stack_top - sizeof(struct thread_context_t));

    if (sym == 0)
        return BF_ERROR_INVALID_ARG;

    ret = resolve_symbol(sym, &entry_point);
    if (ret != BF_SUCCESS)
        return ret;

    tc->cpuid = cpuid;
    tc->tlsptr = (uint64_t)g_tls + (THREAD_LOCAL_STORAGE_SIZE * cpuid);

    ret = execute_entry(g_stack_top - sizeof(struct thread_context_t) - 1, entry_point, arg1, arg2);
    if (ret != ENTRY_SUCCESS)
    {
        ALERT("%s failed\n", sym);
        return ret;
    }

    return BF_SUCCESS;
}

int64_t
add_raw_md_to_memory_manager(uint64_t virt, uint64_t type)
{
    int64_t ret = 0;
    struct memory_descriptor md = {0, 0, 0};

    md.virt = virt;
    md.phys = (uint64_t)platform_virt_to_phys((void *)md.virt);
    md.type = type;

    ret = execute_symbol("add_md", (uint64_t)&md, 0, 0);
    if (ret != MEMORY_MANAGER_SUCCESS)
        return ret;

    return BF_SUCCESS;
}

int64_t
add_md_to_memory_manager(struct module_t *module)
{
    int64_t ret = 0;
    bfelf64_word s = 0;

    if (module == 0)
        return BF_ERROR_INVALID_ARG;

    for (s = 0; s < bfelf_file_num_load_instrs(&module->file); s++)
    {
        uint64_t exec_s = 0;
        uint64_t exec_e = 0;
        struct bfelf_load_instr *instr = 0;

        ret = bfelf_file_get_load_instr(&module->file, s, &instr);
        if (ret != BFELF_SUCCESS)
            return ret;

        exec_s = (uint64_t)module->exec + instr->mem_offset;
        exec_e = (uint64_t)module->exec + instr->mem_offset + instr->memsz;
        exec_s &= ~(MAX_PAGE_SIZE - 1);
        exec_e &= ~(MAX_PAGE_SIZE - 1);

        for (; exec_s <= exec_e; exec_s += MAX_PAGE_SIZE)
        {
            if ((instr->perm & bfpf_x) != 0)
                ret = add_raw_md_to_memory_manager(exec_s, MEMORY_TYPE_R | MEMORY_TYPE_E);
            else
                ret = add_raw_md_to_memory_manager(exec_s, MEMORY_TYPE_R | MEMORY_TYPE_W);

            if (ret != MEMORY_MANAGER_SUCCESS)
                return ret;
        }
    }

    return BF_SUCCESS;
}

int64_t
load_elf_file(struct module_t *module)
{
    bfelf64_word s = 0;

    if (module == 0)
        return BF_ERROR_INVALID_ARG;

    platform_memset(module->exec, 0, module->size);

    for (s = 0; s < bfelf_file_num_load_instrs(&module->file); s++)
    {
        int64_t ret = 0;
        struct bfelf_load_instr *instr = 0;

        const char *src = 0;
        char *dst = 0;
        uint64_t len = 0;

        ret = bfelf_file_get_load_instr(&module->file, s, &instr);
        if (ret != BFELF_SUCCESS)
            return ret;

        dst = module->exec + instr->mem_offset;
        src = module->file.file + instr->file_offset;
        len = instr->filesz;

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
    int64_t i;

    for (i = 0; i < g_num_modules; i++)
    {
        if (g_modules[i].exec != 0)
            platform_free_rwe(g_modules[i].exec, g_modules[i].size);
    }

    platform_memset(&g_modules, 0, sizeof(g_modules));

    g_num_modules = 0;
    g_vmm_status = VMM_UNLOADED;

    platform_memset(&g_loader, 0, sizeof(struct bfelf_loader_t));

    execute_entry = 0;
    g_num_cpus_started = 0;

    if (g_tls != 0)
        platform_free_rw(g_tls, g_tls_size);

    if (g_stack != 0)
        platform_free_rw(g_stack, g_stack_size);

    g_tls = 0;
    g_stack = 0;
    g_stack_top = 0;

    return BF_SUCCESS;
}

int64_t
common_init(void)
{
    return common_reset();
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

    return BF_SUCCESS;
}

int64_t
common_add_module(const char *file, uint64_t fsize)
{
    int64_t ret = 0;
    struct module_t *module = 0;

    /*
     * TODO: Might not be a bad idea to add the ability to detect when a
     * module is alreayed added. Since we want the ability to have signed
     * modules, we could combine the two and kill two birds with one stone.
     */

    if (file == 0 || fsize == 0)
        return BF_ERROR_INVALID_ARG;

    if (common_vmm_status() == VMM_CORRUPT)
        return BF_ERROR_VMM_CORRUPTED;

    if (common_vmm_status() != VMM_UNLOADED)
        return BF_ERROR_VMM_INVALID_STATE;

    if (g_num_modules >= MAX_NUM_MODULES)
        return BF_ERROR_MAX_MODULES_REACHED;

    module = &(g_modules[g_num_modules]);

    ret = bfelf_file_init(file, fsize, &module->file);
    if (ret != BFELF_SUCCESS)
        return ret;

    module->size = (uint64_t)bfelf_file_get_total_size(&module->file);
    if (module->size <= 0)
        return BF_ERROR_FAILED_TO_ADD_FILE;

    module->exec = platform_alloc_rwe(module->size);
    if (module->exec == 0)
        return BF_ERROR_OUT_OF_MEMORY;

    ret = load_elf_file(module);
    if (ret != BF_SUCCESS)
        goto failure;

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
    int64_t ignore_ret = 0;
    struct module_t *module = 0;

    if (common_vmm_status() == VMM_CORRUPT)
        return BF_ERROR_VMM_CORRUPTED;

    if (common_vmm_status() == VMM_LOADED)
        return BF_SUCCESS;

    if (common_vmm_status() == VMM_RUNNING)
        return BF_ERROR_VMM_INVALID_STATE;

    if (g_num_modules == 0)
        return BF_ERROR_NO_MODULES_ADDED;

    g_tls_size = THREAD_LOCAL_STORAGE_SIZE * (uint64_t)platform_num_cpus();
    g_stack_size = STACK_SIZE * 2;

    g_tls = platform_alloc_rw(g_tls_size);
    if (g_tls == 0)
        return BF_ERROR_OUT_OF_MEMORY;

    g_stack = platform_alloc_rw(g_stack_size);
    if (g_stack == 0)
        return BF_ERROR_OUT_OF_MEMORY;

    g_stack_top = (uint64_t)g_stack + g_stack_size;
    g_stack_top = (g_stack_top & ~(STACK_SIZE - 1)) - 1;

    platform_memset(g_tls, 0, g_tls_size);
    platform_memset(&g_loader, 0, sizeof(struct bfelf_loader_t));

    for (i = 0; (module = get_module(i)) != 0; i++)
    {
        ret = bfelf_loader_add(&g_loader, &module->file, module->exec, module->exec);
        if (ret != BFELF_SUCCESS)
            goto failure;
    }

    ret = bfelf_loader_relocate(&g_loader);
    if (ret != BFELF_SUCCESS)
        goto failure;

    ret = resolve_symbol("execute_entry", (void **)&execute_entry);
    if (ret != BF_SUCCESS)
        goto failure;

    for (i = 0; (module = get_module(i)) != 0; i++)
    {
        struct section_info_t info = {0, 0, 0, 0, 0, 0, 0, 0};

        ret = bfelf_file_get_section_info(&module->file, &info);
        if (ret != BF_SUCCESS)
            goto failure;

        ret = execute_symbol("local_init", (uint64_t)&info, 0, 0);
        if (ret != BF_SUCCESS)
            goto failure;
    }

    for (i = 0; (module = get_module(i)) != 0; i++)
    {
        ret = add_md_to_memory_manager(module);
        if (ret != BF_SUCCESS)
            goto failure;
    }

    {
        uint64_t tlss = (uint64_t)g_tls;
        uint64_t tlse = tlss + g_tls_size;

        for (; tlss <= tlse; tlss += MAX_PAGE_SIZE)
        {
            ret = add_raw_md_to_memory_manager(tlss, MEMORY_TYPE_R | MEMORY_TYPE_W);
            if (ret != BF_SUCCESS)
                return ret;
        }
    }

    g_vmm_status = VMM_LOADED;
    return BF_SUCCESS;

failure:

    ignore_ret = common_unload_vmm();
    (void) ignore_ret;

    return ret;
}

int64_t
common_unload_vmm(void)
{
    int64_t i = 0;
    int64_t ret = 0;
    struct module_t *module = 0;

    if (common_vmm_status() == VMM_CORRUPT)
        return BF_ERROR_VMM_CORRUPTED;

    if (common_vmm_status() == VMM_RUNNING)
        return BF_ERROR_VMM_INVALID_STATE;

    if (common_vmm_status() == VMM_LOADED)
    {
        for (i = g_num_modules - 1; (module = get_module(i)) != 0; i--)
        {
            struct section_info_t info = {0, 0, 0, 0, 0, 0, 0, 0};

            ret = bfelf_file_get_section_info(&module->file, &info);
            if (ret != BF_SUCCESS)
                goto corrupted;

            ret = execute_symbol("local_fini", (uint64_t)&info, 0, 0);
            if (ret != BF_SUCCESS)
                goto corrupted;
        }
    }

    common_reset();

    g_vmm_status = VMM_UNLOADED;
    return BF_SUCCESS;

corrupted:

    g_vmm_status = VMM_CORRUPT;
    return ret;
}

int64_t
common_start_vmm(void)
{
    int64_t ret = 0;
    int64_t cpuid = 0;
    int64_t ignore_ret = 0;
    int64_t caller_affinity = 0;
    struct vmcall_registers_t regs;

    if (common_vmm_status() == VMM_CORRUPT)
        return BF_ERROR_VMM_CORRUPTED;

    if (common_vmm_status() == VMM_RUNNING)
        return BF_SUCCESS;

    if (common_vmm_status() == VMM_UNLOADED)
        return BF_ERROR_VMM_INVALID_STATE;

    for (cpuid = 0, g_num_cpus_started = 0; cpuid < platform_num_cpus(); cpuid++)
    {
        regs.r00 = VMCALL_START;
        regs.r01 = VMCALL_MAGIC_NUMBER;

        ret = caller_affinity = platform_set_affinity(cpuid);
        if (caller_affinity < 0)
            goto failure;

        ret = execute_symbol("start_vmm", (uint64_t)cpuid, 0, (uint64_t)cpuid);
        if (ret != BF_SUCCESS)
            goto failure;

        g_num_cpus_started++;

        platform_vmcall(&regs);
        if (regs.r01 != 0)
            return ENTRY_ERROR_VMM_START_FAILED;

        platform_start();
        platform_restore_affinity(caller_affinity);

        g_vmm_status = VMM_RUNNING;
    }

    return BF_SUCCESS;

failure:

    ignore_ret = common_stop_vmm();
    (void) ignore_ret;

    return ret;
}

int64_t
common_stop_vmm(void)
{
    int64_t ret = 0;
    int64_t cpuid = 0;
    int64_t caller_affinity = 0;
    struct vmcall_registers_t regs;

    if (common_vmm_status() == VMM_CORRUPT)
        return BF_ERROR_VMM_CORRUPTED;

    if (common_vmm_status() == VMM_LOADED)
        return BF_SUCCESS;

    if (common_vmm_status() == VMM_UNLOADED)
        return BF_ERROR_VMM_INVALID_STATE;

    for (cpuid = g_num_cpus_started - 1; cpuid >= 0 ; cpuid--)
    {
        regs.r00 = VMCALL_STOP;
        regs.r01 = VMCALL_MAGIC_NUMBER;

        ret = caller_affinity = platform_set_affinity(cpuid);
        if (caller_affinity < 0)
            goto corrupted;

        platform_vmcall(&regs);
        if (regs.r01 != 0)
            return ENTRY_ERROR_VMM_STOP_FAILED;

        ret = execute_symbol("stop_vmm", (uint64_t)cpuid, 0, (uint64_t)cpuid);
        if (ret != BFELF_SUCCESS)
            goto corrupted;

        g_num_cpus_started--;

        platform_stop();
        platform_restore_affinity(caller_affinity);
    }

    g_vmm_status = VMM_LOADED;
    return BF_SUCCESS;

corrupted:

    g_vmm_status = VMM_CORRUPT;
    return ret;
}

int64_t
common_dump_vmm(struct debug_ring_resources_t **drr, uint64_t vcpuid)
{
    int64_t ret = 0;

    if (drr == 0)
        return BF_ERROR_INVALID_ARG;

    if (common_vmm_status() == VMM_UNLOADED)
        return BF_ERROR_VMM_INVALID_STATE;

    ret = execute_symbol("get_drr", (uint64_t)vcpuid, (uint64_t)drr, 0);
    if (ret != BFELF_SUCCESS)
        return ret;

    return BF_SUCCESS;
}

int64_t
common_vmcall(struct vmcall_registers_t *regs, uint64_t cpuid)
{
    int64_t ret = 0;
    int64_t caller_affinity = 0;
    int64_t signed_cpuid = (int64_t)cpuid;

    if (common_vmm_status() == VMM_CORRUPT)
        return BF_ERROR_VMM_CORRUPTED;

    if (common_vmm_status() == VMM_LOADED)
        return BF_ERROR_VMM_INVALID_STATE;

    if (common_vmm_status() == VMM_UNLOADED)
        return BF_ERROR_VMM_INVALID_STATE;

    if (regs == 0)
        return BF_ERROR_INVALID_ARG;

    if (signed_cpuid >= g_num_cpus_started)
        return BF_ERROR_INVALID_ARG;

    if (signed_cpuid >= 0)
    {
        ret = caller_affinity = platform_set_affinity((int64_t)cpuid);
        if (caller_affinity < 0)
            return ret;
    }

    if (regs->r00 == VMCALL_EVENT)
        platform_vmcall_event(regs);
    else
        platform_vmcall(regs);

    if (signed_cpuid >= 0)
        platform_restore_affinity(caller_affinity);

    return BF_SUCCESS;
}
