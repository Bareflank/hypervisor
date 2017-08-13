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

#include <bftypes.h>
#include <bfdebug.h>
#include <bfmemory.h>
#include <bfplatform.h>
#include <bfconstants.h>
#include <bfthreadcontext.h>
#include <bfdriverinterface.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

int64_t g_num_modules = 0;
struct bfelf_binary_t g_modules[MAX_NUM_MODULES];

_start_t _start;
struct crt_info_t g_info;
struct bfelf_loader_t g_loader;

int64_t g_num_cpus_started = 0;
int64_t g_vmm_status = VMM_UNLOADED;

void *g_tls = 0;
void *g_stack = 0;

uint64_t g_tls_size = 0;
uint64_t g_stack_size = 0;
uint64_t g_stack_top = 0;

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

int64_t
setup_stack(void)
{
    g_stack_size = STACK_SIZE * 2;

    g_stack = platform_alloc_rw(g_stack_size);
    if (g_stack == 0) {
        return BF_ERROR_OUT_OF_MEMORY;
    }

    g_stack_top = (uint64_t)g_stack + g_stack_size;
    g_stack_top = (g_stack_top & ~(STACK_SIZE - 1)) - 1;

    platform_memset(g_stack, 0, g_stack_size);
    return BF_SUCCESS;
}

int64_t
setup_tls(void)
{
    g_tls_size = THREAD_LOCAL_STORAGE_SIZE * (uint64_t)platform_num_cpus();

    g_tls = platform_alloc_rw(g_tls_size);
    if (g_tls == 0) {
        return BF_ERROR_OUT_OF_MEMORY;
    }

    platform_memset(g_tls, 0, g_tls_size);
    return BF_SUCCESS;
}

int64_t
call_vmm(uintptr_t request, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    int64_t ret = 0;
    int64_t cpuid = 0;
    struct thread_context_t *tc = (struct thread_context_t *)(g_stack_top - sizeof(struct thread_context_t));

    ret = bfelf_set_integer_args(&g_info, request, arg1, arg2, arg3);
    if (ret != BF_SUCCESS) {
        return ret;
    }

    cpuid = platform_get_current_cpu_num();

    tc->cpuid = cpuid;
    tc->tlsptr = (uint64_t)g_tls + (THREAD_LOCAL_STORAGE_SIZE * cpuid);

    if (_start != 0) {
        ret = _start((void *)(g_stack_top - sizeof(struct thread_context_t) - 1), &g_info);
    }
    else {
        ret = BF_ERROR_UNKNOWN;
    }

    platform_restore_preemption();
    return ret;
}

int64_t
add_raw_md_to_memory_manager(uint64_t virt, uint64_t type)
{
    int64_t ret = 0;
    struct memory_descriptor md = {0, 0, 0};

    md.virt = virt;
    md.phys = (uint64_t)platform_virt_to_phys((void *)md.virt);
    md.type = type;

    ret = call_vmm(BF_REQUEST_ADD_MDL, (uintptr_t)&md, 0, 0);
    if (ret != MEMORY_MANAGER_SUCCESS) {
        return ret;
    }

    return BF_SUCCESS;
}

// TODO
//
// Put this function into the ELF loader with a callback. This will be needed
// in the hyperkernel, but what it has to do will be different.
//

int64_t
add_md_to_memory_manager(struct bfelf_binary_t *module)
{
    int64_t ret = 0;
    bfelf64_word s = 0;

    if (module == 0) {
        return BF_ERROR_INVALID_ARG;
    }

    for (s = 0; s < bfelf_file_get_num_load_instrs(&module->ef); s++) {

        uint64_t exec_s = 0;
        uint64_t exec_e = 0;
        const struct bfelf_load_instr *instr = 0;

        ret = bfelf_file_get_load_instr(&module->ef, s, &instr);
        if (ret != BFELF_SUCCESS) {
            return ret;
        }

        exec_s = (uint64_t)module->exec + instr->mem_offset;
        exec_e = (uint64_t)module->exec + instr->mem_offset + instr->memsz;
        exec_s &= ~(MAX_PAGE_SIZE - 1);
        exec_e &= ~(MAX_PAGE_SIZE - 1);

        for (; exec_s <= exec_e; exec_s += MAX_PAGE_SIZE) {
            if ((instr->perm & bfpf_x) != 0) {
                ret = add_raw_md_to_memory_manager(exec_s, MEMORY_TYPE_R | MEMORY_TYPE_E);
            }
            else {
                ret = add_raw_md_to_memory_manager(exec_s, MEMORY_TYPE_R | MEMORY_TYPE_W);
            }

            if (ret != MEMORY_MANAGER_SUCCESS) {
                return ret;
            }
        }
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

    for (i = 0; i < g_num_modules; i++) {
        if (g_modules[i].exec != 0) {
            platform_free_rwe(g_modules[i].exec, g_modules[i].exec_size);
        }
    }

    platform_memset(&g_modules, 0, sizeof(g_modules));
    platform_memset(&g_loader, 0, sizeof(struct bfelf_loader_t));
    platform_memset(&g_info, 0, sizeof(struct crt_info_t));
    platform_memset(&g_loader, 0, sizeof(struct bfelf_loader_t));

    _start = 0;

    g_num_modules = 0;
    g_num_cpus_started = 0;
    g_vmm_status = VMM_UNLOADED;

    if (g_tls != 0) {
        platform_free_rw(g_tls, g_tls_size);
    }

    if (g_stack != 0) {
        platform_free_rw(g_stack, g_stack_size);
    }

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
    if (common_vmm_status() == VMM_RUNNING) {
        if (common_stop_vmm() != BF_SUCCESS) {
            BFALERT("common_fini: failed to stop vmm\n");
        }
    }

    if (common_vmm_status() == VMM_LOADED) {
        if (common_unload_vmm() != BF_SUCCESS) {
            BFALERT("common_fini: failed to unload vmm\n");
        }
    }

    if (common_vmm_status() == VMM_CORRUPT) {
        return BF_ERROR_VMM_CORRUPTED;
    }

    if (common_vmm_status() == VMM_UNLOADED && g_num_modules > 0) {
        if (common_reset() != BF_SUCCESS) {
            BFALERT("common_fini: failed to reset\n");
        }
    }

    return BF_SUCCESS;
}

int64_t
common_add_module(const char *file, uint64_t fsize)
{
    if (file == 0 || fsize == 0) {
        return BF_ERROR_INVALID_ARG;
    }

    switch (common_vmm_status()) {
        case VMM_CORRUPT:
            return BF_ERROR_VMM_CORRUPTED;
        case VMM_LOADED:
            return BF_ERROR_VMM_INVALID_STATE;
        case VMM_RUNNING:
            return BF_ERROR_VMM_INVALID_STATE;
        default:
            break;
    }

    if (g_num_modules >= MAX_NUM_MODULES) {
        return BF_ERROR_MAX_MODULES_REACHED;
    }

    g_modules[g_num_modules].file = file;
    g_modules[g_num_modules].file_size = fsize;

    BFDEBUG("common_add_module [%d]:\n", (int)g_num_modules);
    BFDEBUG("    addr = %p\n", (void *)file);
    BFDEBUG("    size = %p\n", (void *)fsize);

    g_num_modules++;
    return BF_SUCCESS;
}

int64_t
common_load_vmm(void)
{
    int64_t i = 0;
    int64_t ret = 0;
    int64_t ignore_ret = 0;

    switch (common_vmm_status()) {
        case VMM_CORRUPT:
            return BF_ERROR_VMM_CORRUPTED;
        case VMM_LOADED:
            return BF_SUCCESS;
        case VMM_RUNNING:
            return BF_ERROR_VMM_INVALID_STATE;
        default:
            break;
    }

    if (g_num_modules == 0) {
        return BF_ERROR_NO_MODULES_ADDED;
    }

    ret = setup_stack();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = setup_tls();
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = bfelf_load(g_modules, g_num_modules, (void **)&_start, &g_info, &g_loader);
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    ret = call_vmm(BF_REQUEST_INIT, 0, 0, 0);
    if (ret != BF_SUCCESS) {
        goto failure;
    }

    // TODO
    //
    // The following should be in their own functions so that they can be
    // tested easier, and we need to send up an MDL and not each MD which will
    // speed things up a lot.
    //

    for (i = 0; i < g_num_modules; i++) {
        ret = add_md_to_memory_manager(&g_modules[i]);
        if (ret != BF_SUCCESS) {
            goto failure;
        }
    }

    {
        uint64_t tlss = (uint64_t)g_tls;
        uint64_t tlse = tlss + g_tls_size;

        for (; tlss <= tlse; tlss += MAX_PAGE_SIZE) {
            ret = add_raw_md_to_memory_manager(tlss, MEMORY_TYPE_R | MEMORY_TYPE_W);
            if (ret != BF_SUCCESS) {
                return ret;
            }
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
    int64_t ret = 0;

    switch (common_vmm_status()) {
        case VMM_CORRUPT:
            goto corrupted;
        case VMM_RUNNING:
            return BF_ERROR_VMM_INVALID_STATE;
        case VMM_UNLOADED:
            goto unloaded;
        default:
            break;
    }

    ret = call_vmm(BF_REQUEST_FINI, 0, 0, 0);
    if (ret != BF_SUCCESS) {
        BFALERT("call_vmm [BF_REQUEST_FINI] failed: %llx", ret);
        goto corrupted;
    }

unloaded:

    common_reset();

    g_vmm_status = VMM_UNLOADED;
    return BF_SUCCESS;

corrupted:

    g_vmm_status = VMM_CORRUPT;
    return BF_ERROR_VMM_CORRUPTED;
}

int64_t
common_start_vmm(void)
{
    int64_t ret = 0;
    int64_t cpuid = 0;
    int64_t ignore_ret = 0;
    int64_t caller_affinity = 0;
    struct vmcall_registers_t regs;

    switch (common_vmm_status()) {
        case VMM_CORRUPT:
            return BF_ERROR_VMM_CORRUPTED;
        case VMM_RUNNING:
            return BF_SUCCESS;
        case VMM_UNLOADED:
            return BF_ERROR_VMM_INVALID_STATE;
        default:
            break;
    }

    for (cpuid = 0, g_num_cpus_started = 0; cpuid < platform_num_cpus(); cpuid++) {

        regs.r00 = VMCALL_START;
        regs.r01 = VMCALL_MAGIC_NUMBER;

        ret = caller_affinity = platform_set_affinity(cpuid);
        if (caller_affinity < 0) {
            goto failure;
        }

        ret = call_vmm(BF_REQUEST_VMM_INIT, (uint64_t)cpuid, 0, 0);
        if (ret != BF_SUCCESS) {
            goto failure;
        }

        g_num_cpus_started++;

        vmcall(&regs);
        if (regs.r01 != 0) {
            return ENTRY_ERROR_VMM_START_FAILED;
        }

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

    switch (common_vmm_status()) {
        case VMM_CORRUPT:
            return BF_ERROR_VMM_CORRUPTED;
        case VMM_LOADED:
            return BF_SUCCESS;
        case VMM_UNLOADED:
            return BF_ERROR_VMM_INVALID_STATE;
        default:
            break;
    }

    for (cpuid = g_num_cpus_started - 1; cpuid >= 0 ; cpuid--) {

        regs.r00 = VMCALL_STOP;
        regs.r01 = VMCALL_MAGIC_NUMBER;

        ret = caller_affinity = platform_set_affinity(cpuid);
        if (caller_affinity < 0) {
            goto corrupted;
        }

        vmcall(&regs);
        if (regs.r01 != 0) {
            return ENTRY_ERROR_VMM_STOP_FAILED;
        }

        ret = call_vmm(BF_REQUEST_VMM_FINI, (uint64_t)cpuid, 0, 0);
        if (ret != BFELF_SUCCESS) {
            goto corrupted;
        }

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

    if (drr == 0) {
        return BF_ERROR_INVALID_ARG;
    }

    if (common_vmm_status() == VMM_UNLOADED) {
        return BF_ERROR_VMM_INVALID_STATE;
    }

    ret = call_vmm(BF_REQUEST_GET_DRR, (uint64_t)vcpuid, (uint64_t)drr, 0);
    if (ret != BFELF_SUCCESS) {
        return ret;
    }

    return BF_SUCCESS;
}
