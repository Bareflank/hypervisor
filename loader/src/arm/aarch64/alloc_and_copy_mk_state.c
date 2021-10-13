/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <bfelf/bfelf_elf64_ehdr_t.h>
#include <constants.h>
#include <debug.h>
#include <exception_vectors.h>
#include <platform.h>
#include <root_page_table_t.h>
#include <span_t.h>
#include <state_save_t.h>
#include <types.h>

/** @brief defines the default value of daif */
#define DEFAULT_DAIF ((uint64_t)0x3C0)
/** @brief defines the default value of spsel */
#define DEFAULT_SPSEL ((uint64_t)0x1)

/** @brief defines the default value of hcr_el2 */
#define DEFAULT_HCR_EL2 ((uint64_t)0x0)
/** @brief defines the default value of mair_el2 */
#define DEFAULT_MAIR_EL2 ((uint64_t)0xFFBB4400)
/** @brief defines the default value of sctlr_el2 */
#define DEFAULT_SCTLR_EL2 ((uint64_t)0x30C5183D)
/** @brief defines the default value of tcr_el2 */
#define DEFAULT_TCR_EL2 ((uint64_t)0x80843510)
/** @brief defines the default value of ttbr0_el2 */
#define DEFAULT_TTBR0_EL2 ((uint64_t)0x0)

/**
 * <!-- description -->
 *   @brief The function's main purpose is to set up the state for the
 *     microkernel.
 *
 * <!-- inputs/outputs -->
 *   @param rpt the mkcrokernel's root page table
 *   @param mk_elf_file the microkernel's ELF file
 *   @param mk_stack the microkernel's stack
 *   @param mk_stack_virt the microkernel's virtual address of the stack
 *   @param state where to save the newly set up state to
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
NODISCARD int64_t
alloc_and_copy_mk_state(
    root_page_table_t const *const rpt,
    struct span_t const *const mk_elf_file,
    struct span_t const *const mk_stack,
    uint64_t const mk_stack_virt,
    struct state_save_t **const state) NOEXCEPT
{
    struct bfelf_elf64_ehdr_t const *ehdr = NULLPTR;
    if (get_elf64_ehdr(mk_elf_file->addr, &ehdr)) {
        bferror("get_elf64_ehdr failed");
        return LOADER_FAILURE;
    }

    /**************************************************************************/
    /* Allocate the resulting state                                           */
    /**************************************************************************/

    *state = (struct state_save_t *)platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (NULLPTR == *state) {
        bferror("platform_alloc failed");
        return LOADER_FAILURE;
    }

    /**************************************************************************/
    /* General Purpose Registers                                              */
    /**************************************************************************/

    (*state)->pc_el2 = ((uint64_t)ehdr->e_entry);
    (*state)->sp_el2 = ((uint64_t)(mk_stack_virt + mk_stack->size));

    /**************************************************************************/
    /* Saved Program Status Registers (SPSR)                                  */
    /**************************************************************************/

    (*state)->daif = DEFAULT_DAIF;
    (*state)->spsel = DEFAULT_SPSEL;

    /**************************************************************************/
    /* Exceptions                                                             */
    /**************************************************************************/

    (*state)->vbar_el2 = ((uint64_t)&exception_vectors);

    /**************************************************************************/
    /* System Registers                                                       */
    /**************************************************************************/

    (*state)->hcr_el2 = DEFAULT_HCR_EL2;
    (*state)->mair_el2 = DEFAULT_MAIR_EL2;
    (*state)->sctlr_el2 = DEFAULT_SCTLR_EL2;
    (*state)->tcr_el2 = DEFAULT_TCR_EL2;
    (*state)->ttbr0_el2 = platform_virt_to_phys(rpt);

    return LOADER_SUCCESS;
}
