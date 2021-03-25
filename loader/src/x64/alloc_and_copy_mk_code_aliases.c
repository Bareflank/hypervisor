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

#include <code_aliases_t.h>
#include <constants.h>
#include <debug.h>
#include <demote.h>
#include <esr_default.h>
#include <esr_df.h>
#include <esr_gpf.h>
#include <esr_nmi.h>
#include <esr_pf.h>
#include <platform.h>
#include <promote.h>
#include <serial_write_c.h>
#include <serial_write_hex.h>
#include <types.h>

#ifdef _MSC_VER
#pragma warning(disable : 4152)
#endif

/**
 * <!-- description -->
 *   @brief The function's main purpose is allocate pages for all of the
 *     executable code that is currently linked into the kernel module, and
 *     copy this code into the newly allocated pages so that they can be
 *     mapped into the microkernel's root page tables, creating an alias.
 *     The following diagram is what we are doing here:
 *
 *                          |-------> physical address (OS kernel)
 *                          |
 *     virtual address <----|
 *                          |
 *                          |-------> physical address (microkernel)
 *
 *     As you can see, the same virtual address for both the OS kernel and
 *     the microkernel point to two different physical addresses. The
 *     physical address for the microkernel is the alias, and we create
 *     the alias by copying the page located in the OS kenrel to the page
 *     located in the microkernel. This is done because we cannot actually
 *     get the physical address of the OS kernel, but we can access the
 *     contents of the page using the virtual address. So we copy the page
 *     to a page that we can get the physical address of and point the
 *     microkernel to that page instead. It should be noted that on Linux,
 *     if you do try to get the physical address of the code that we need
 *     to map into the microkernel, you will actually get what looks like
 *     a valid physical address, but be warned that the page it returns
 *     is actually garbage. You can only get the physical address of
 *     memory that is allocated using vmalloc(), which is why we need to
 *     create the aliases, as we need the physical address of the code so
 *     that we can map it into the microkernel's root page tables.
 *
 * <!-- inputs/outputs -->
 *   @param a a pointer to a code_aliases_t that will store the
 *     resulting aliases.
 *   @return 0 on success, LOADER_FAILURE on failure.
 */
int64_t
alloc_and_copy_mk_code_aliases(struct code_aliases_t *const a)
{
    a->demote = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == a->demote) {
        bferror("platform_alloc failed");
        goto platform_alloc_demote_failed;
    }

    a->promote = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == a->promote) {
        bferror("platform_alloc failed");
        goto platform_alloc_promote_failed;
    }

    a->esr_default = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == a->esr_default) {
        bferror("platform_alloc failed");
        goto platform_alloc_esr_default_failed;
    }

    a->esr_df = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == a->esr_df) {
        bferror("platform_alloc failed");
        goto platform_alloc_esr_df_failed;
    }

    a->esr_gpf = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == a->esr_gpf) {
        bferror("platform_alloc failed");
        goto platform_alloc_esr_gpf_failed;
    }

    a->esr_nmi = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == a->esr_nmi) {
        bferror("platform_alloc failed");
        goto platform_alloc_esr_nmi_failed;
    }

    a->esr_pf = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == a->esr_pf) {
        bferror("platform_alloc failed");
        goto platform_alloc_esr_pf_failed;
    }

    a->serial_write_c = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == a->serial_write_c) {
        bferror("platform_alloc failed");
        goto platform_alloc_esr_pf_failed;
    }

    a->serial_write_hex = platform_alloc(HYPERVISOR_PAGE_SIZE);
    if (((void *)0) == a->serial_write_hex) {
        bferror("platform_alloc failed");
        goto platform_alloc_esr_pf_failed;
    }

    platform_memcpy(a->demote, demote, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(a->promote, promote, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(a->esr_default, esr_default, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(a->esr_df, esr_df, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(a->esr_gpf, esr_gpf, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(a->esr_nmi, esr_nmi, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(a->esr_pf, esr_pf, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(a->serial_write_c, serial_write_c, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(a->serial_write_hex, serial_write_hex, HYPERVISOR_PAGE_SIZE);

    return LOADER_SUCCESS;

platform_alloc_esr_pf_failed:

    platform_free(a->esr_nmi, HYPERVISOR_PAGE_SIZE);
platform_alloc_esr_nmi_failed:

    platform_free(a->esr_gpf, HYPERVISOR_PAGE_SIZE);
platform_alloc_esr_gpf_failed:

    platform_free(a->esr_df, HYPERVISOR_PAGE_SIZE);
platform_alloc_esr_df_failed:

    platform_free(a->esr_default, HYPERVISOR_PAGE_SIZE);
platform_alloc_esr_default_failed:

    platform_free(a->promote, HYPERVISOR_PAGE_SIZE);
platform_alloc_promote_failed:

    platform_free(a->demote, HYPERVISOR_PAGE_SIZE);
platform_alloc_demote_failed:

    platform_memset(a, 0, sizeof(struct code_aliases_t));
    return LOADER_FAILURE;
}

#ifdef _MSC_VER
#pragma warning(default : 4152)
#endif
