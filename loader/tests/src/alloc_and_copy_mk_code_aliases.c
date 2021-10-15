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
#include <demote.h>
#include <platform.h>
#include <promote.h>
#include <serial_write_c.h>
#include <serial_write_hex.h>
#include <types.h>

#ifdef _MSC_VER
#pragma warning(disable : 4152)
#endif

int32_t g_mut_alloc_and_copy_mk_code_aliases = 0;

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
 *   @param pmut_a a pointer to a code_aliases_t that will store the
 *     resulting aliases.
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
NODISCARD int64_t
alloc_and_copy_mk_code_aliases(struct code_aliases_t *const pmut_a) NOEXCEPT
{
    if (g_mut_alloc_and_copy_mk_code_aliases > 0) {
        --g_mut_alloc_and_copy_mk_code_aliases;
        return LOADER_FAILURE;
    }

    pmut_a->demote = platform_alloc(HYPERVISOR_PAGE_SIZE);
    platform_expects(NULLPTR != pmut_a->demote);

    pmut_a->promote = platform_alloc(HYPERVISOR_PAGE_SIZE);
    platform_expects(NULLPTR != pmut_a->promote);

    pmut_a->serial_write_c = platform_alloc(HYPERVISOR_PAGE_SIZE);
    platform_expects(NULLPTR != pmut_a->serial_write_c);

    pmut_a->serial_write_hex = platform_alloc(HYPERVISOR_PAGE_SIZE);
    platform_expects(NULLPTR != pmut_a->serial_write_hex);

    platform_memcpy(pmut_a->demote, (void *)&demote, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(pmut_a->promote, (void *)&promote, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(pmut_a->serial_write_c, (void *)&serial_write_c, HYPERVISOR_PAGE_SIZE);
    platform_memcpy(pmut_a->serial_write_hex, (void *)&serial_write_hex, HYPERVISOR_PAGE_SIZE);

    return LOADER_SUCCESS;
}

#ifdef _MSC_VER
#pragma warning(default : 4152)
#endif
