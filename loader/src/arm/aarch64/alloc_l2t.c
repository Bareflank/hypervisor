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

#include <constants.h>
#include <debug.h>
#include <flush_cache.h>
#include <l1t_t.h>
#include <l1to.h>
#include <l2t_t.h>
#include <platform.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Given a l1t_t and a virtual address, this function allocates a
 *     l2t_t and adds it to the l1t_t. If an l2t_t has already been allocated,
 *     this function will fail.
 *
 * <!-- inputs/outputs -->
 *   @param l1 the l1t_t to add the newly allocated l2t_t to
 *   @param virt the virtual address to get the l1t_t offset from.
 *   @return a pointer to the newly allocated l2t_t on success, NULLPTR
 *     otherwise.
 */
NODISCARD struct l2t_t *
alloc_l2t(struct l1t_t *const l1t, uint64_t const virt) NOEXCEPT
{
    uint64_t i;
    uint64_t phys;
    struct l2t_t *l2t;
    struct l1te_t *l1te;

    l1te = &l1t->entires[l1to(virt)];
    if (l1te->p != ((uint64_t)0)) {
        bferror_x64("l2t already present", virt);
        return NULLPTR;
    }

    l2t = (struct l2t_t *)platform_alloc(sizeof(struct l2t_t));
    if (NULLPTR == l2t) {
        bferror("platform_alloc failed");
        goto platform_alloc_l2t_failed;
    }

    for (i = 0; i < LOADER_NUM_L2T_ENTRIES; ++i) {
        flush_cache(&(l2t->entires[i]));
    }

    phys = platform_virt_to_phys(l2t);
    if (((uint64_t)0) == phys) {
        bferror("platform_virt_to_phys_l2t failed");
        goto platform_virt_to_phys_l2t_failed;
    }

    l1t->tables[l1to(virt)] = l2t;
    l1te->phys = (phys >> HYPERVISOR_PAGE_SHIFT);
    l1te->p = ((uint64_t)1);
    l1te->bt = ((uint64_t)1);

    flush_cache(l1te);
    return l2t;

platform_virt_to_phys_l2t_failed:

    platform_free(l2t, sizeof(struct l2t_t));
platform_alloc_l2t_failed:

    return NULLPTR;
}
