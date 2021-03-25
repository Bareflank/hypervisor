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
#include <l2t_t.h>
#include <l2to.h>
#include <l3t_t.h>
#include <platform.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Given a l2t_t and a virtual address, this function allocates a
 *     l3t_t and adds it to the l2t_t. If an l3t_t has already been allocated,
 *     this function will fail.
 *
 * <!-- inputs/outputs -->
 *   @param l2 the l2t_t to add the newly allocated l3t_t to
 *   @param virt the virtual address to get the l2t_t offset from.
 *   @return a pointer to the newly allocated l3t_t on success, ((void *)0)
 *     otherwise.
 */
struct l3t_t *
alloc_l3t(struct l2t_t *const l2t, uint64_t const virt)
{
    uint64_t i;
    uint64_t phys;
    struct l3t_t *l3t;
    struct l2te_t *l2te;

    l2te = &l2t->entires[l2to(virt)];
    if (l2te->p != ((uint64_t)0)) {
        bferror_x64("l3t already present", virt);
        return ((void *)0);
    }

    l3t = (struct l3t_t *)platform_alloc(sizeof(struct l3t_t));
    if (((void *)0) == l3t) {
        bferror("platform_alloc failed");
        goto platform_alloc_l3t_failed;
    }

    for (i = 0; i < LOADER_NUM_L3T_ENTRIES; ++i) {
        flush_cache(&(l3t->entires[i]));
    }

    phys = platform_virt_to_phys(l3t);
    if (((uint64_t)0) == phys) {
        bferror("platform_virt_to_phys_l3t failed");
        goto platform_virt_to_phys_l3t_failed;
    }

    l2t->tables[l2to(virt)] = l3t;
    l2te->phys = (phys >> HYPERVISOR_PAGE_SHIFT);
    l2te->p = ((uint64_t)1);
    l2te->bt = ((uint64_t)1);

    flush_cache(l2te);
    return l3t;

platform_virt_to_phys_l3t_failed:

    platform_free(l3t, sizeof(struct l3t_t));
platform_alloc_l3t_failed:

    return ((void *)0);
}
