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

#include <alloc_mk_huge_pool.h>
#include <debug.h>
#include <mutable_span_t.h>
#include <platform.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Allocates a chunk of memory for the huge pool used by the
 *     microkernel. Note that the "size" parameter is in total pages and
 *     not in bytes. Finally, if the provided size is 0, this function
 *     will allocate a default number of pages.
 *
 * <!-- inputs/outputs -->
 *   @param size the total number of pages (not bytes) to allocate
 *   @param pmut_huge_pool the mutable_span_t to store the page pool addr/size.
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
NODISCARD int64_t
alloc_mk_huge_pool(uint32_t const size, struct mutable_span_t *const pmut_huge_pool) NOEXCEPT
{
    if (0U == size) {
        pmut_huge_pool->size = HYPERVISOR_MK_HUGE_POOL_SIZE;
    }
    else {
        pmut_huge_pool->size = HYPERVISOR_PAGE_SIZE * (uint64_t)size;
    }

    pmut_huge_pool->addr = platform_alloc_contiguous(pmut_huge_pool->size);
    if (NULLPTR == pmut_huge_pool->addr) {
        bferror("platform_alloc failed");
        goto platform_alloc_failed;
    }

    return LOADER_SUCCESS;

platform_alloc_failed:

    platform_memset(pmut_huge_pool, ((uint8_t)0), sizeof(struct mutable_span_t));
    return LOADER_FAILURE;
}
