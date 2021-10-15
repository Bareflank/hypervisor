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

#include <disable_hve.h>
#include <global_descriptor_table_register_t.h>
#include <interrupt_descriptor_table_register_t.h>
#include <platform.h>
#include <state_save_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Releases a previously allocated state_save_t that was allocated
 *     using the alloc_and_copy_mk_state function.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_state the state_save_t to free.
 */
void
free_mk_state(struct state_save_t **const pmut_state) NOEXCEPT
{
    platform_expects(NULLPTR != pmut_state);

    if (NULLPTR == *pmut_state) {
        return;
    }

    platform_free((*pmut_state)->idtr.base, HYPERVISOR_PAGE_SIZE);
    platform_free((*pmut_state)->gdtr.base, HYPERVISOR_PAGE_SIZE);
    platform_free((*pmut_state)->ist, HYPERVISOR_PAGE_SIZE);
    platform_free((*pmut_state)->tss, HYPERVISOR_PAGE_SIZE);

    disable_hve();
    platform_free((*pmut_state)->hve_page, HYPERVISOR_PAGE_SIZE);

    platform_free(*pmut_state, HYPERVISOR_PAGE_SIZE);
    *pmut_state = NULLPTR;
}
