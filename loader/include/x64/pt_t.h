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

#ifndef PT_T_H
#define PT_T_H

#pragma pack(push, 1)

#include <pte_t.h>
#include <static_assert.h>
#include <types.h>

/** @brief defines total number of entries in the PT */
#define LOADER_NUM_PT_ENTRIES ((uint64_t)512)

/**
 * @struct pt_t
 *
 * <!-- description -->
 *   @brief Defines the layout of a page table (pt).
 */
struct pt_t
{
    /** @brief stores the entries for this page table */
    struct pte_t entires[LOADER_NUM_PT_ENTRIES];
};

/** @brief verify that the pt_t structure is the right size */
STATIC_ASSERT(sizeof(struct pt_t) == 0x1000, pt_t_has_incorrect_size);

#pragma pack(pop)

#endif
