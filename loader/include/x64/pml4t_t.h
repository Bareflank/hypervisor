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

#ifndef PML4T_T_H
#define PML4T_T_H

#include <pdpt_t.h>
#include <pml4te_t.h>
#include <types.h>

#pragma pack(push, 1)

/** @brief defines total number of entries in the PML4T */
#define LOADER_NUM_PML4T_ENTRIES ((uint64_t)512)

/**
 * @struct pml4t_t
 *
 * <!-- description -->
 *   @brief Defines the layout of a page-map level-4 table (pml4).
 */
struct pml4t_t
{
    /** @brief stores the entries for this page table */
    struct pml4te_t entires[LOADER_NUM_PML4T_ENTRIES];
    /** @brief stores pointers to child tables */
    struct pdpt_t *tables[LOADER_NUM_PML4T_ENTRIES];
};

#pragma pack(pop)

#endif
