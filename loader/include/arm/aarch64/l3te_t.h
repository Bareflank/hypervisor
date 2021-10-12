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

#ifndef L3TE_T
#define L3TE_T

#include <types.h>

#pragma pack(push, 1)

/** @brief used to signal that the page should be non-cached */
#define bfelf_pf_nc ((uint32_t)0x01000000U)

/**
 * <!-- description -->
 *   @brief Defines the layout of a level-3 table entry (L3TE).
 */
struct l3te_t
{
    /** @brief defines the "present" field in the page */
    uint64_t p : ((uint64_t)1);
    /** @brief defines the "page" field in the page */
    uint64_t page : ((uint64_t)1);
    /** @brief defines the "AttrIndx" field in the page */
    uint64_t attr_indx : ((uint64_t)3);
    /** @brief defines the "NS" field in the page */
    uint64_t ns : ((uint64_t)1);
    /** @brief defines the "AP" field in the page */
    uint64_t ap : ((uint64_t)2);
    /** @brief defines the "SH" field in the page */
    uint64_t sh : ((uint64_t)2);
    /** @brief defines the "AF" field in the page */
    uint64_t af : ((uint64_t)1);
    /** @brief defines the "nG" field in the page */
    uint64_t ng : ((uint64_t)1);
    /** @brief defines the "physical address" field in the page */
    uint64_t phys : ((uint64_t)38);
    /** @brief defines the "GP" field in the page */
    uint64_t gp : ((uint64_t)1);
    /** @brief defines the "DBM" field in the page */
    uint64_t dbm : ((uint64_t)1);
    /** @brief defines the "Contiguous" field in the page */
    uint64_t contiguous : ((uint64_t)1);
    /** @brief defines the "PXN" field in the page */
    uint64_t pxn : ((uint64_t)1);
    /** @brief defines the "UXN or XN" field in the page */
    uint64_t xn : ((uint64_t)1);
    /** @brief defines our "auto_release" field in the page */
    uint64_t auto_release : ((uint64_t)3);
    /** @brief defines the "available to software" field in the page */
    uint64_t available1 : ((uint64_t)1);
    /** @brief defines the "PBHA" field in the page */
    uint64_t pbha : ((uint64_t)4);
    /** @brief defines the "available to software" field in the page */
    uint64_t available2 : ((uint64_t)1);
};

#pragma pack(pop)

#endif
