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

#ifndef L0TE_T
#define L0TE_T

#include <types.h>

#pragma pack(push, 1)

/**
 * @struct l0te_t
 *
 * <!-- description -->
 *   @brief Defines the layout of a level-0 table entry (L0TE).
 */
struct l0te_t
{
    /** @brief defines the "present" field in the page */
    uint64_t p : ((uint64_t)1);
    /** @brief defines the "block/table" field in the page */
    uint64_t bt : ((uint64_t)1);
    /** @brief defines our "aliased" field in the page */
    uint64_t alias : ((uint64_t)1);
    /** @brief defines the "available to software" field in the page */
    uint64_t available1 : ((uint64_t)9);
    /** @brief defines the "physical address" field in the page */
    uint64_t phys : ((uint64_t)40);
    /** @brief defines the "available to software" field in the page */
    uint64_t available2 : ((uint64_t)7);
    /** @brief defines the "PXNTable" field in the page */
    uint64_t pxntable : ((uint64_t)1);
    /** @brief defines the "XNTable" field in the page */
    uint64_t xntable : ((uint64_t)1);
    /** @brief defines the "APTable" field in the page */
    uint64_t aptable : ((uint64_t)2);
    /** @brief defines the "NSTable" field in the page */
    uint64_t nstable : ((uint64_t)1);
};

#pragma pack(pop)

#endif
