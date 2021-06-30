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

#ifndef L3TO_H
#define L3TO_H

#include <types.h>

/** @brief defines the mask used for the L3T offset */
#define L3T_OFFSET_MASK ((uint64_t)0x1FF)
/** @brief defines the bit location of the L3T offset */
#define L3T_OFFSET_SHIFT ((uint64_t)12)

/**
 * <!-- description -->
 *   @brief Returns the level-3 table (L3T) offset given a
 *     virtual address.
 *
 * <!-- inputs/outputs -->
 *   @param virt the virtual address to get the L3T offset from.
 *   @return the L3T offset from the virtual address
 */
static inline uint64_t
l3to(uint64_t const virt)
{
    return ((virt >> L3T_OFFSET_SHIFT) & L3T_OFFSET_MASK);
}

#endif
