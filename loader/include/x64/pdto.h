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

#ifndef PDTO_H
#define PDTO_H

#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief defines the size of the PDT offset */
#define PDT_OFFSET_MASK ((uint64_t)0x1FF)
/** @brief defines the bit location of the PDT offset */
#define PDT_OFFSET_SHIFT ((uint64_t)21)

    /**
     * <!-- description -->
     *   @brief Returns the page-directory table (PDT) offset given a
     *     virtual address.
     *
     * <!-- inputs/outputs -->
     *   @param virt the virtual address to get the PDT offset from.
     *   @return the PDT offset from the virtual address
     */
    NODISCARD static inline uint64_t
    pdto(uint64_t const virt) NOEXCEPT
    {
        return ((virt >> PDT_OFFSET_SHIFT) & PDT_OFFSET_MASK);
    }

#ifdef __cplusplus
}
#endif

#endif
