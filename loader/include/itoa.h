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

#ifndef ITOA_H
#define ITOA_H

#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * <!-- description -->
     *   @brief Implements itoa
     *
     * <!-- inputs/outputs -->
     *   @param mut_value the value to convert to a string
     *   @param pmut_str where to store the results
     *   @param base the base for conversion, which should only be 10 or 16
     *   @return returns str
     */
    NODISCARD static inline char *
    bfitoa(uint64_t mut_value, char *const pmut_str, uint64_t const base) NOEXCEPT
    {
        char const digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
        uint64_t mut_i = ((uint64_t)0);
        uint64_t mut_j = ((uint64_t)0);
        uint64_t mut_remainder = ((uint64_t)0);

        do {
            mut_remainder = mut_value % base;
            pmut_str[mut_i++] = digits[mut_remainder];
            mut_value = mut_value / base;
        } while (((uint64_t)0) != mut_value);

        pmut_str[mut_i] = ((char)'\0');

        for (mut_j = ((uint64_t)0), mut_i--; mut_j < mut_i; mut_j++, mut_i--) {
            char const c = pmut_str[mut_j];
            pmut_str[mut_j] = pmut_str[mut_i];
            pmut_str[mut_i] = c;
        }

        return pmut_str;
    }

#ifdef __cplusplus
}
#endif

#endif
