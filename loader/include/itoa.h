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

/**
 * <!-- description -->
 *   @brief Implements itoa
 *
 * <!-- inputs/outputs -->
 *   @param value the value to convert to a string
 *   @param str where to store the results
 *   @param base the base for conversion, which should only be 10 or 16
 *   @return returns str
 */
static inline char *
bfitoa(uint64_t value, char *const str, uint64_t const base)
{
    /**
     * TODO:
     * - Rework this code to be compliant with MISRA/AUTOSAR. Specifically,
     *   this needs bounds checks, the result of increment should not be
     *   used directly, make sure base is only 10 or 16, get rid of the
     *   do/while loop, etc...
     */

    char const digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    uint64_t i = 0;
    uint64_t j = 0;
    uint64_t remainder;

    do {
        remainder = value % base;
        str[i++] = digits[remainder];
        value = value / base;
    } while (value != 0);

    str[i] = '\0';

    for (j = 0, i--; j < i; j++, i--) {
        char c = str[j];
        str[j] = str[i];
        str[i] = c;
    }

    return str;
}

#endif
