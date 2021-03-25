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

#ifndef BFELF_TYPES_H
#define BFELF_TYPES_H

#include <stdint.h>

/** @brief defines an unsigned program address */
typedef uintptr_t bfelf_elf64_addr;
/** @brief defines an unsigned file offset */
typedef uintptr_t bfelf_elf64_off;
/** @brief defines an unsigned medium integer */
typedef uint16_t bfelf_elf64_half;
/** @brief defines an unsigned integer */
typedef uint32_t bfelf_elf64_word;
/** @brief defines an signed integer */
typedef int32_t bfelf_elf64_sword;
/** @brief defines an unsigned long integer */
typedef uint64_t bfelf_elf64_xword;
/** @brief defines an signed long integer */
typedef int64_t bfelf_elf64_sxword;

/** @brief returned by a function for an invalid argument */
#define BFELF_INVALID_ARGUMENT ((int64_t)0xBFE1F00000000100)
/** @brief returned by a function for an invalid mag0 */
#define BFELF_INVALID_MAG0 ((int64_t)0xBFE1F00000000101)
/** @brief returned by a function for an invalid mag1 */
#define BFELF_INVALID_MAG1 ((int64_t)0xBFE1F00000000102)
/** @brief returned by a function for an invalid mag2 */
#define BFELF_INVALID_MAG2 ((int64_t)0xBFE1F00000000103)
/** @brief returned by a function for an invalid mag3 */
#define BFELF_INVALID_MAG3 ((int64_t)0xBFE1F00000000104)
/** @brief returned by a function for an invalid class */
#define BFELF_INVALID_CLASS ((int64_t)0xBFE1F00000000105)
/** @brief returned by a function for an invalid osabi */
#define BFELF_INVALID_OSABI ((int64_t)0xBFE1F00000000106)
/** @brief returned by a function for an invalid type */
#define BFELF_INVALID_TYPE ((int64_t)0xBFE1F00000000107)

#endif
