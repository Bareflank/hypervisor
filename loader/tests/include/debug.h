/* SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT */

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

#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>    // IWYU pragma: export
#include <types.h>

/**
 * <!-- description -->
 *   @brief Outputs a string to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 */
static inline void
bfdebug(char const *const str) NOEXCEPT
{
    printf("[BAREFLANK DEBUG] %s\n", str);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 8bit hex to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 8bit hex value to output
 */
static inline void
bfdebug_x8(char const *const str, uint8_t const val) NOEXCEPT
{
    printf("[BAREFLANK DEBUG] %s: 0x%" PRIx32 "\n", str, (uint32_t)val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 16bit hex to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 16bit hex value to output
 */
static inline void
bfdebug_x16(char const *const str, uint16_t const val) NOEXCEPT
{
    printf("[BAREFLANK DEBUG] %s: 0x%" PRIx32 "\n", str, (uint32_t)val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 32bit hex to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 32bit hex value to output
 */
static inline void
bfdebug_x32(char const *const str, uint32_t const val) NOEXCEPT
{
    printf("[BAREFLANK DEBUG] %s: 0x%" PRIx32 "\n", str, val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 64bit hex to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 64bit hex value to output
 */
static inline void
bfdebug_x64(char const *const str, uint64_t const val) NOEXCEPT
{
    printf("[BAREFLANK DEBUG] %s: 0x%" PRIx64 "\n", str, val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 8bit dec to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 8bit dec value to output
 */
static inline void
bfdebug_d8(char const *const str, uint8_t const val) NOEXCEPT
{
    printf("[BAREFLANK DEBUG] %s: %" PRId32 "\n", str, (uint32_t)val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 16bit dec to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 16bit dec value to output
 */
static inline void
bfdebug_d16(char const *const str, uint16_t const val) NOEXCEPT
{
    printf("[BAREFLANK DEBUG] %s: %" PRId32 "\n", str, (uint32_t)val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 32bit dec to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 32bit dec value to output
 */
static inline void
bfdebug_d32(char const *const str, uint32_t const val) NOEXCEPT
{
    printf("[BAREFLANK DEBUG] %s: %" PRId32 "\n", str, val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 64bit dec to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 64bit dec value to output
 */
static inline void
bfdebug_d64(char const *const str, uint64_t const val) NOEXCEPT
{
    printf("[BAREFLANK DEBUG] %s: %" PRId64 "\n", str, val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an pointer to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param p the pointer to output
 */
static inline void
bfdebug_ptr(char const *const str, void const *const p) NOEXCEPT
{
    printf("[BAREFLANK DEBUG] %s: 0x%p\n", str, p);
}

/**
 * <!-- description -->
 *   @brief Outputs a string to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 */
static inline void
bferror(char const *const str) NOEXCEPT
{
    printf("[BAREFLANK ERROR] %s\n", str);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 8bit hex to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 8bit hex value to output
 */
static inline void
bferror_x8(char const *const str, uint8_t const val) NOEXCEPT
{
    printf("[BAREFLANK ERROR] %s: 0x%" PRIx32 "\n", str, (uint32_t)val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 16bit hex to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 16bit hex value to output
 */
static inline void
bferror_x16(char const *const str, uint16_t const val) NOEXCEPT
{
    printf("[BAREFLANK ERROR] %s: 0x%" PRIx32 "\n", str, (uint32_t)val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 32bit hex to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 32bit hex value to output
 */
static inline void
bferror_x32(char const *const str, uint32_t const val) NOEXCEPT
{
    printf("[BAREFLANK ERROR] %s: 0x%" PRIx32 "\n", str, val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 64bit hex to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 64bit hex value to output
 */
static inline void
bferror_x64(char const *const str, uint64_t const val) NOEXCEPT
{
    printf("[BAREFLANK ERROR] %s: 0x%" PRIx64 "\n", str, val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 8bit dec to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 8bit dec value to output
 */
static inline void
bferror_d8(char const *const str, uint8_t const val) NOEXCEPT
{
    printf("[BAREFLANK ERROR] %s: %" PRId32 "\n", str, (uint32_t)val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 16bit dec to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 16bit dec value to output
 */
static inline void
bferror_d16(char const *const str, uint16_t const val) NOEXCEPT
{
    printf("[BAREFLANK ERROR] %s: %" PRId32 "\n", str, (uint32_t)val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 32bit dec to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 32bit dec value to output
 */
static inline void
bferror_d32(char const *const str, uint32_t const val) NOEXCEPT
{
    printf("[BAREFLANK ERROR] %s: %" PRId32 "\n", str, val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 64bit dec to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param val the 64bit dec value to output
 */
static inline void
bferror_d64(char const *const str, uint64_t const val) NOEXCEPT
{
    printf("[BAREFLANK ERROR] %s: %" PRId64 "\n", str, val);
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an pointer to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param p the pointer value to output
 */
static inline void
bferror_ptr(char const *const str, void const *const p) NOEXCEPT
{
    printf("[BAREFLANK ERROR] %s: 0x%p\n", str, p);
}

#endif
