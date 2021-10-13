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

#include <efi/efi_system_table.h>
#include <efi/efi_types.h>
#include <itoa.h>
#include <serial_write.h>
#include <types.h>

/** @brief defines a constant for base 10 */
#define BASE10 ((uint64_t)10)
/** @brief defines a constant for base 16 */
#define BASE16 ((uint64_t)16)

/**
 * <!-- description -->
 *   @brief Writes a string to the console.
 *
 * <!-- inputs/outputs -->
 *   @param str the string to write to the console.
 */
static inline void
console_write(char const *const str)
{
    uint64_t i = 0;
    char buf[4] = {0};

    /**
     * NOTE:
     * - We cannot simply send the string to OutputString as it is expecting
     *   a unicode string.
     * - The minimum sized unicode string is one character (2 bytes) and a
     *   second character for the \0, which is why we have a 4 byte array.
     *   One byte to store the character we wish to print, and a second to
     *   tell OutputString to stop.
     * - This, of course would not be needed if EFI has a character output
     *   function, which is basically what this function needs to emulate.
     */

    while (str[i] != '\0') {
        buf[0] = str[i];
        if (g_st->ConOut->OutputString(g_st->ConOut, ((CHAR16 *)buf))) {
            return;
        }

        ++i;
    }
}

static inline void
console_write_c(char const c)
{
    char buf[4] = {0};

    if (c == '\n') {
        console_write("\r\n");
        return;
    }

    if (c == '\r') {
        return;
    }

    /**
     * NOTE:
     * - We cannot simply send the string to OutputString as it is expecting
     *   a unicode string.
     * - The minimum sized unicode string is one character (2 bytes) and a
     *   second character for the \0, which is why we have a 4 byte array.
     *   One byte to store the character we wish to print, and a second to
     *   tell OutputString to stop.
     * - This, of course would not be needed if EFI has a character output
     *   function, which is basically what this function needs to emulate.
     */

    buf[0] = c;
    g_st->ConOut->OutputString(g_st->ConOut, ((CHAR16 *)buf));
}

/**
 * <!-- description -->
 *   @brief Outputs a string to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 */
static inline void
bfdebug(char const *const str)
{
    serial_write("[BAREFLANK DEBUG] ");
    serial_write(str);
    serial_write("\n");

    console_write("[BAREFLANK DEBUG] ");
    console_write(str);
    console_write("\r\n");
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
bfdebug_x8(char const *const str, uint8_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE16);

    serial_write("[BAREFLANK DEBUG] ");
    serial_write(str);
    serial_write(": 0x");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK DEBUG] ");
    console_write(str);
    console_write(": 0x");
    console_write(num);
    console_write("\r\n");
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
bfdebug_x16(char const *const str, uint16_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE16);

    serial_write("[BAREFLANK DEBUG] ");
    serial_write(str);
    serial_write(": 0x");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK DEBUG] ");
    console_write(str);
    console_write(": 0x");
    console_write(num);
    console_write("\r\n");
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
bfdebug_x32(char const *const str, uint32_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE16);

    serial_write("[BAREFLANK DEBUG] ");
    serial_write(str);
    serial_write(": 0x");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK DEBUG] ");
    console_write(str);
    console_write(": 0x");
    console_write(num);
    console_write("\r\n");
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
bfdebug_x64(char const *const str, uint64_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE16);

    serial_write("[BAREFLANK DEBUG] ");
    serial_write(str);
    serial_write(": 0x");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK DEBUG] ");
    console_write(str);
    console_write(": 0x");
    console_write(num);
    console_write("\r\n");
}

/**
 * <!-- description -->
 *   @brief Outputs a string and an 64bit hex to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 *   @param idx an index (for an array)
 *   @param val the 64bit hex value to output
 */
static inline void
bfdebug_x64_idx(char const *const str, uint64_t const idx, uint64_t const val)
{
    char idx_num[65] = {0};
    char val_num[65] = {0};
    (void)bfitoa(((uint64_t)idx), idx_num, BASE16);
    (void)bfitoa(((uint64_t)val), val_num, BASE16);

    serial_write(str);
    serial_write("[0x");
    serial_write(idx_num);
    serial_write("]: 0x");
    serial_write(val_num);
    serial_write("\n");
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
bfdebug_d8(char const *const str, uint8_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE10);

    serial_write("[BAREFLANK DEBUG] ");
    serial_write(str);
    serial_write(": ");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK DEBUG] ");
    console_write(str);
    console_write(": ");
    console_write(num);
    console_write("\r\n");
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
bfdebug_d16(char const *const str, uint16_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE10);

    serial_write("[BAREFLANK DEBUG] ");
    serial_write(str);
    serial_write(": ");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK DEBUG] ");
    console_write(str);
    console_write(": ");
    console_write(num);
    console_write("\r\n");
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
bfdebug_d32(char const *const str, uint32_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE10);

    serial_write("[BAREFLANK DEBUG] ");
    serial_write(str);
    serial_write(": ");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK DEBUG] ");
    console_write(str);
    console_write(": ");
    console_write(num);
    console_write("\r\n");
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
bfdebug_d64(char const *const str, uint64_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE10);

    serial_write("[BAREFLANK DEBUG] ");
    serial_write(str);
    serial_write(": ");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK DEBUG] ");
    console_write(str);
    console_write(": ");
    console_write(num);
    console_write("\r\n");
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
bfdebug_ptr(char const *const str, void const *const p)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)p), num, BASE16);

    serial_write("[BAREFLANK DEBUG] ");
    serial_write(str);
    serial_write(": 0x");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK DEBUG] ");
    console_write(str);
    console_write(": 0x");
    console_write(num);
    console_write("\r\n");
}

/**
 * <!-- description -->
 *   @brief Outputs a string to the console
 *
 * <!-- inputs/outputs -->
 *   @param str the string to output
 */
static inline void
bferror(char const *const str)
{
    serial_write("[BAREFLANK ERROR] ");
    serial_write(str);
    serial_write("\n");

    console_write("[BAREFLANK ERROR] ");
    console_write(str);
    console_write("\r\n");
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
bferror_x8(char const *const str, uint8_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE16);

    serial_write("[BAREFLANK ERROR] ");
    serial_write(str);
    serial_write(": 0x");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK ERROR] ");
    console_write(str);
    console_write(": 0x");
    console_write(num);
    console_write("\r\n");
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
bferror_x16(char const *const str, uint16_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE16);

    serial_write("[BAREFLANK ERROR] ");
    serial_write(str);
    serial_write(": 0x");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK ERROR] ");
    console_write(str);
    console_write(": 0x");
    console_write(num);
    console_write("\r\n");
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
bferror_x32(char const *const str, uint32_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE16);

    serial_write("[BAREFLANK ERROR] ");
    serial_write(str);
    serial_write(": 0x");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK ERROR] ");
    console_write(str);
    console_write(": 0x");
    console_write(num);
    console_write("\r\n");
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
bferror_x64(char const *const str, uint64_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE16);

    serial_write("[BAREFLANK ERROR] ");
    serial_write(str);
    serial_write(": 0x");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK ERROR] ");
    console_write(str);
    console_write(": 0x");
    console_write(num);
    console_write("\r\n");
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
bferror_d8(char const *const str, uint8_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE10);

    serial_write("[BAREFLANK ERROR] ");
    serial_write(str);
    serial_write(": ");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK ERROR] ");
    console_write(str);
    console_write(": ");
    console_write(num);
    console_write("\r\n");
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
bferror_d16(char const *const str, uint16_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE10);

    serial_write("[BAREFLANK ERROR] ");
    serial_write(str);
    serial_write(": ");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK ERROR] ");
    console_write(str);
    console_write(": ");
    console_write(num);
    console_write("\r\n");
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
bferror_d32(char const *const str, uint32_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE10);

    serial_write("[BAREFLANK ERROR] ");
    serial_write(str);
    serial_write(": ");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK ERROR] ");
    console_write(str);
    console_write(": ");
    console_write(num);
    console_write("\r\n");
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
bferror_d64(char const *const str, uint64_t const val)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)val), num, BASE10);

    serial_write("[BAREFLANK ERROR] ");
    serial_write(str);
    serial_write(": ");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK ERROR] ");
    console_write(str);
    console_write(": ");
    console_write(num);
    console_write("\r\n");
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
bferror_ptr(char const *const str, void const *const p)
{
    char num[65] = {0};
    (void)bfitoa(((uint64_t)p), num, BASE16);

    serial_write("[BAREFLANK ERROR] ");
    serial_write(str);
    serial_write(": 0x");
    serial_write(num);
    serial_write("\n");

    console_write("[BAREFLANK ERROR] ");
    console_write(str);
    console_write(": 0x");
    console_write(num);
    console_write("\r\n");
}

#endif
