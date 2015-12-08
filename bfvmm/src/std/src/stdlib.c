/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <std/string.h>
#include <std/stdlib.h>

/* ========================================================================== */
/* Helpers                                                                    */
/* ========================================================================== */

char *reverse(char *str)
{
    int i = 0;
    int j = bfstrlen(str) - 1;

    while (i < j)
    {
        char c = str[i];
        str[i] = str[j];
        str[j] = c;

        i++;
        j--;
    }

    return str;
}

char *bfitoa_10(int64_t value, char *str, uint64_t base)
{
    int64_t i = 0;
    int64_t s = value;

    if (value < 0)
        value = -value;

    while (value != 0)
    {
        str[i] = (value % base) + '0';

        i++;
        value /= base;
    }

    if (s < 0)
        str[i++] = '-';

    str[i++] = '\0';

    return reverse(str);
}

char *bfitoa_xxx(uint64_t value, char *str, uint64_t base)
{
    uint64_t i = 0;
    uint64_t d = 0;

    while (value != 0)
    {
        str[i] = (d = value % base) < 10 ? d + '0' : (d - 10) + 'A';

        i++;
        value /= base;
    }

    str[i++] = '\0';

    return reverse(str);
}

/* ========================================================================== */
/* Implementation                                                             */
/* ========================================================================== */

char *itoa(int64_t value, char *str, uint64_t base)
{
    return bfitoa(value, str, base);
}

char *bfitoa(int64_t value, char *str, uint64_t base)
{
    if (str == 0)
        return 0;

    if (value == 0 || base == 0)
    {
        str[0] = '0';
        str[1] = '\0';

        return str;
    }

    /*
     * itoa treats all base 10 numbers as signed, and the rest of the base
     * numbers as unsigned. To keep things clean, we have different functions
     * for each
     */
    if (base == 10)
        return bfitoa_10(value, str, base);
    else
        return bfitoa_xxx(value, str, base);
}
