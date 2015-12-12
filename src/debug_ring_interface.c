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

#include <debug_ring_interface.h>

long long int
debug_ring_read(struct debug_ring_resources_t *drr, char *str, long long int len)
{
    long long int i;
    long long int spos;
    long long int content;

    if (drr == 0 || str == 0 || len == 0)
        return DEBUG_RING_READ_ERROR;

    spos = drr->spos % DEBUG_RING_SIZE;
    content = drr->epos - drr->spos;

    /*
     * We need to remove the \0 from the output because it causes the Linux
     * kernel logging daemon to get all sorts of mad. We need to keep it in
     * the original ring because we use it to figure out which strings to
     * remove when we run out of space
     */

    for (i = 0; i < content && i < len - 1; i++)
    {
        if (spos == DEBUG_RING_SIZE)
            spos = 0;

        if (drr->buf[spos] != '\0')
            str[i] = drr->buf[spos];
        else
        {
            i--;
            content--;
        }

        spos++;
    }

    str[i] = '\0';

    return content;
}
