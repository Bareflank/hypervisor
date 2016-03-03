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

#include <crt.h>
#include <eh_frame_list.h>

typedef void (*ctor_t)(void);
typedef void (*dtor_t)(void);

void local_init(struct section_info_t *info)
{
    if (info == 0)
        return;

    if (info->ctors_addr != 0)
    {
        int i = 0;
        int n = info->ctors_size / sizeof(ctor_t);
        ctor_t *ctors = (ctor_t *)info->ctors_addr;

        while(i < n && ctors[i] != 0)
            ctors[i++]();
    }

    register_eh_frame(info->eh_frame_addr, info->eh_frame_size);
}

void local_fini(struct section_info_t *info)
{
    if (info == 0)
        return;

    if (info->dtors_addr != 0)
    {
        int i = 0;
        int n = info->dtors_size / sizeof(dtor_t);
        dtor_t *dtors = (dtor_t *)info->dtors_addr;

        while(i < n && dtors[i] != 0)
            dtors[i++]();
    }
}
