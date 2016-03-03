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

#ifndef EH_FRAME_LIST_H
#define EH_FRAME_LIST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * EH Frame
 *
 * Defines a ".eh_frame" section.
 *
 * @var eh_frame_t::addr
 *     the starting address of the the .eh_frame section
 * @var eh_frame_t::size
 *     the size of the .eh_frame section
 */
struct eh_frame_t
{
    void *addr;
    uint64_t size;
};

/**
 * Get EH Framework List
 *
 * Returns a list of ".eh_frame" sections, containing their start address,
 * and size. This is used by the unwind library to find stack frames. The
 * list should have one .eh_frame section for each module that is loaded.
 *
 * @return eh_frame list (of size MAX_NUM_MODULES)
 */
struct eh_frame_t *get_eh_frame_list();

/**
 * Register EH Framework
 *
 * Registers an ".eh_frame" section, containing it's start address,
 * and size. This will add the eh_frame section to a global list that can
 * be retreived using get_eh_frame_list
 *
 * @param addr the address of the eh_frame section
 * @param size the size of the eh_frame section
 *
 */
void register_eh_frame(void *addr, uint64_t size);

#ifdef __cplusplus
}
#endif

#endif
