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

#ifndef CONSTANTS_H
#define CONSTANTS_H

/*
 * Max Supported VCPUs
 */
#ifndef MAX_PAGES
#define MAX_PAGES 10
#endif

/*
 * Max Supported VCPUs
 */
#ifndef MAX_VCPUS
#define MAX_VCPUS 1
#endif

/*
 * Max Supported Modules
 */
#ifndef MAX_NUM_MODULES
#define MAX_NUM_MODULES 25
#endif

/**
 * Defines the size of a Debug Ring
 */
#ifndef DEBUG_RING_SIZE
#define DEBUG_RING_SIZE (10 * 4096)
#endif

#endif
