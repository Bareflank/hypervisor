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

#ifndef VMM_ENTRY_INTERFACE_H
#define VMM_ENTRY_INTERFACE_H

#include <debug_ring_interface.h>

/**
 * VMM Error Codes
 */
#define VMM_SUCCESS 0
#define VMM_ERROR_UNKNOWN ((void *)-1)
#define VMM_ERROR_INVALID_ARG ((void *)-2)

/**
 * Entry Point
 *
 * This typedef defines what an entry point is. All functions that are to
 * be called using the ELF loader should conform to this prototype.
 *
 * @param arg the argument you wish to pass to the entry point
 * @return the return value of the entry point
 */
typedef void *(*entry_point_t)(void *arg);

/**
 * VMM Resources
 *
 * When starting the Virtual Machine Monitor (VMM), different resources
 * need to be provided to the VMM so that it can make sense of the
 * environment provided to it by the driver entry (since the driver entry
 * could be coming from Windows, Linux, OSX or EFI). The driver entry
 * fills in this structure to provide this information to the VMM prior to
 * calling start_vmm
 */
struct vmm_resources_t
{
    struct debug_ring_resources *drr;
};

/**
 * Start VMM
 *
 * This is the prototype for the function that should be called by the driver
 * entry to start the VMM. It should be noted that the driver entry will be
 * starting C++ code, and thus, this entry point might not be usable if a
 * normal C compiler is being used that does not mangle the name properly.
 *
 * @param arg pointer to vmm_resources struct
 * @return VMM_SUCCESS on success, negative error code on failure
 */
void *
start_vmm(void *arg);

/**
 * Stop VMM
 *
 * This is the prototype for the function that should be called by the driver
 * entry to stop the VMM. It should be noted that the driver entry will be
 * starting C++ code, and thus, this entry point might not be usable if a
 * normal C compiler is being used that does not mangle the name properly.
 *
 * @param arg currently unused (set to 0)
 * @return VMM_SUCCESS on success, negative error code on failure
 */
void *
stop_vmm(void *arg);

#endif
