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

#ifndef COMMON_H
#define COMMON_H

#include <types.h>
#include <error_codes.h>
#include <bfelf_loader.h>
#include <debug_ring_interface.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Module                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * This structure defines the properties that make up a module. Specifically,
 * a module is made up of the ELF file that stores all of the information
 * assocaited with the module as well as the execution buffer and size where
 * the module will be loaded to, and execute from.
 *
 * @var module_t::exec
 *     the buffer that the module is executed from
 * @var module_t::size
 *     the size of the execution buffer
 * @var module_t::file
 *     the ELF file that has all of the information about the module
 */
struct module_t
{
    char *exec;
    uint64_t size;
    struct bfelf_file_t file;
};

/* -------------------------------------------------------------------------- */
/* Common Functions                                                           */
/* -------------------------------------------------------------------------- */

/**
 * VMM Status
 *
 * @return returns the current status of the VMM.
 */
int64_t
common_vmm_status(void);

/**
 * Reset
 *
 * This function should not be called directly. Instead, use common_unload.
 * This is only exposed publically for unit testing.
 *
 * @return will always return BF_SUCCESS
 */
int64_t
common_reset(void);

/**
 * Initialize Driver Entry
 *
 * This code should be run as part of the driver entry's init code. This
 * sets up some resources that are needed throughout the lifetime of the
 * driver entry.
 *
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_init(void);

/**
 * Finalize Driver Entry
 *
 * This code should be run as part of the driver entry's fini code. This
 * cleans up some resources that were needed throughout the lifetime of the
 * driver entry.
 *
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_fini(void);

/**
 * Add Module
 *
 * Add's a module into memory to be executed once start_vmm is run. This
 * function uses the platform functions to allocate memory for the executable.
 * The file that is provided should not be removed until after stop_vmm is
 * run. Removing the file from memory could cause a crash, as the start_vmm
 * function uses the file that is being added to search for symbols that are
 * needed, as well as the stop_vmm function. Once stop_vmm is run, it's safe
 * to remove the files. Also, this function cannot be run if the vmm has
 * already been started.
 *
 * @param file the file to add to memory
 * @param fsize the size of the file in bytes
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_add_module(const char *file, uint64_t fsize);

/**
 * Load VMM
 *
 * This function loads the vmm (assuming that the modules that were
 * loaded are actually a vmm). Once a VMM is loaded, it is placed in memory,
 * and all of the modules are properly reloacted such that, code within each
 * module is now capable of executing.
 *
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_load_vmm(void);

/**
 * Unload VMM
 *
 * This function unloads the vmm. Once the VMM is unloaded, all of the symbols
 * for the VMM are removed from memory, and are no longer accessible. The VMM
 * cannot be unloaded unless the VMM is already loaded, but is not running.
 *
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_unload_vmm(void);

/**
 * Start VMM
 *
 * This function starts the vmm. Before the VMM can be started, it must first
 * be loaded.
 *
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_start_vmm(void);

/**
 * Stop VMM
 *
 * This function stops the vmm. Before a VMM can be stopped, it must first be
 * loaded, and running.
 *
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_stop_vmm(void);

/**
 * Dump VMM
 *
 * This grabs the conents of the debug ring, and dumps the contents to the
 * driver entry's console. This is one of a couple of ways to get feedback
 * from the VMM. Note that the VMM must at least be loaded for this function
 * to work as it has to do a symbol lookup
 *
 * @param drr a pointer to the drr provided by the user
 * @param vcpuid indicates which drr to get as each vcpu has its own drr
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_dump_vmm(struct debug_ring_resources_t **drr, uint64_t vcpuid);

#ifdef __cplusplus
}
#endif

#endif
