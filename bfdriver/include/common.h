/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef COMMON_H
#define COMMON_H

#include <bftypes.h>
#include <bferrorcodes.h>
#include <bfelf_loader.h>
#include <bfdebugringinterface.h>

#ifdef __cplusplus
extern "C" {
#endif

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
 */
void
common_reset(void);

/**
 * Initialize Driver Entry
 *
 * This code should be run as part of the driver entry's init code. This
 * sets up some resources that are needed throughout the lifetime of the
 * driver entry.
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

/**
 * Call VMM
 *
 * Executes the VMM. The VMM has a single entry point, with a switch statement
 * that executes the provided "request". When this occurs, arg1 and arg2 are
 * provided to the requested function. Note that the first arg takes a cpuid,
 * which is the core number you are currently executing on. This is needed
 * because this function needs to set up the proper stack before executing
 * the VMM, and it needs to know which core you are on to use the proper stack
 * which in turn also executes with the proper TLS region.
 *
 * @param cpuid the core id this code is currently being executed on
 * @param request the requested function in the VMM to execute
 * @param arg1 arg #1
 * @param arg2 arg #2
 * @return BF_SUCCESS on success, negative error code on failure
 */
int64_t
common_call_vmm(uint64_t cpuid, uint64_t request, uintptr_t arg1, uintptr_t arg2);

#ifdef __cplusplus
}
#endif

#endif
