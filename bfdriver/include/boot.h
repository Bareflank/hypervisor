/*
 * Bareflank Hypervisor
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef BF_BOOT_H
#define BF_BOOT_H

#include <bftypes.h>
#include <bfsupport.h>
#include <bferrorcodes.h>
#include <bfelf_loader.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int64_t boot_ret_t;
typedef boot_ret_t (*boot_fn_t)();

#define BOOT_FAIL             ( 0L )
#define BOOT_SUCCESS          ( 1L )

#define BOOT_CONTINUE         ( 1L << 1)
#define BOOT_INTERRUPT_STAGE  ( 2L << 1)
#define BOOT_ABORT            ( 3L << 1)
#define BOOT_NOT_FOUND        ( 4L << 1)

#ifndef NR_START_FNS
#define NR_START_FNS ( 8U )
#endif

extern struct platform_info_t boot_platform_info;

/**
 * boot_add_prestart_fn()
 *
 * Register a prestart function. A prestart function is run
 * in UEFI context, before VMX is enabled.
 *
 * @param fn the prestart function to add
 * @return boot_ret_t BOOT_SUCCESS on success
 */
boot_ret_t boot_add_prestart_fn(boot_fn_t fn);

/**
 * boot_set_start_fn()
 *
 * Register a start function. On success, the start function
 * will execute during boot_start and return with VMX enabled.
 *
 * @param fn the start function to execute during boot_start
 * @return boot_ret_t BOOT_SUCCESS on success
 */
boot_ret_t boot_set_start_fn(boot_fn_t fn);

/**
 * boot_add_poststart_fn()
 *
 * Register a poststart function. The poststart function runs
 * after the start_fn returns, and will execute in VMX-nonroot mode.
 *
 * @param fn the poststart function to add
 * @return boot_ret_t BOOT_SUCCESS on success
 */
boot_ret_t boot_add_poststart_fn(boot_fn_t fn);

/**
 * boot_start()
 *
 * Begin the boot process (prestart_fns->start_fn->poststart_fns)
 * Called by EFI entry point and unlikely to be needed by extension creator
 *
 * @return boot_ret_t BOOT_SUCCESS on success
 */
boot_ret_t boot_start();

#endif
