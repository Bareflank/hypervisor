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

#ifndef PROMOTE_H
#define PROMOTE_H

#include <mk_args_t.h>
#include <state_save_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief This promotes the OS by overwriting the state of the microkernel
 *     with the OS's state. This can be called when an error occurs during
 *     the initialization of the microkernel and it can also be called when
 *     the hypervisor is asked to stop.
 *
 * <!-- inputs/outputs -->
 *   @param mk_args_t the arguments that were passed to the microkernel
 *   @return LOADER_SUCCESS on success, LOADER_FAILURE on failure.
 */
int64_t promote(struct mk_args_t const *const args);

#endif
