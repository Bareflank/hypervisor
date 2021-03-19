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

#ifndef PLATFORM_ON_EACH_CPU_CALLBACK_ARGS_H
#define PLATFORM_ON_EACH_CPU_CALLBACK_ARGS_H

#include <platform.h>
#include <types.h>

/**
 * @struct work_on_cpu_callback_args
 *
 * <!-- description -->
 *   @brief Defines the args passed to the platform_on_each_cpu_callback
 *     function.
 */
struct work_on_cpu_callback_args
{
    /**
     * @brief The fucntion to call from platform_on_each_cpu_callback
     */
    platform_per_cpu_func func;

    /**
     * @brief The CPU platform_on_each_cpu_callback is called on
     */
    uint32_t cpu;

    /**
     * @brief Singals when the DPC is done.
     */
    uint32_t done;

    /**
     * @brief The return value of 'func'
     */
    int64_t ret;
};

#endif
