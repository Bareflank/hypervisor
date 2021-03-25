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

#include <debug.h>
#include <types.h>
#include <work_on_cpu_callback_args.h>

/**
 * <!-- description -->
 *   @brief This function is called when the user calls platform_on_each_cpu.
 *     On each iteration of the CPU, this function calls the user provided
 *     callback with the signature that we perfer.
 *
 * <!-- inputs/outputs -->
 *   @param ProcedureArgument stores the params needed to execute the callback
 */
static void
work_on_cpu_callback(void *const ProcedureArgument)
{
    struct work_on_cpu_callback_args *args =
        ((struct work_on_cpu_callback_args *)ProcedureArgument);

    args->ret = args->func(args->cpu);
}

/**
 * <!-- description -->
 *   @brief Executes a callback on a specific core on this architecture.
 *
 * <!-- inputs/outputs -->
 *   @param cpu the core to execute the callback on
 *   @param callback the callback to call
 *   @param args the arguments for work_on_cpu_callback
 */
void
arch_work_on_cpu(
    uint32_t const cpu, void *const callback, struct work_on_cpu_callback_args *const args)
{
    /**
     * NOTE:
     * - ARMv8 doesn't support INIT/SIPI, and MP services do not seem to be
     *   implemented in UEFI yet. ServerReady systems will almost certainly
     *   need some form of MP services (using ACPI maybe?) so this is likely
     *   a temporary problem.
     * - Unlike x86, ARMv8 starts all of the cores all at the same time, and
     *   it leaves the process of how to bootstrap each core to the firmware.
     *   This means that right now, there is no standard way to start up
     *   each core. On the Raspberry Pi 4, when each core starts, they check
     *   their processor ID. If it is zero, it boots. If it is not zero, it
     *   enters an endless loop, waiting for a memory location to be written
     *   to. The OS is supposed to write the address of a function it wishes to
     *   be executed to memory locations specific to each core that the core
     *   is waiting on. It will then jump to this address and continue to
     *   bootstrap using whatever logic you provide. This will work for now,
     *   but adding more devices will likely require device specific logic
     *   here until MP services, or something else like it is ready.
     * - The lack of decent standardization on ARM is hands down the biggest
     *   issue with the CPU. Hopefully the ServerReady specs fix this.
     */

    if (cpu == 0U) {
        args->ret = args->func(args->cpu);
    }
    else {
        /**
         * TODO:
         * - Complete
         */
    }
}
