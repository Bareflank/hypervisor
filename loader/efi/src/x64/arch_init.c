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

#include <setup_cr0.h>
#include <setup_cr4.h>
#include <setup_tss.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Sets up the CPU above and beyond what UEFI has provided.
 *
 * <!-- inputs/outputs -->
 *   @return Returns 0 on success, LOADER_FAILURE otherwise
 */
int64_t
arch_init(void)
{
    /**
     * TODO:
     * - The arch_init() logic needs an additional function to enable as many
     *   hardward security features as possible. For example, SMEP/SMAP. Right
     *   now all it does is ensure that CR0/CR4 are configured to support
     *   virtualization. The values that UEFI sets up however are what the
     *   microkernel will inherit and use so the UEFI loader needs to turn as
     *   many of these features on as possible so that the microkernel can
     *   use them. Once virtualization is started, the root OS can configure
     *   itself however it wants, which will not affect the microkernel unless
     *   the feature is outside of the control of the VMCS/VMCB, in which
     *   case it will be up to the extension to deal with.
     */

    setup_cr0();
    setup_cr4();

    return setup_tss();
}
