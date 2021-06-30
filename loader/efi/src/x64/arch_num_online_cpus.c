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
#include <efi/efi_mp_services_protocol.h>
#include <efi/efi_status.h>
#include <efi/efi_types.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Returns the total number of online CPUs on this architecture
 *     (i.e. PPs)
 *
 * <!-- inputs/outputs -->
 *   @return Returns the total number of online CPUs on this architecture
 *     (i.e. PPs)
 */
uint32_t
arch_num_online_cpus(void)
{
    EFI_STATUS status = EFI_SUCCESS;
    UINTN NumberOfProcessors;
    UINTN NumberOfEnabledProcessors;

    status = g_mp_services_protocol->GetNumberOfProcessors(
        g_mp_services_protocol, &NumberOfProcessors, &NumberOfEnabledProcessors);
    if (EFI_ERROR(status)) {
        bferror_x64("GetNumberOfProcessors failed", status);
        return ((uint32_t)0);
    }

    return (uint32_t)NumberOfProcessors;
}
