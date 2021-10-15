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

#ifndef CODE_ALIASES_T_H
#define CODE_ALIASES_T_H

#include <types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

    /**
     * <!-- description -->
     *   @brief Stores pointers to memory that is allocated for executable
     *     code that is compiled into the kernel, that must be mapped into the
     *     microkernel's root page tables. Some operating systems will not
     *     provide the physical address of a page that is mapped into the
     *     executable portion of a kernel module (e.g., Linux). To overcome this
     *     the executable code is copied into an alias page. When the function
     *     is executed using the kernel module's page tables, nothing changes, but
     *     when the code is executed from the microkernel's page tables, the
     *     pages stored here provide the page that stores the executable code
     *     instead, ensuring we have a means to get a physical address of a page
     *     that has the code we want.
     */
    struct code_aliases_t
    {
        /** @brief stores an alias page to the demote code */
        void *demote;
        /** @brief stores an alias page to the promote code */
        void *promote;
        /** @brief stores an alias page to the esr_default code */
        void *esr_default;
        /** @brief stores an alias page to the esr_df code */
        void *esr_df;
        /** @brief stores an alias page to the esr_gpf code */
        void *esr_gpf;
        /** @brief stores an alias page to the esr_nmi code */
        void *esr_nmi;
        /** @brief stores an alias page to the esr_pf code */
        void *esr_pf;
        /** @brief stores an alias page to the serial_write_c code */
        void *serial_write_c;
        /** @brief stores an alias page to the serial_write_hex code */
        void *serial_write_hex;
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
