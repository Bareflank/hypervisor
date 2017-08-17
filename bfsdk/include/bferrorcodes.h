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

#ifndef BFERROR_CODES_H
#define BFERROR_CODES_H

#include <bftypes.h>

/* -------------------------------------------------------------------------- */
/* Success                                                                    */
/* -------------------------------------------------------------------------- */

#define SUCCESS 0

/* -------------------------------------------------------------------------- */
/* Entry Error Codes                                                          */
/* -------------------------------------------------------------------------- */

#define ENTRY_SUCCESS bfscast(int64_t, SUCCESS)
#define ENTRY_ERROR_STACK_OVERFLOW bfscast(int64_t, 0x8000000000000010)
#define ENTRY_ERROR_VMM_INIT_FAILED bfscast(int64_t, 0x8000000000000020)
#define ENTRY_ERROR_VMM_START_FAILED bfscast(int64_t, 0x8000000000000030)
#define ENTRY_ERROR_VMM_STOP_FAILED bfscast(int64_t, 0x8000000000000040)
#define ENTRY_ERROR_UNKNOWN bfscast(int64_t, 0x8000000000000050)

/* -------------------------------------------------------------------------- */
/* C Runtime Error Codes                                                      */
/* -------------------------------------------------------------------------- */

#define CRT_SUCCESS bfscast(int64_t, SUCCESS)
#define CRT_FAILURE bfscast(int64_t, 0x8000000000000100)

/* -------------------------------------------------------------------------- */
/* Unwinder Error Codes                                                       */
/* -------------------------------------------------------------------------- */

#define REGISTER_EH_FRAME_SUCCESS bfscast(int64_t, SUCCESS)
#define REGISTER_EH_FRAME_FAILURE bfscast(int64_t, 0x8000000000001000)

/* -------------------------------------------------------------------------- */
/* Debug Ring Error Codes                                                     */
/* -------------------------------------------------------------------------- */

#define GET_DRR_SUCCESS bfscast(int64_t, SUCCESS)
#define GET_DRR_FAILURE bfscast(int64_t, 0x8000000000010000)

/* -------------------------------------------------------------------------- */
/* ELF Loader Error Codes                                                     */
/* -------------------------------------------------------------------------- */

#define BFELF_SUCCESS bfscast(int64_t, SUCCESS)
#define BFELF_ERROR_INVALID_ARG bfscast(int64_t, 0x8000000000100000)
#define BFELF_ERROR_INVALID_FILE bfscast(int64_t, 0x8000000000200000)
#define BFELF_ERROR_INVALID_INDEX bfscast(int64_t, 0x8000000000300000)
#define BFELF_ERROR_INVALID_SIGNATURE bfscast(int64_t, 0x8000000000500000)
#define BFELF_ERROR_UNSUPPORTED_FILE bfscast(int64_t, 0x8000000000600000)
#define BFELF_ERROR_INVALID_SEGMENT bfscast(int64_t, 0x8000000000700000)
#define BFELF_ERROR_INVALID_SECTION bfscast(int64_t, 0x8000000000800000)
#define BFELF_ERROR_LOADER_FULL bfscast(int64_t, 0x8000000000900000)
#define BFELF_ERROR_NO_SUCH_SYMBOL bfscast(int64_t, 0x8000000000A00000)
#define BFELF_ERROR_MISMATCH bfscast(int64_t, 0x8000000000B00000)
#define BFELF_ERROR_UNSUPPORTED_RELA bfscast(int64_t, 0x8000000000C00000)
#define BFELF_ERROR_OUT_OF_ORDER bfscast(int64_t, 0x8000000000D00000)
#define BFELF_ERROR_OUT_OF_MEMORY bfscast(int64_t, 0x8000000000E00000)

/* -------------------------------------------------------------------------- */
/* Memory Manager Error Codes                                                 */
/* -------------------------------------------------------------------------- */

#define MEMORY_MANAGER_SUCCESS bfscast(int64_t, SUCCESS)
#define MEMORY_MANAGER_FAILURE bfscast(int64_t, 0x8000000001000000)

/* -------------------------------------------------------------------------- */
/* Common Error Codes                                                         */
/* -------------------------------------------------------------------------- */

#define BF_SUCCESS bfscast(int64_t, SUCCESS)
#define BF_ERROR_INVALID_ARG bfscast(int64_t, 0x8000000010000000)
#define BF_ERROR_INVALID_INDEX bfscast(int64_t, 0x8000000020000000)
#define BF_ERROR_NO_MODULES_ADDED bfscast(int64_t, 0x8000000030000000)
#define BF_ERROR_MAX_MODULES_REACHED bfscast(int64_t, 0x8000000040000000)
#define BF_ERROR_VMM_INVALID_STATE bfscast(int64_t, 0x8000000050000000)
#define BF_ERROR_FAILED_TO_ADD_FILE bfscast(int64_t, 0x8000000060000000)
#define BF_ERROR_FAILED_TO_DUMP_DR bfscast(int64_t, 0x8000000070000000)
#define BF_ERROR_OUT_OF_MEMORY bfscast(int64_t, 0x8000000080000000)
#define BF_ERROR_VMM_CORRUPTED bfscast(int64_t, 0x8000000090000000)
#define BF_ERROR_UNKNOWN bfscast(int64_t, 0x80000000A0000000)

/* -------------------------------------------------------------------------- */
/* IOCTL Error Codes                                                          */
/* -------------------------------------------------------------------------- */

#define BF_IOCTL_SUCCESS bfscast(int64_t, SUCCESS)
#define BF_IOCTL_FAILURE bfscast(int64_t, -1)

/* -------------------------------------------------------------------------- */
/* Bad Alloc                                                                  */
/* -------------------------------------------------------------------------- */

#define BF_BAD_ALLOC bfscast(int64_t, 0x8000000100000000)

/* -------------------------------------------------------------------------- */
/* VMCall                                                                     */
/* -------------------------------------------------------------------------- */

#define BF_VMCALL_SUCCESS bfscast(int64_t, SUCCESS)
#define BF_VMCALL_FAILURE bfscast(int64_t, 0x8000001000000000)

/* -------------------------------------------------------------------------- */
/* Stringify Error Codes                                                      */
/* -------------------------------------------------------------------------- */

static inline const char *
ec_to_str(int64_t value)
{
    switch (value) {
        case SUCCESS: return "SUCCESS";
        case ENTRY_ERROR_STACK_OVERFLOW: return "ENTRY_ERROR_STACK_OVERFLOW";
        case ENTRY_ERROR_VMM_INIT_FAILED: return "ENTRY_ERROR_VMM_INIT_FAILED";
        case ENTRY_ERROR_VMM_START_FAILED: return "ENTRY_ERROR_VMM_START_FAILED";
        case ENTRY_ERROR_VMM_STOP_FAILED: return "ENTRY_ERROR_VMM_STOP_FAILED";
        case ENTRY_ERROR_UNKNOWN: return "ENTRY_ERROR_UNKNOWN";
        case CRT_FAILURE: return "CRT_FAILURE";
        case REGISTER_EH_FRAME_FAILURE: return "REGISTER_EH_FRAME_FAILURE";
        case GET_DRR_FAILURE: return "GET_DRR_FAILURE";
        case MEMORY_MANAGER_FAILURE: return "MEMORY_MANAGER_FAILURE";
        case BFELF_ERROR_INVALID_ARG: return "BFELF_ERROR_INVALID_ARG";
        case BFELF_ERROR_INVALID_FILE: return "BFELF_ERROR_INVALID_FILE";
        case BFELF_ERROR_INVALID_INDEX: return "BFELF_ERROR_INVALID_INDEX";
        case BFELF_ERROR_INVALID_SIGNATURE: return "BFELF_ERROR_INVALID_SIGNATURE";
        case BFELF_ERROR_UNSUPPORTED_FILE: return "BFELF_ERROR_UNSUPPORTED_FILE";
        case BFELF_ERROR_INVALID_SEGMENT: return "BFELF_ERROR_INVALID_SEGMENT";
        case BFELF_ERROR_INVALID_SECTION: return "BFELF_ERROR_INVALID_SECTION";
        case BFELF_ERROR_LOADER_FULL: return "BFELF_ERROR_LOADER_FULL";
        case BFELF_ERROR_NO_SUCH_SYMBOL: return "BFELF_ERROR_NO_SUCH_SYMBOL";
        case BFELF_ERROR_MISMATCH: return "BFELF_ERROR_MISMATCH";
        case BFELF_ERROR_UNSUPPORTED_RELA: return "BFELF_ERROR_UNSUPPORTED_RELA";
        case BFELF_ERROR_OUT_OF_ORDER: return "BFELF_ERROR_OUT_OF_ORDER";
        case BFELF_ERROR_OUT_OF_MEMORY: return "BFELF_ERROR_OUT_OF_MEMORY";
        case BF_ERROR_INVALID_ARG: return "BF_ERROR_INVALID_ARG";
        case BF_ERROR_INVALID_INDEX: return "BF_ERROR_INVALID_INDEX";
        case BF_ERROR_NO_MODULES_ADDED: return "BF_ERROR_NO_MODULES_ADDED";
        case BF_ERROR_MAX_MODULES_REACHED: return "BF_ERROR_MAX_MODULES_REACHED";
        case BF_ERROR_VMM_INVALID_STATE: return "BF_ERROR_VMM_INVALID_STATE";
        case BF_ERROR_FAILED_TO_ADD_FILE: return "BF_ERROR_FAILED_TO_ADD_FILE";
        case BF_ERROR_FAILED_TO_DUMP_DR: return "BF_ERROR_FAILED_TO_DUMP_DR";
        case BF_ERROR_OUT_OF_MEMORY: return "BF_ERROR_OUT_OF_MEMORY";
        case BF_ERROR_VMM_CORRUPTED: return "BF_ERROR_VMM_CORRUPTED";
        case BF_ERROR_UNKNOWN: return "BF_ERROR_UNKNOWN";
        case BF_BAD_ALLOC: return "BF_BAD_ALLOC";
        case BF_IOCTL_FAILURE: return "BF_IOCTL_FAILURE";

        default:
            return "UNDEFINED_ERROR_CODE";
    }
}

#endif
