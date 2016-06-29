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

#ifndef ERROR_CODES_H
#define ERROR_CODES_H

#define sign(a) ((int64_t)(a))

/**
 * Success
 */
#define SUCCESS 0

/**
 * Entry Error Codes
 */
#define ENTRY_SUCCESS sign(SUCCESS)
#define ENTRY_ERROR_STACK_OVERFLOW sign(0x8000000000000010)
#define ENTRY_ERROR_VMM_INIT_FAILED sign(0x8000000000000020)
#define ENTRY_ERROR_VMM_START_FAILED sign(0x8000000000000030)
#define ENTRY_ERROR_VMM_STOP_FAILED sign(0x8000000000000040)
#define ENTRY_ERROR_UNKNOWN sign(0x8000000000000050)

/**
 * CRT Error Codes
 */
#define CRT_SUCCESS sign(SUCCESS)
#define CRT_FAILURE sign(0x8000000000000100)

/**
 * Register EH Frame Error Codes
 */
#define REGISTER_EH_FRAME_SUCCESS sign(SUCCESS)
#define REGISTER_EH_FRAME_FAILURE sign(0x8000000000001000)

/**
 * Debug Ring Error Codes
 */
#define GET_DRR_SUCCESS sign(SUCCESS)
#define GET_DRR_FAILURE sign(0x8000000000010000)

#endif
