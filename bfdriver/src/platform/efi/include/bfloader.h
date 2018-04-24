//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef HYP_LOADER_H
#define HYP_LOADER_H

#include "bfefi.h"

/**
 * EFI_HANDLE this_image_h
 *
 * Globally accessible handle to this image, passed in by firmware
 */
extern EFI_HANDLE this_image_h;

/**
 * EFI_MP_SERVICES_PROTOCOL *g_mp_services;
 *
 * Globally accessible pointer to EFI_MP_SERVICES_PROTOCOL interface
 */
extern EFI_MP_SERVICES_PROTOCOL *g_mp_services;

/**
 * Get keystroke
 *
 * Wait for keystroke from user
 *
 * @param key IN/OUT:
 * @return EFI_STATUS EFI_SUCCESS if successful
 */
EFI_STATUS console_get_keystroke(EFI_INPUT_KEY *key);

/**
 * Boot next image by order
 *
 * Boots the image after this one in BootOrder variable.  Not really necessary unless
 * we find firmware that doesn't do this automatically when this image returns EFI_NOT_FOUND
 *
 * @return EFI_STATUS Return status of next image.  Generally doesn't return.
 */
EFI_STATUS bf_boot_next_by_order();

/**
 * bf_start_by_startupallaps()
 *
 * Uses MP services protocol (StartupAllAPs) to launch hypervisor
 * on all cores
 *
 * @return EFI_STATUS EFI_SUCCESS on success
 */
EFI_STATUS bf_start_by_startupallaps();

#endif
