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
