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


// uefi-related includes using gnu-efi

#ifndef BFEFI_H
#define BFEFI_H

#include <efi.h>
#include <efilib.h>
#include "extras.h"
#include "MpService.h"

#ifndef __GNUC__
#define __FILE__ __FILENAME__
#endif

#define PRINT_ERROR(status) \
    Print(L"\n %a: %d: returned status %r\n", __FILE__, __LINE__, status);

#endif
