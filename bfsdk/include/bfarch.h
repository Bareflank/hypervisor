/*
 * Bareflank Hypervisor
 * Copyright (C) 2017 Assured Information Security, Inc.
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

#ifndef BFARCH_H
#define BFARCH_H

#ifndef BF_ARCH

#if defined(_MSC_VER)
#   if defined(_M_X64)
#       define BF_ARCH "intel_x64"
#       define BF_X64
#       define BF_INTEL_X64
#   else
#       error "bfarch.h: unsupported architecture"
#   endif
#elif defined(__GNUC__) || defined(__clang__)
#   if defined(__x86_64__)
#       define BF_ARCH "intel_x64"
#       define BF_X64
#       define BF_INTEL_X64
#   elif defined(__aarch64__)
#       define BF_ARCH "aarch64"
#       define BF_AARCH64
#   else
#       error "bfarch.h: unsupported architecture"
#   endif
#else
#   error "bfarch.h: unsupported compiler"
#endif

#endif
#endif
