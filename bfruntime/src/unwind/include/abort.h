//
// Bareflank Unwind Library
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef ABORT_H
#define ABORT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" uint64_t
unsafe_write_cstr(const char *cstr, size_t len);

inline void
private_abort(const char *msg, const char *func)
{
    const char *str_txt1 = "\033[1;31mFATAL ERROR\033[0m [\033[1;33m";
    const char *str_txt2 = "\033[0m]: ";
    const char *str_endl = "\n"; \

    unsafe_write_cstr(str_txt1, strlen(str_txt1)); \
    unsafe_write_cstr(func, strlen(func)); \
    unsafe_write_cstr(str_txt2, strlen(str_txt2)); \
    unsafe_write_cstr(msg, strlen(msg)); \
    unsafe_write_cstr(str_endl, strlen(str_endl)); \

    abort();
}

#define ABORT(a) private_abort(a,__func__);

#endif
