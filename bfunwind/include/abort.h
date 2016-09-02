//
// Bareflank Unwind Library
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifdef CROSS_COMPILED
extern "C" void abort(void);
extern "C" int printf(const char *format, ...);
extern "C" unsigned int write(int fd, const void *buf, unsigned int count);
#else
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#endif

inline void
private_abort(const char *msg, const char *func, int line)
{
    (void) msg;
    (void) func;
    (void) line;

#ifdef DISABLE_LOGGING
    auto ignored = write(1, "abort called in the unwinder", 28);
    (void) ignored;
#else
    printf("%s FATAL ERROR [%d]: %s\n", func, line, msg);
#endif

    abort();
}
#define ABORT(a) { private_abort(a,__func__,__LINE__); __builtin_unreachable(); }

#endif
