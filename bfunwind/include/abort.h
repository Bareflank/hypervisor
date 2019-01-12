//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
