/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
