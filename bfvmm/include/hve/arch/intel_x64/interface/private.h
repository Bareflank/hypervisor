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

// Note:
//
// This file defines private portions of the interfaces. The interfaces
// defined in this file are subject to change and should not be used by
// extensions. You have been warned.
//

#include "types.h"
#include <bfgsl.h>

#ifdef ENABLE_BUILD_TEST
#include <hippomocks.h>
#define PRIVATE_INTERFACES(name)                                                \
    \
    private:                                                                    \
    \
    IMPL m_impl;                                                            \
    \
    public:                                                                     \
    \
    name(name &&) = default;                                                \
    name &operator=(name &&) = default;                                     \
    \
    name(const name &) = delete;                                            \
    name &operator=(const name &) = delete;                                 \
    \
    public:                                                                     \
    \
    static void name ## _mock(                                              \
            MockRepository &mocks, gsl::not_null<vcpu *> vcpu)                  \
    { IMPL::mock(mocks, vcpu); }                                            \
    \
    gsl::not_null<IMPL *> name ## _impl()                                   \
    { return &m_impl; }

#else
#define PRIVATE_INTERFACES(name)                                                \
    \
    private:                                                                    \
    \
    IMPL m_impl;                                                            \
    \
    public:                                                                     \
    \
    name(name &&) = default;                                                \
    name &operator=(name &&) = default;                                     \
    \
    name(const name &) = delete;                                            \
    name &operator=(const name &) = delete;

#endif
