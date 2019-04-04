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

#ifndef RDTSC_X64_H
#define RDTSC_X64_H

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" uint64_t _read_tsc(void) noexcept;
extern "C" uint64_t _read_tscp(void) noexcept;

// *INDENT-OFF*

namespace x64
{

namespace tsc
{
    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_tsc(); }
}

namespace tscp
{
    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_tscp(); }
}

}

// *INDENT-ON*

#endif
