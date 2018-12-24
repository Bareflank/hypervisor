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

#ifndef TSS_X64_H
#define TSS_X64_H

#include <cstdint>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::x64
{

#pragma pack(push, 1)

/* @cond */

struct tss {
    uint32_t reserved1{0};
    uint64_t rsp0{0};
    uint64_t rsp1{0};
    uint64_t rsp2{0};
    uint32_t reserved2{0};
    uint32_t reserved3{0};
    uint64_t ist1{0};
    uint64_t ist2{0};
    uint64_t ist3{0};
    uint64_t ist4{0};
    uint64_t ist5{0};
    uint64_t ist6{0};
    uint64_t ist7{0};
    uint32_t reserved4{0};
    uint32_t reserved5{0};
    uint16_t reserved6{0};
    uint16_t iomap{0};

    uint8_t pad[3992];
};

static_assert(sizeof(tss) == 0x1000, "TSS is not a page in size");

/* @endcond */

#pragma pack(pop)

}

#endif
