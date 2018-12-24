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

#ifndef IDT_X64_H
#define IDT_X64_H

#pragma pack(push, 1)

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" void _read_idt(void *idt_reg) noexcept;
extern "C" void _write_idt(void *idt_reg) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace idt_reg
{

struct reg_t {
    uint16_t limit{0};
    uint64_t base{0};
};

inline auto get() noexcept
{
    reg_t reg;
    _read_idt(&reg);

    return reg;
}

inline void set(uint64_t base, uint16_t limit) noexcept
{
    reg_t reg;

    reg.base = base;
    reg.limit = limit;

    _write_idt(&reg);
}

namespace base
{
    inline auto get() noexcept
    {
        reg_t reg;
        _read_idt(&reg);

        return reg.base;
    }

    inline void set(uint64_t base) noexcept
    {
        reg_t reg;
        _read_idt(&reg);

        reg.base = base;
        _write_idt(&reg);
    }
}

namespace limit
{
    inline auto get() noexcept
    {
        reg_t reg;
        _read_idt(&reg);

        return reg.limit;
    }

    inline void set(uint16_t limit) noexcept
    {
        reg_t reg;
        _read_idt(&reg);

        reg.limit = limit;
        _write_idt(&reg);
    }
}

}
}

// *INDENT-ON*

#pragma pack(pop)

#endif
