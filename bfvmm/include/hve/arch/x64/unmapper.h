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

#ifndef UNMAPPER_X64_H
#define UNMAPPER_X64_H

#include <memory>
#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::x64
{

/// Unmapper
///
/// This class is used by the mapping functions to unmap previously mapped
/// memory. This unmapper adheres to the deleter concept for a
/// std::unique_ptr so that a std::unique_ptr can be used for mapping memory.
///
class unmapper
{
    uintptr_t m_hva{};
    std::size_t m_len{};

public:

    unmapper() = default;

    /// Constructor
    ///
    /// Create an unmapper that can unmap previous mapped memory
    ///
    /// @param hva the host virtual address to unmap
    /// @param len the length of the buffer that was previous mapped
    ///
    explicit unmapper(
        void *hva,
        std::size_t len
    ) :
        m_hva{reinterpret_cast<uintptr_t>(hva)},
        m_len{len}
    { }

    /// Unmap Functor
    ///
    /// @param p unused
    ///
    void operator()(void *p) const;
};

template<typename T>
using unique_map = std::unique_ptr<T, unmapper>;

}

#endif
