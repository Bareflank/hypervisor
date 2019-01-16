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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <hve/arch/x64/unmapper.h>
#include <memory_manager/arch/x64/cr3.h>

namespace bfvmm::x64
{

void
unmapper::operator()(void *p) const
{
    bfignored(p);
    using namespace ::x64::pt;

    /// Note:
    ///
    /// For now, we do not have a map_gva function that is above 4k, so we
    /// only need to loop with 4k granularity. All of the map_gpa functions
    /// only need to unmap once, so they will work as well. At some point,
    /// we should add a map_gva functions that is above 4k. When this is
    /// done, we will likely have to track the granularity so that we know
    /// what pages need to be unmapped specifically.
    ///

    for (auto hva = m_hva; hva < m_hva + m_len; hva += page_size) {
        g_cr3->unmap(hva);
        ::x64::tlb::invlpg(hva);
    }

    g_mm->free_map(reinterpret_cast<void *>(m_hva));
}

}
