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

#include <bfdebug.h>
#include <hve/arch/intel_x64/interrupt_queue.h>

namespace bfvmm::intel_x64
{

// For now, this is a simple first in, first out queue. In the future,
// we should implement the priority portion of the interrupt queue that
// the APIC is doing in hardware.
//
// It should be noted that the reason this works is that by the time
// the VMM sees the interrupt, the APIC has already released an interrupt
// with priority in mind, which means in theory, a simple queue is
// sufficient. Incomplete, but sufficient.

void
interrupt_queue::push(vector_t vector)
{ m_vectors.push(vector); }

interrupt_queue::vector_t
interrupt_queue::pop()
{
    auto vector = m_vectors.front();
    m_vectors.pop();

    return vector;
}

bool
interrupt_queue::empty() const
{ return m_vectors.empty(); }

}
