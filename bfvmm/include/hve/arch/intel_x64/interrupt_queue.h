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

#ifndef INTERRUPT_QUEUE_INTEL_X64_H
#define INTERRUPT_QUEUE_INTEL_X64_H

#include <queue>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

/// Interrupt Queue
///
/// Simple queue designed to work with external interrupts.
///
class interrupt_queue
{
public:

    using vector_t = uint64_t;              ///< Vector type

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    interrupt_queue() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~interrupt_queue() = default;

    /// Push
    ///
    /// Add an interrupt vector to the queue
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vector the vector number to add to the queue
    ///
    void push(vector_t vector);

    /// Pop
    ///
    /// Removes a vector from the queue, and returns it.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the removed vector or throws if the queue
    ///     is empty
    ///
    vector_t pop();

    /// Empty
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the removed vector or throws if the queue
    ///     is empty
    ///
    bool empty() const;

private:

    std::queue<uint64_t> m_vectors;

public:

    /// @cond

    interrupt_queue(interrupt_queue &&) = default;
    interrupt_queue &operator=(interrupt_queue &&) = default;

    interrupt_queue(const interrupt_queue &) = delete;
    interrupt_queue &operator=(const interrupt_queue &) = delete;

    /// @endcond
};

}

#endif
