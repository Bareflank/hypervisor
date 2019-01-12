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

#ifndef BFCALLONCE
#define BFCALLONCE

/// @cond

#include <mutex>

// TODO
//
// This code is only needed because there seems to be a bug with GCC that
// causes a system error when --coverage is enabled. The following was written
// to have the same names and implementation as std::call_once so that at
// some point this code can easily be removed.
//
namespace bfn
{

struct once_flag {
    bool m_value{false};
    mutable std::mutex m_mutex{};
};

template<typename FUNC>
void call_once(once_flag &flag, FUNC func)
{
    std::lock_guard<std::mutex> lock(flag.m_mutex);

    if (!flag.m_value) {
        func();
        flag.m_value = true;
    }
}

}

/// @endcond

#endif
