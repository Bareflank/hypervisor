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
#include <bfconstants.h>

#include <vcpu/vcpu.h>

namespace bfvmm
{

vcpu::vcpu(vcpuid::type id) :
    m_id{id}
{
    if ((id & vcpuid::reserved) != 0) {
        throw std::invalid_argument("invalid vcpuid");
    }
}

void
vcpu::run(bfobject *obj)
{
    m_is_running = true;

    try {
        for (const auto &d : m_run_delegates) {
            d(obj);
        }
    }
    catch (...) {
        m_is_running = false;
        throw;
    }
}

void
vcpu::hlt(bfobject *obj)
{
    for (const auto &d : m_hlt_delegates) {
        d(obj);
    }

    m_is_running = false;
}

void
vcpu::init(bfobject *obj)
{
    m_is_initialized = true;

    try {
        for (const auto &d : m_init_delegates) {
            d(obj);
        }
    }
    catch (...) {
        m_is_initialized = false;
        throw;
    }
}

void
vcpu::fini(bfobject *obj)
{
    if (m_is_running) {
        this->hlt();
    }

    for (const auto &d : m_fini_delegates) {
        d(obj);
    }

    m_is_initialized = false;
}

}
