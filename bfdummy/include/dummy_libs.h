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

#ifndef DUMMY_LIBS_H
#define DUMMY_LIBS_H

#include <stddef.h>
#include <stdint.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/* @cond */

extern int global_var;

class base
{
public:
    base() noexcept = default;
    virtual ~base() = default;

    virtual int
    foo(int) noexcept
    {
        return 0;
    }
};

class derived1 : public base
{
public:
    derived1() noexcept;
    ~derived1() override;

    int
    foo(int arg) noexcept override;

private:
    int m_member{1000};
};

class derived2 : public base
{
public:
    derived2() noexcept;
    ~derived2() override;

    int
    foo(int arg) noexcept override;

private:
    int m_member{2000};
};

/* @endcond */

#endif
