//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <dummy1.h>
#include <dummy2.h>
#include <dummy3.h>

#include <vmm_entry.h>

int g_my_glob1;
int g_my_glob2 = 0;
int g_my_glob3 = 3;

static int l_my_glob1;
static int l_my_glob2 = 0;
static int l_my_glob3 = 3;

int x[2], *y = x + 1;

void *
dummy2_func_pointer(void *arg);

int
dummy3_test1(int num)
{
    g_my_glob1 = 1;

    dummy2 _dummy2;
    void *p = (void *)dummy2_func_pointer;

    x[0] = 1;
    x[1] = 2;

    if (p != 0)
    {
        return g_my_glob1 +
               g_my_glob2 +
               g_my_glob3 +
               *y +
               dummy1_add1(num) +
               dummy2::dummy2_add2(num) +
               dummy1_mul1(num) +
               _dummy2.dummy2_mul2(num);
    }
    else
    {
        return 0;
    }
}

class A
{
public:
    A() {}
    virtual ~A() {}
};

class B : public A
{
public:
    B() : i(1) {}
    ~B() {}

    void init() {i = 1;}

    decltype(auto) get_i() { return i; }
private:
    int i;
};

B b;

int
dummy3_test2(int num)
{
    b.init();
    l_my_glob1 = b.get_i();

    return l_my_glob1 +
           l_my_glob2 +
           l_my_glob3 +
           dummy3_test1(num);
}

void *
start_vmm(void *arg)
{
    if (arg == 0)
        return VMM_ERROR_INVALID_ARG;

    if (dummy3_test2(5) != 0x26)
        return VMM_ERROR_UNKNOWN;

    return 0;
}

void *
stop_vmm(void *arg)
{
    if (arg != 0)
        return VMM_ERROR_INVALID_ARG;

    return 0;
}

void operator delete(void *ptr)
{
}

void operator delete[](void *p)
{
}

extern "C"
{
    void __cxa_pure_virtual()
    {
    }
}
