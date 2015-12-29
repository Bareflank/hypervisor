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

#include <entry.h>
#include <memory.h>
#include <debug_ring_interface.h>

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

class Blah1
{
public:
    Blah1() {}
    virtual ~Blah1() {}

    virtual int foo() { return 0; }
};

class Blah2 : public Blah1
{
public:
    Blah2() {}
    ~Blah2() {}

    int boo()
    { return 1; }

    int foo() override
    { return 1; }
};

Blah2 g_blah2;

Blah2 *
static_blah()
{
    static Blah2 my_blah;
    return &my_blah;
}

int
dummy3_test2(int num)
{
    Blah2 &r_blah2 = g_blah2;
    l_my_glob1 = r_blah2.foo();

    // Foo does not crash. This is the pattern we have been using for
    // everything as it seems to be stable.
    static_blah()->foo();

    // Foo does crash. Still don't know why, but this repros in the kernel
    // as well so don't do it. Oh.... and if you notice, I do the same thing
    // above, just not with -> and it works fine. I also do it with a staticly
    // defined memory and it works fine.
    // Blah2 *p_blah2 = &g_blah2;
    // p_blah2->foo();

    return l_my_glob1 +
           l_my_glob2 +
           l_my_glob3 +
           dummy3_test1(num);
}

// The following functions are place holders for unit tests. Some of the
// unit tests expect these functions to exist somewhere, and so we provided
// them so that the unit tests can succeed.

extern "C" int
init_vmm(int arg)
{
    return ENTRY_SUCCESS;
}

extern "C" int
start_vmm(int arg)
{
    if (dummy3_test2(5) != 0x26)
        return ENTRY_ERROR_VMM_START_FAILED;

    return ENTRY_SUCCESS;
}

extern "C" int
stop_vmm(int arg)
{
    return ENTRY_SUCCESS;
}

extern "C" long long int
add_page(struct page_t *pg)
{
    return MEMORY_MANAGER_SUCCESS;
}

extern "C" long long int
remove_page(struct page_t *pg)
{
    return MEMORY_MANAGER_SUCCESS;
}

extern "C" struct debug_ring_resources_t *
get_drr(long long int vcpuid)
{
    static debug_ring_resources_t drr = {0};

    if (vcpuid >= 1)
        return 0;

    return &drr;
}

extern "C" int
sym_that_returns_success(int arg)
{
    return ENTRY_SUCCESS;
}

extern "C" int
sym_that_returns_failure(int arg)
{
    return ENTRY_ERROR_VMM_START_FAILED;
}

void
operator delete(void *ptr)
{
}

void
operator delete[](void *p)
{
}

extern "C" void
__cxa_pure_virtual()
{
}

extern "C" int
atexit(void (*func)(void))
{
    return 0;
}

