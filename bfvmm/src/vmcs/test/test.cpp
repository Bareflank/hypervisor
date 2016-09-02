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

#include <test.h>

size_t g_new_throws_bad_alloc = 0;

static void *
malloc_aligned(std::size_t size)
{
    int ret = 0;
    void *ptr = nullptr;

    ret = posix_memalign(&ptr, MAX_PAGE_SIZE, size);
    (void) ret;

    return ptr;
}

static void *
custom_new(std::size_t size)
{
    if (size == g_new_throws_bad_alloc)
        throw std::bad_alloc();

    if ((size & (MAX_PAGE_SIZE - 1)) == 0)
        return malloc_aligned(size);

    return malloc(size);
}

static void
custom_delete(void *ptr)
{
    free(ptr);
}

void *
operator new[](std::size_t size)
{
    return custom_new(size);
}

void *
operator new(std::size_t size)
{
    return custom_new(size);
}

void
operator delete(void *ptr, std::size_t /* size */) throw()
{
    custom_delete(ptr);
}

void
operator delete(void *ptr) throw()
{
    custom_delete(ptr);
}

void
operator delete[](void *ptr) throw()
{
    custom_delete(ptr);
}

void
operator delete[](void *ptr, std::size_t /* size */) throw()
{
    custom_delete(ptr);
}

vmcs_ut::vmcs_ut()
{
    auto mem1 = new char;
    auto mem2 = new char[10];
    delete mem1;
    delete[] mem2;

    operator delete(nullptr);
    operator delete(nullptr, sizeof(char));
    operator delete[](nullptr);
    operator delete[](nullptr, sizeof(char));
}

bool
vmcs_ut::init()
{
    return true;
}

bool
vmcs_ut::fini()
{
    return true;
}

bool
vmcs_ut::list()
{
    this->test_constructor_null_intrinsics();
    this->test_launch_success();
    this->test_launch_vmlaunch_failure();
    this->test_launch_create_vmcs_region_failure();
    this->test_launch_create_exit_handler_stack_failure();
    this->test_launch_clear_failure();
    this->test_launch_load_failure();
    this->test_promote_failure();
    this->test_resume_failure();
    this->test_vmread_failure();
    this->test_vmwrite_failure();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(vmcs_ut);
}
