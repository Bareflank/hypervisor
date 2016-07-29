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

entry_ut::entry_ut()
{
}

bool
entry_ut::init()
{
    return true;
}

bool
entry_ut::fini()
{
    return true;
}

bool
entry_ut::list()
{
    this->test_start_vmm_success();
    this->test_start_vmm_throws_general_exception();
    this->test_start_vmm_throws_standard_exception();
    this->test_start_vmm_throws_any_exception();
    this->test_stop_vmm_success();
    this->test_stop_vmm_throws_general_exception();
    this->test_stop_vmm_throws_standard_exception();
    this->test_stop_vmm_throws_any_exception();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(entry_ut);
}
