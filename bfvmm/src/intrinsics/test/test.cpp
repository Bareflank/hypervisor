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

intrinsics_ut::intrinsics_ut()
{
}

bool
intrinsics_ut::init()
{
    return true;
}

bool
intrinsics_ut::fini()
{
    return true;
}

bool
intrinsics_ut::list()
{
    this->test_gdt_constructor_no_size();
    this->test_gdt_constructor_zero_size();
    this->test_gdt_constructor_size();
    this->test_gdt_constructor_null_intrinsics();
    this->test_gdt_base();
    this->test_gdt_limit();
    this->test_gdt_set_base_zero_index();
    this->test_gdt_set_base_invalid_index();
    this->test_gdt_set_base_tss_at_end_of_gdt();
    this->test_gdt_set_base_descriptor_success();
    this->test_gdt_set_base_tss_success();
    this->test_gdt_base_zero_index();
    this->test_gdt_base_invalid_index();
    this->test_gdt_base_tss_at_end_of_gdt();
    this->test_gdt_base_descriptor_success();
    this->test_gdt_base_tss_success();
    this->test_gdt_set_limit_zero_index();
    this->test_gdt_set_limit_invalid_index();
    this->test_gdt_set_limit_descriptor_success();
    this->test_gdt_limit_zero_index();
    this->test_gdt_limit_invalid_index();
    this->test_gdt_limit_descriptor_success();
    this->test_gdt_limit_descriptor_in_bytes_success();
    this->test_gdt_set_access_rights_zero_index();
    this->test_gdt_set_access_rights_invalid_index();
    this->test_gdt_set_access_rights_descriptor_success();
    this->test_gdt_access_rights_zero_index();
    this->test_gdt_access_rights_invalid_index();
    this->test_gdt_access_rights_descriptor_success();

    this->test_idt_constructor_no_size();
    this->test_idt_constructor_zero_size();
    this->test_idt_constructor_size();
    this->test_idt_constructor_null_intrinsics();
    this->test_idt_base();
    this->test_idt_limit();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(intrinsics_ut);
}
