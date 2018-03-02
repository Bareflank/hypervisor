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

#include <exit_handler/exit_handler_intel_x64_unittests.h>

#ifndef INCLUDE_LIBCXX_UNITTESTS

void
exit_handler_intel_x64::handle_vmcall_unittest(vmcall_registers_t &regs)
{ (void) regs; }

#else

void
exit_handler_intel_x64::handle_vmcall_unittest(vmcall_registers_t &regs)
{
    switch (regs.r02)
    {
        case 0x1001: unittest_1001_containers_array(); break;
        case 0x1002: unittest_1002_containers_vector(); break;
        case 0x1003: unittest_1003_containers_deque(); break;
        case 0x1004: unittest_1004_containers_forward_list(); break;
        case 0x1005: unittest_1005_containers_list(); break;
        case 0x1006: unittest_1006_containers_stack(); break;
        case 0x1007: unittest_1007_containers_queue(); break;
        case 0x1008: unittest_1008_containers_priority_queue(); break;
        case 0x1009: unittest_1009_containers_set(); break;
        case 0x100A: unittest_100A_containers_map(); break;

        case 0x1100: unittest_1100_io_cout(); break;
        case 0x1101: unittest_1101_io_manipulators(); break;

        default:
            throw std::runtime_error("unknown unit test #");
    }
}

#endif
