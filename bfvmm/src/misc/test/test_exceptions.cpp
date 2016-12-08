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
#include <exception.h>

void
misc_ut::test_exceptions()
{
    try { throw bfn::general_exception(); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::unknown_command_error(""); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::unknown_vmcall_type_error(""); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::unknown_vmcall_string_type_error(""); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::unknown_vmcall_data_type_error(""); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::missing_argument_error(); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::invalid_file_error(""); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::driver_inaccessible_error(); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::ioctl_failed_error(""); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::corrupt_vmm_error(); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::unknown_status_error(); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
    try { throw bfn::invalid_vmm_state_error(""); }
    catch (bfn::general_exception &e) { std::cout << e << '\n'; }
}
