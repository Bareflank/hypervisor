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

#include <unistd.h>

#include <vcpu/vcpu_manager.h>
#include <serial/serial_port_intel_x64.h>

extern "C" int
write(int file, const void *buffer, size_t count)
{
    if (buffer == nullptr || count == 0)
        return 0;

    if (file != 1 && file != 2)
        return 0;

    try
    {
        std::string str(static_cast<const char *>(buffer), count);
        if (str.length() >= 26 && str.compare(0, 8, "$vcpuid=") == 0)
        {
            str.erase(0, 8);

            auto vcpuid_str = str.substr(0, 18);
            auto vcpuid_num = std::stoull(vcpuid_str, 0, 16);

            str.erase(0, 18);

            g_vcm->write(vcpuid_num, str);
            return static_cast<int>(count);
        }
        else
        {
            g_vcm->write(0, str);
            serial_port_intel_x64::instance()->write(str);
            return static_cast<int>(count);
        }
    }
    catch (...) { }

    return 0;
}
