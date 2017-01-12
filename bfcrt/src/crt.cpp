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

#include <gsl/gsl>

#include <crt.h>
#include <eh_frame_list.h>

typedef void (*init_t)();
typedef void (*fini_t)();

extern "C" int64_t
local_init(struct section_info_t *info)
{
    if (info == nullptr)
        return CRT_FAILURE;

    try
    {
        if (info->init_addr != nullptr)
            reinterpret_cast<init_t>(info->init_addr)();

        if (info->init_array_addr != nullptr)
        {
            auto n = static_cast<std::ptrdiff_t>(info->init_array_size >> 3);
            auto init_array = gsl::make_span(static_cast<init_t *>(info->init_array_addr), n);

            for (auto i = 0U; i < n && init_array.at(i) != nullptr; i++)
                init_array.at(i)();
        }
    }
    catch (...)
    {
        return CRT_FAILURE;
    }

    auto ret = register_eh_frame(info->eh_frame_addr, info->eh_frame_size);
    if (ret != REGISTER_EH_FRAME_SUCCESS)
        return ret;

    return CRT_SUCCESS;
}

extern "C" int64_t
local_fini(struct section_info_t *info)
{
    if (info == nullptr)
        return CRT_FAILURE;

    try
    {
        if (info->fini_array_addr != nullptr)
        {
            auto n = static_cast<std::ptrdiff_t>(info->fini_array_size >> 3);
            auto fini_array = gsl::make_span(static_cast<fini_t *>(info->fini_array_addr), n);

            for (auto i = 0U; i < n && fini_array.at(i) != nullptr; i++)
                fini_array.at(i)();
        }

        if (info->fini_addr != nullptr)
            reinterpret_cast<fini_t>(info->fini_addr)();
    }
    catch (...)
    {
        return CRT_FAILURE;
    }

    return CRT_SUCCESS;
}
