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

#include <crt.h>
#include <eh_frame_list.h>

typedef void (*ctor_t)();
typedef void (*dtor_t)();
typedef void (*init_array_t)();
typedef void (*fini_array_t)();

int64_t
local_init(struct section_info_t *info)
{
    if (info == nullptr)
        return CRT_FAILURE;

    try
    {
        if (info->ctors_addr != nullptr)
        {
            auto n = info->ctors_size >> 3;
            auto ctors = static_cast<ctor_t *>(info->ctors_addr);

            for (auto i = 0U; i < n && ctors[i] != nullptr; i++)
                ctors[i]();
        }

        if (info->init_array_addr != nullptr)
        {
            auto n = info->init_array_size >> 3;
            auto init_array = static_cast<init_array_t *>(info->init_array_addr);

            for (auto i = 0U; i < n && init_array[i] != nullptr; i++)
                init_array[i]();
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

int64_t
local_fini(struct section_info_t *info)
{
    if (info == nullptr)
        return CRT_FAILURE;

    try
    {
        if (info->fini_array_addr != nullptr)
        {
            auto n = info->fini_array_size >> 3;
            auto fini_array = static_cast<fini_array_t *>(info->fini_array_addr);

            for (auto i = 0U; i < n && fini_array[i] != nullptr; i++)
                fini_array[i]();
        }

        if (info->dtors_addr != nullptr)
        {
            auto n = info->dtors_size >> 3;
            auto dtors = static_cast<dtor_t *>(info->dtors_addr);

            for (auto i = 0U; i < n && dtors[i] != nullptr; i++)
                dtors[i]();
        }
    }
    catch (...)
    {
        return CRT_FAILURE;
    }

    return CRT_SUCCESS;
}
