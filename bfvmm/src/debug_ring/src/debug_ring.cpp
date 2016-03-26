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

#include <debug_ring/debug_ring.h>
#include <debug_ring/debug_ring_exceptions.h>

// -----------------------------------------------------------------------------
// Global
// -----------------------------------------------------------------------------

extern "C" struct debug_ring_resources_t *
get_drr(int64_t vcpuid)
{
    static debug_ring_resources_t drrs[MAX_VCPUS] = {};

    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        return 0;

    return &drrs[vcpuid];
}

// -----------------------------------------------------------------------------
// Debug Ring Implementation
// -----------------------------------------------------------------------------

debug_ring::debug_ring(int64_t vcpuid) :
    m_drr(0)
{
    if (vcpuid < 0 || vcpuid >= MAX_VCPUS)
        return;

    m_drr = get_drr(vcpuid);

    m_drr->epos = 0;
    m_drr->spos = 0;

    for (auto i = 0U; i < DEBUG_RING_SIZE; i++)
        m_drr->buf[i] = '\0';
}

void
debug_ring::write(const std::string &str)
{
    // TODO: A more interesting implementation would use an optimized
    //       memcpy to implement this code. Doing so would increase it's
    //       performance, but would require some better math, and an
    //       optimized memcpy that used both rep string instructions and
    //       SIMD instructions

    if (m_drr == NULL)
        throw invalid_debug_ring();

    if (str.length() >= DEBUG_RING_SIZE)
        throw std::invalid_argument("str.length() >= DEBUG_RING_SIZE");

    if (str.length() == 0)
        return;

    // The length that we were given is equivalent to strlen, which does not
    // include the '\0', so we add one to the length to account for that.
    auto len = str.length() + 1;

    auto epos = m_drr->epos % DEBUG_RING_SIZE;
    auto spos = m_drr->spos % DEBUG_RING_SIZE;
    auto space = DEBUG_RING_SIZE - (m_drr->epos - m_drr->spos);

    if (space < len)
    {
        auto cpos = spos;

        // Make room for the write. Normally, with a circular buffer, you
        // would just move the start position when a read occurs, but in this
        // case, the vmm needs to be able to write as it wishes to the buffer.
        // If we just move the start position based on the amount of space we
        // need, you would end up with the first string being cropped once
        // the ring wraps. The following code makes sure that we are making
        // room by removing complete strings.
        //
        // Note: There is still a race condition with this code. If the reader
        //       reads at the same time we are writing, you could end up with
        //       a cropped string for the first string, but that's fine, as
        //       this is just debug text, and if we add locks, we would
        //       greatly increase the complexity of this code, while
        //       serializing the code, which is not a good idea.
        while (space <= DEBUG_RING_SIZE)
        {
            if (cpos >= DEBUG_RING_SIZE)
                cpos = 0;

            if (spos >= DEBUG_RING_SIZE)
                spos = 0;

            spos++;
            space++;
            m_drr->spos++;

            if (m_drr->buf[cpos] == '\0' &&
                space >= len)
            {
                break;
            }

            m_drr->buf[cpos++] = '\0';
        }
    }

    for (auto i = 0U; i < len; i++)
    {
        if (epos >= DEBUG_RING_SIZE)
            epos = 0;

        m_drr->buf[epos] = str[i];

        epos++;
        m_drr->epos++;
    }
}
