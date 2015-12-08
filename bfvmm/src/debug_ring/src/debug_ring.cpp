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

#include <assert.h>
#include <debug_ring/debug_ring.h>

debug_ring_error::type
debug_ring::init(struct debug_ring_resources *drr)
{
    m_is_valid = false;
    m_drr = drr;

    if (m_drr == 0)
        return debug_ring_error::invalid;

    if (m_drr->len <= 0)
        return debug_ring_error::invalid;

    m_drr->epos = 0;
    m_drr->spos = 0;

    for (auto i = 0; i < m_drr->len; i++)
        m_drr->buf[i] = '\0';

    m_is_valid = true;

    return debug_ring_error::success;
}

debug_ring_error::type
debug_ring::write(const char *str, int64_t len)
{
    // TODO: A more interesting implementation would use an optimized
    //       memcpy to implement this code. Doing so would increase it's
    //       performance, but would require some better math, and an
    //       optimized memcpy that used both rep string instructions and
    //       SIMD instructions

    if (m_is_valid == false)
        return debug_ring_error::invalid;

    if (str == 0 || len == 0 || len >= m_drr->len)
        return debug_ring_error::failure;

    len++;
    auto epos = m_drr->epos % m_drr->len;
    auto spos = m_drr->spos % m_drr->len;
    auto space = m_drr->len - (m_drr->epos - m_drr->spos);

    if (space < len)
    {
        auto pos = spos;

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
        while (space <= m_drr->len)
        {
            if (pos == m_drr->len)
                pos = 0;

            if (spos == m_drr->len)
                spos = 0;

            spos++;
            space++;
            m_drr->spos++;

            if (m_drr->buf[pos] == '\0' &&
                space >= len)
            {
                break;
            }

            m_drr->buf[pos++] = '\0';
        }
    }

    for (auto i = 0; i < len; i++)
    {
        if (epos == m_drr->len)
            epos = 0;

        m_drr->buf[epos] = str[i];

        epos++;
        m_drr->epos++;
    }

    return debug_ring_error::success;
}

debug_ring &debug_ring::instance()
{
    static debug_ring self;
    return self;
}
