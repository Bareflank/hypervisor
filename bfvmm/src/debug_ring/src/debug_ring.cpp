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

#include <gsl/gsl>

#include <map>
#include <debug_ring/debug_ring.h>

// -----------------------------------------------------------------------------
// Mutex
// -----------------------------------------------------------------------------

#include <mutex>
std::mutex g_debug_mutex;

// -----------------------------------------------------------------------------
// Global
// -----------------------------------------------------------------------------

std::map<uint64_t, debug_ring_resources_t *> g_drrs;

extern "C" int64_t
get_drr(uint64_t vcpuid, struct debug_ring_resources_t **drr) noexcept
{
    if (drr == nullptr)
        return GET_DRR_FAILURE;

    if (auto found_drr = g_drrs[vcpuid])
    {
        *drr = found_drr;
        return GET_DRR_SUCCESS;
    }

    return GET_DRR_FAILURE;
}

// -----------------------------------------------------------------------------
// Debug Ring Implementation
// -----------------------------------------------------------------------------

debug_ring::debug_ring(uint64_t vcpuid) noexcept
{
    try
    {
        m_vcpuid = vcpuid;
        m_drr = std::make_unique<debug_ring_resources_t>();

        m_drr->epos = 0;
        m_drr->spos = 0;
        m_drr->tag1 = 0xDB60DB60DB60DB60;
        m_drr->tag2 = 0x06BD06BD06BD06BD;

        std::lock_guard<std::mutex> guard(g_debug_mutex);
        g_drrs[vcpuid] = m_drr.get();
    }
    catch (...)
    { }
}

debug_ring::~debug_ring() noexcept
{
    std::lock_guard<std::mutex> guard(g_debug_mutex);
    g_drrs.erase(m_vcpuid);
}

void
debug_ring::write(const std::string &str) noexcept
{
    try
    {
        // TODO: A more interesting implementation would use an optimized
        //       memcpy to implement this code. Doing so would increase it's
        //       performance, but would require some better math, and an
        //       optimized memcpy that used both rep string instructions and
        //       SIMD instructions

        if (!m_drr)
            throw std::invalid_argument("m_drr == nullptr");

        if (str.length() == 0 || str.length() >= DEBUG_RING_SIZE)
            throw std::invalid_argument("invalid string length");

        // The length that we were given is equivalent to strlen, which does not
        // include the '\0', so we add one to the length to account for that.
        auto len = str.length() + 1;

        auto epos = m_drr->epos & (DEBUG_RING_SIZE - 1);
        auto cpos = m_drr->spos & (DEBUG_RING_SIZE - 1);
        auto space = DEBUG_RING_SIZE - (m_drr->epos - m_drr->spos);

        if (space < len)
        {
            // Make room for the write. Normally, with a circular buffer, you
            // would just move the start position when a read occurs, but in
            // this case, the vmm needs to be able to write as it wishes to the
            // buffer. If we just move the start position based on the amount
            // of space we need, you would end up with the first string being
            // cropped once the ring wraps. The following code makes sure that
            // we are making room by removing complete strings.
            //
            // Note: There is still a race condition with this code. If the
            //       reader reads at the same time we are writing, you could
            //       end up with a cropped string for the first string, but
            //       that's fine, as this is just debug text, and if we add
            //       locks, we would greatly increase the complexity of this
            //       code, while serializing the code, which is not a good idea.
            //
            while (space <= DEBUG_RING_SIZE)
            {
                if (cpos >= DEBUG_RING_SIZE)
                    cpos = 0;

                space++;
                m_drr->spos++;

                if (gsl::at(m_drr->buf, cpos) == '\0' && space >= len)
                    break;

                gsl::at(m_drr->buf, cpos++) = '\0';
            }
        }

        for (auto i = 0U; i < len; i++)
        {
            if (epos >= DEBUG_RING_SIZE)
                epos = 0;

            gsl::at(m_drr->buf, epos) = str[i];

            epos++;
            m_drr->epos++;
        }
    }
    catch (...) { }
}
