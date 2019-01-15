//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <bfgsl.h>

#include <map>
#include <debug/debug_ring/debug_ring.h>

// -----------------------------------------------------------------------------
// Mutex
// -----------------------------------------------------------------------------

#include <mutex>
std::mutex g_debug_mutex;

// -----------------------------------------------------------------------------
// Global
// -----------------------------------------------------------------------------

static auto &
drr_map() noexcept
{
    static std::map<vcpuid::type, debug_ring_resources_t *> g_drrs;
    return g_drrs;
}

extern "C" int64_t
get_drr(uint64_t vcpuid, struct debug_ring_resources_t **drr) noexcept
{
    if (drr == nullptr) {
        return GET_DRR_FAILURE;
    }

    if (auto found_drr = drr_map()[vcpuid]) {
        *drr = found_drr;
        return GET_DRR_SUCCESS;
    }

    return GET_DRR_FAILURE;
}

// -----------------------------------------------------------------------------
// Debug Ring Implementation
// -----------------------------------------------------------------------------

namespace bfvmm
{

debug_ring::debug_ring(vcpuid::type vcpuid) noexcept
{
    m_vcpuid = vcpuid;
    m_drr = std::make_unique<debug_ring_resources_t>();

    m_drr->epos = 0;
    m_drr->spos = 0;
    m_drr->tag1 = 0xDB60DB60DB60DB60;
    m_drr->tag2 = 0x06BD06BD06BD06BD;

    std::lock_guard<std::mutex> guard(g_debug_mutex);
    drr_map()[vcpuid] = m_drr.get();
}

debug_ring::~debug_ring() noexcept
{
    std::lock_guard<std::mutex> guard(g_debug_mutex);
    drr_map().erase(m_vcpuid);
}

void
debug_ring::write(const std::string &str) noexcept
{
    // TODO: A more interesting implementation would use an optimized
    //       memcpy to implement this code. Doing so would increase it's
    //       performance, but would require some better math, and an
    //       optimized memcpy that used both rep string instructions and
    //       SIMD instructions

    if (!m_drr || str.empty() || str.length() >= DEBUG_RING_SIZE) {
        return;
    }

    // The length that we were given is equivalent to strlen, which does not
    // include the '\0', so we add one to the length to account for that.
    auto len = str.length() + 1;

    auto epos = m_drr->epos & (DEBUG_RING_SIZE - 1);
    auto cpos = m_drr->spos & (DEBUG_RING_SIZE - 1);
    auto space = DEBUG_RING_SIZE - (m_drr->epos - m_drr->spos);

    if (space < len) {

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

        while (space <= DEBUG_RING_SIZE) {
            if (cpos >= DEBUG_RING_SIZE) {
                cpos = 0;
            }

            space++;
            m_drr->spos++;

            if (gsl::at(m_drr->buf, static_cast<std::ptrdiff_t>(cpos)) == '\0' && space >= len) {
                break;
            }

            gsl::at(m_drr->buf, static_cast<std::ptrdiff_t>(cpos++)) = '\0';
        }
    }

    for (auto i = 0U; i < len; i++) {
        if (epos >= DEBUG_RING_SIZE) {
            epos = 0;
        }

        gsl::at(m_drr->buf, static_cast<std::ptrdiff_t>(epos)) = str[i];

        epos++;
        m_drr->epos++;
    }
}

}
