/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file bfdebug.h
 */

#ifndef BFDEBUGRINGINTERFACE_H
#define BFDEBUGRINGINTERFACE_H

#include <bftypes.h>
#include <bfdebug.h>
#include <bfconstants.h>
#include <bferrorcodes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get Debug Ring Resource Typedef
 *
 * @expects none
 * @ensures none
 *
 * This is used by the driver entry to as the function signature for
 * getting it's internal debug ring
 */
typedef struct debug_ring_resources_t *(*get_drr_t)(uint64_t vcpuid);

/**
 * @struct debug_ring_resources_t
 *
 * Debug Ring Resources
 *
 * Each driver entry needs to allocate some memory for the debug ring, and
 * then cast this structure over the allocated memory to access the bits used
 * by the ring.
 *
 * Prior to providing this structure to the debug ring, the memory should be
 * cleared, and the len of the buffer should be set to the total length of
 * memory allocated minus the size of debug_ring_resources_t.
 *
 * @code
 *
 *  int len = PAGE_SIZE * 100;
 *  struct debug_ring_resources_t *drr = valloc(len);
 *
 *  memset(drr, 0, len);
 *  drr->len = len - sizeof(debug_ring_resources_t);
 *
 *  <give to vmm and do stuff>
 *
 *  int ret;
 *  char read_buf[len]
 *
 *  ret = debug_ring_read(drr, read_buf, len);
 *  if(ret < 0)
 *      <report error>
 *
 * @endcode
 *
 * Note there are many different designs for cicular buffers, but all of the
 * designs have to face the same problem. How to detect when the buffer is
 * full vs when it is empty. This design uses two counters the grow
 * forever. The current position in the buffer is then pos % len. If the
 * counters are 64bit, it would take a life time for the counters to
 * overflow.
 *
 * @var debug_ring_resources_t::epos
 *     the end position in the circular buffer
 * @var debug_ring_resources_t::spos
 *     the start position in the circular buffer
 * @var debug_ring_resources_t::tag1
 *     used to identify the debug ring from a memory dump
 * @var debug_ring_resources_t::buf
 *     the circular buffer that stores the debug strings.
 * @var debug_ring_resources_t::tag2
 *     used to identify the debug ring from a memory dump
 */
struct debug_ring_resources_t {
    uint64_t epos;
    uint64_t spos;

    uint64_t tag1;
    char buf[DEBUG_RING_SIZE];
    uint64_t tag2;
};

/**
 * Debug Ring Read
 *
 * Reads strings that have been written to the debug ring. Although you can
 * provide any buffer size you want, it's advised to provide a buffer that
 * is the same size as the buffer that was originally allocated.
 *
 * @expects none
 * @ensures none
 *
 * @param drr the debug_ring_resource that was used to create the
 *        debug ring
 * @param str the buffer to read the string into. should be the same size
 *        as drr in bytes
 * @param len the length of the str buffer in bytes
 * @return the number of bytes read from the debug ring, 0
 *        on error
 */
static inline uint64_t
debug_ring_read(struct debug_ring_resources_t *drr, char *str, uint64_t len)
{
    uint64_t i;
    uint64_t spos;
    uint64_t count;
    uint64_t content;

    if (drr == 0 || str == 0 || len == 0) {
        return 0;
    }

    if (drr->spos > drr->epos) {
        return 0;
    }

    spos = drr->spos % DEBUG_RING_SIZE;
    content = drr->epos - drr->spos;

    for (i = 0, count = 0; i < content && i < len - 1; i++) {
        if (drr->buf[spos] != '\0') {
            str[count++] = drr->buf[spos];
        }

        spos = ((spos + 1) % DEBUG_RING_SIZE);
    }

    str[i] = '\0';
    return count;
}

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
