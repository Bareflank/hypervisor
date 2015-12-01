/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef DEBUG_RING_INTERFACE_H
#define DEBUG_RING_INTERFACE_H

/**
 * Returned by debug_ring_read on error
 */
#define DEBUG_RING_READ_ERROR -1

/**
 * Debug Ring Resources
 *
 * Each driver entry needs to allocate some memory for the debug ring, and
 * then cast this structure over the allocated memory to access the bits used
 * by the ring.
 *
 * Prior to providing this structure to the debug ring, the memory should be
 * cleared, and the len of the buffer should be set to the total length of
 * memory allocated minus the size of debug_ring_resources.
 *
 * @code
 *
 *  int len = PAGE_SIZE * 100;
 *  struct debug_ring_resources *drr = valloc(len);
 *
 *  memset(drr, 0, len);
 *  drr->len = len - sizeof(debug_ring_resources);
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
 * @len the length of the buffer (not the length of this struct)
 * @var epos the end position in the circular buffer
 * @var epos the start position in the circular buffer
 * @buf the circular buffer that stores the debug strings.
 */
struct debug_ring_resources
{
    long long int len;
    long long int epos;
    long long int spos;

    char buf[];
};

/**
 * Debug Ring Read
 *
 * Reads strings that have been written to the debug ring. Although you can
 * provide any buffer size you want, it's advised to provide a buffer that
 * is the same size as the buffer that was originally allocated.
 *
 * @param drr the debug_ring_resource that was used to create the
 *        debug ring
 * @param str the buffer to read the string into. should be the same size
 *        as drr in bytes
 * @param len the length of the str buffer in bytes
 * @return the number of bytes read from the debug ring, DEBUG_RING_READ_ERROR
 *        on error
 */
inline long long int
debug_ring_read(struct debug_ring_resources *drr, char *str, long long int len)
{
    long long int i;
    long long int spos;
    long long int content;

    if(drr == 0 || str == 0 || len == 0)
        return DEBUG_RING_READ_ERROR;

    spos = drr->spos % drr->len;
    content = drr->epos - drr->spos;

    for(i = 0; i < content && i < len; i++)
    {
        if(spos == drr->len)
            spos = 0;

        str[i] = drr->buf[spos++];
    }

    return content;
}

#endif
