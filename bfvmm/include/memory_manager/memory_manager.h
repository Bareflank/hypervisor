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

#ifndef MEMORY_MANAGER_H
#define MEMORY_MANAGER_H

#include <stdint.h>
#include <memory.h>
#include <memory_manager/page.h>

namespace memory_manager_error
{
    enum type
    {
        success = 0,
        failure = 1,
        out_of_memory = 2,
        full = 3,
        already_added = 4
    };
};

class memory_manager
{
public:

    /// Manager Constructor
    ///
    memory_manager();

    /// Destructor
    ///
    virtual ~memory_manager() {}

    /// Add Page to Memory Manager
    ///
    /// Adds a page to the memory mamanger. The page must be a valid page
    /// that has not already been added.
    ///
    /// @param pg valid page to add to the memory manager
    /// @return failure if the page is invalid, full if too many pages have
    ///     been added to the memory manager, already_added if the page has
    ///     already been added to the memory manager, and success on success
    ///
    virtual memory_manager_error::type add_page(page &pg);

    /// Allocate Page
    ///
    /// Allocates a page from the memory manage. Once a page has been
    /// allocated, it cannot be allocated again unless it has been freed.
    ///
    /// @param pg pointer to page to store the allocated page
    /// @return invalid if a NULL page is provide, out_of_memory if the
    ///     memory manager has run out of pages to allocate, success on
    ///     success
    ///
    virtual memory_manager_error::type alloc_page(page *pg);

    /// Free Page
    ///
    /// Frees a page that has been previously allocated. Once a page is free
    /// it can be allocated again (i.e. discontinue use of a page once it has
    /// been freed)
    ///
    /// @param pg page to free
    ///
    virtual void free_page(page &pg);

private:

    page m_pages[MAX_PAGES];
};

/// Get Memory Manager
///
/// We cannot use global memory since we don't have support for globally
/// constructor objects. Instead, we provide access to a globally defined
/// memory manager via a statically created global object with still provides
/// global access to a single memory manager, but allows the manager to be
/// properly constructed, and provides a simple means to test the class if
/// needed.
memory_manager *mm();

/// Add Page
///
/// Adds a page to the memory manager. This is a "C" function that can
/// be used by the driver entry point to provide the memory manager with a
/// page that it can manage.
///
/// @param pg the page to add to the memory manager
/// @return MEMORY_MANAGER_SUCCESS on success, MEMORY_MANAGER_FAILURE
///     otherwise
///
extern "C" long long int
add_page(struct page_t *pg);

/// Remove Page
///
/// Remove a page to the memory manager. This is a "C" function that can
/// be used by the driver entry point to remove a page from  the memory manager.
///
/// @param pg the page to remove from the memory manager
/// @return MEMORY_MANAGER_SUCCESS on success, MEMORY_MANAGER_FAILURE
///     otherwise
///
extern "C" long long int
remove_page(struct page_t *pg);

#endif
