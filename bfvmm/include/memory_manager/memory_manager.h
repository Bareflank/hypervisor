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

    /// Get Singleton Instance
    ///
    /// @return an instance to this singleton class
    ///
    static memory_manager *instance();

    /// Memory Manager Destructor
    ///
    ~memory_manager() {}

    /// Init Memory Manager
    ///
    /// Initializes the memory manager.
    ///
    /// @return succss on success, failure otherwise
    ///
    memory_manager_error::type init();

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
    memory_manager_error::type add_page(page &pg);

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
    memory_manager_error::type alloc_page(page *pg);

    /// Free Page
    ///
    /// Frees a page that has been previously allocated. Once a page is free
    /// it can be allocated again (i.e. discontinue use of a page once it has
    /// been freed)
    ///
    /// @param pg page to free
    ///
    void free_page(page &pg);

private:

    /// Private Memory Manager Constructor
    ///
    /// Since this is a singleton class, the constructor should not be used
    /// directly. Instead, use instance()
    ///
    memory_manager() {}

public:

    /// Copy Constructor
    ///
    /// Explicity deleted as copying this class is forbidden
    ///
    memory_manager(const memory_manager &) = delete;

    /// Equality Operator
    ///
    /// Explicity deleted as copying this class is forbidden
    ///
    void operator=(const memory_manager &) = delete;

private:

    page m_pages[MAX_PAGES];
};

#endif
