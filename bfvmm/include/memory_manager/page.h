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

#ifndef PAGE_H
#define PAGE_H

#include <stdint.h>

class page
{
public:

    /// Page Default Constructor
    ///
    /// Creates an empty, invalid page
    ///
    page();

    /// Valid Page Constructor
    ///
    /// If given the correct values, creates a valid page
    ///
    /// @param phys the physical address of the page
    /// @param virt the virtual address of the page
    /// @param size the size of the page in bytes
    ///
    page(void *phys, void *virt, uint64_t size);

    /// Page Destructor
    ///
    virtual ~page();

    /// Is Valid
    ///
    /// @return true if the page is valid, false otherwise. A valid page has
    ///     a physical address, virtual address, and non-zero size.
    ///
    virtual bool is_valid() const;

    /// Is Allocated
    ///
    /// @return true if the page is allocated, false otherwise
    ///
    virtual bool is_allocated() const;

    /// Allocate Page
    ///
    /// Changes the page's is_allocated() status to true
    ///
    virtual void allocate();

    /// Free Page
    ///
    /// Changes the page's is_allocated() status to false
    ///
    virtual void free();

    /// Physical Address
    ///
    /// @return the physical address of the page
    ///
    virtual void *phys_addr() const;

    /// Virtual Address
    ///
    /// @return the virtual address of the page
    ///
    virtual void *virt_addr() const;

    /// Page Size
    ///
    /// @return the size of the page in bytes
    ///
    virtual uint64_t size() const;

    /// Page Copy Constructor
    ///
    page(const page &other);

    /// Page Equal Operator
    ///
    void operator=(const page &other);

    /// Page Is Equal
    ///
    /// @return true if both pages have the same physical address, virtual
    ///     address and size. False otherwise. A page's allocated status is
    ///     ignored.
    bool operator==(const page &other);

    /// Page Is Not Equal
    ///
    /// @return false if both pages have the same physical address, virtual
    ///     address and size. True otherwise. A page's allocated status is
    ///     ignored.
    bool operator!=(const page &other);

private:

    void *m_phys;
    void *m_virt;
    uint64_t m_size;

    bool m_allocated;
};

#endif
