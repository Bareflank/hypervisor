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

///
/// @file bfbuffer.h
///

#ifndef BFBUFFER_H
#define BFBUFFER_H

#include <bfgsl.h>
#include <bfdebug.h>

namespace bfn
{

/// Buffer
///
/// Simple character buffer class that stores both a buffer and its size.
/// This class is a hybrid between std::array, and std::unique_ptr. It's
/// dynamic, doesn't have support for iterators or random memory access,
/// and cannot be copied.
///
class buffer
{
public:

    using size_type = std::size_t;      ///< Size type of buffer
    using data_type = char;             ///< Data type of buffer

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    buffer() = default;

    /// Allocate Buffer Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param size the size of the buffer to allocate
    ///
    /// @throws std::bad_alloc if this constructor is unable to allocate memory for the buffer
    ///
    buffer(size_type size) :
        m_size(size),
        m_data(std::make_unique<data_type[]>(m_size))
    {
        expects(size != 0);
    }

    /// Pre-Allocated Buffer Constructor
    ///
    /// @note Takes ownership of data, and frees the provided buffer when the
    ///     buffer goes out of scope
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param data a pointer to the buffer to store.
    /// @param size the size of the provided buffer
    ///
    buffer(void *data, size_type size) :
        m_size(size),
        m_data(static_cast<data_type *>(data))
    {
        expects(size != 0 || data == nullptr);
        expects(data != nullptr || size == 0);
    }

    /// Initializer List Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param list initial list to create the buffer
    ///
    /// @throws std::bad_alloc if this constructor is unable to allocate memory for the buffer
    ///
    buffer(std::initializer_list<data_type> list) :
        m_size(list.size()),
        m_data(std::make_unique<data_type[]>(m_size))
    {
        gsl::span<const data_type> list_span(list);
        gsl::copy(list_span, span());
    }

    /// Default Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~buffer() = default;

    /// Get Data
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns a pointer to the buffer
    ///
    data_type *get() noexcept
    { return m_data.get(); }

    /// Get Data
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns a pointer to the buffer
    ///
    data_type *data() noexcept
    { return m_data.get(); }

    /// Get Data
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns a pointer to the buffer
    ///
    const data_type *data() const noexcept
    { return m_data.get(); }

    /// Is Empty
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns true if size() == 0, false otherwise
    ///
    bool empty() const noexcept
    { return m_size == 0; }

    /// Valid
    ///
    /// @return returns true if the buffer is valid, false otherwise
    ///
    operator bool() const noexcept
    { return m_data.operator bool(); }

    /// Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the size of the buffer
    ///
    size_type size() const noexcept
    { return m_size; }

    /// Release
    ///
    /// @expects none
    /// @ensures none
    ///
    void
    release() noexcept
    {
        m_size = 0;
        m_data.release();
    }

    /// Swap
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the other buffer to swap with
    ///
    void
    swap(buffer &other) noexcept
    {
        std::swap(m_size, other.m_size);
        std::swap(m_data, other.m_data);
    }

    /// Span
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns a gsl::span that can be used to access the buffer.
    ///
    gsl::span<data_type>
    span() const
    { return gsl::make_span(m_data, gsl::narrow_cast<std::ptrdiff_t>(m_size)); }

    /// Resize
    ///
    /// Resize the buffer. If count is smaller than the original size, the
    /// data is truncated. If count is larger than the original size, the
    /// remaining data is undefined.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param count the number of bytes to resize the buffer to
    ///
    /// @throws std::bad_alloc if this method is unable to allocate memory for the buffer
    ///
    void
    resize(size_type count)
    {
        auto new_data = std::make_unique<data_type[]>(count);
        memcpy(new_data.get(), m_data.get(), std::min(m_size, count));

        m_size = count;
        m_data = std::move(new_data);
    }

private:

    size_type m_size{0};
    std::unique_ptr<data_type[]> m_data;

public:

    buffer(buffer &&) noexcept = default;               ///< Default move construction
    buffer &operator=(buffer &&) noexcept = default;    ///< Default move operator

    buffer(const buffer &) = delete;                    ///< Default copy construction
    buffer &operator=(const buffer &) = delete;         ///< Default copy operator
};

/// Swap
///
/// @expects none
/// @ensures none
///
/// @param lhs buffer to swap
/// @param rhs buffer to swap
///
inline void
swap(buffer &lhs, buffer &rhs) noexcept
{ lhs.swap(rhs); }

/// Equals
///
/// @expects none
/// @ensures none
///
/// @param lhs buffer to compare
/// @param rhs buffer to compare
///
inline bool
operator==(const buffer &lhs, const buffer &rhs) noexcept
{
    if (lhs.size() != rhs.size()) {
        return false;
    }

    return memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
}

/// Not Equals
///
/// @expects none
/// @ensures none
///
/// @param lhs buffer to compare
/// @param rhs buffer to compare
///
inline bool
operator!=(const buffer &lhs, const buffer &rhs) noexcept
{ return !(lhs == rhs); }

}

#endif
