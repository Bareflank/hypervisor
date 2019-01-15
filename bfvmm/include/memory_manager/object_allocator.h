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

#ifndef OBJECT_ALLOCATOR_H
#define OBJECT_ALLOCATOR_H

#include <bfgsl.h>
#include <bfexception.h>
#include <bfconstants.h>

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

extern "C" void *alloc_page();
extern "C" void free_page(void *ptr);

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

constexpr const auto pagepool_size = 255U;
constexpr const auto objtpool_size = 255U;

#ifndef OBJECT_ALLOCATOR_DEBUG
#define OBJECT_ALLOCATOR_DEBUG 5
#endif

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// @struct __oa_page
///
/// Object Allocator Page
///
/// This struct defines a page size, and can be used to validate pages,
/// as well as allocate them.
///
/// @var __oa_page::data
///     the size of the page
///
struct __oa_page {
    gsl::byte data[BAREFLANK_PAGE_SIZE];
};

/// Object Allocator Alloc
///
/// Allocates a page size, and uses the template function to verify at compile
/// time that allocations are the size of a page
///
/// @return the allocated memory
///
template<typename S>
S *__oa_alloc()
{
    static_assert(BAREFLANK_PAGE_SIZE == sizeof(S), "allocation is not a page");
    void *addr;

    if (GSL_LIKELY(addr = alloc_page())) {
        return static_cast<S *>(addr);
    }

    throw std::runtime_error("__oa_alloc: out of memory");
}

/// Object Allocator Free
///
/// Frees previous allocated memory, and uses the template argument to ensure
/// freed memory is a page in size.
///
template<typename S>
void __oa_free(S *ptr)
{
    static_assert(BAREFLANK_PAGE_SIZE == sizeof(S), "deallocation is not a page");
    free_page(ptr);
}

/// Object Allocator
///
/// The goals of this allocator includes:
/// - O(1) allocation time
/// - O(1) deallocation time
/// - No external fragmentation (internal fragmentation is allowed, and can
///   be high depending on the size of the object)
/// - Pre-allocate backing store, or dynamically allocate backing store as
///   needed (depends on usage)
/// - All external allocations made by the object allocator are a page in size
///
/// To support these features, this allocator uses 4 different stacks.
/// - page stack: this stack stores a pool of page_t structures, each page_t
///   stores the address of a single page that can be used as a backing store
///   for allocations. Each page_stack_t can store 255 page_t structures before
///   anther page_stack_t has to be pushed to the stack
/// - object stack: this stack stores all of the object_t structures. Each
///   object_stack_t can store 255 object_t structures before another
///   object_stack_t has to be pushed to the stack. Each object_t stores an
///   address within a page_t's allocated page, in other words, the object_t
///   struct actually stores the memory that is given out by the allocator.
/// - free / used stacks: these stacks store the object_t structures based
///   on their current status. object_t structures ready to be allocated are
///   stored on the free stack, while object_t structures already allocated
///   are stored on the used stack. Each allocation / deallocation simply
///   moves a object_t structure from one stack to another.
///
/// In order to support both dynamic allocation, and limited pre-allocation
/// schemes (i.e. all memory is allocated ahead of time, and once this
/// pre-allocated memory is used, the allocator is out of memory), a max_pages
/// variable is defined. If set to 0, the max number of pages used by the
/// allocator is unlimited, and all allocations are performed dynamically
/// on demand. If set to > 0, all memory is pre-allocated and limited. Also
/// note that the max_pages refers to the total number of pages allocated for
/// use by the page pool, and does not include pages allocated for the
/// allocator's internal stacks.
///
/// Limitations:
/// - The largest allocation that can take place is a page. Any
///   allocation larger than this should use the buddy allocator
/// - To achieve O(1) deallocation times, deallocation does not check the
///   validity of the provided pointer. If the pointer provided was not
///   previously allocated using the same allocator, corruption is likely.
///
class object_allocator
{
public:

    using pointer = void *;             ///< Alloc::pointer
    using size_type = std::size_t;      ///< Alloc::size_type

public:

    /// Constructor
    ///
    /// @expects size != 0
    /// @ensures none
    ///
    /// @param size the size of the object to allocate
    /// @param max_pages the max number of pages that may be used. 0 for
    ///     unlimited
    ///
    object_allocator(size_type size, size_type max_pages = 0) noexcept :
        m_size(size),
        m_max_pages(max_pages)
    {
        guard_exceptions([&]() {

            if (m_size == 0) {
                m_size = 1;
            }

            if (max_pages != 0) {
                for (auto i = 0U; i < max_pages; ++i) {
                    add_to_free_stack();
                }
            }
        });
    }

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~object_allocator() noexcept
    {
        if (m_used_stack_top != nullptr) {
            bfalert_nhex(OBJECT_ALLOCATOR_DEBUG, "object_allocator leaked memory", num_used());
            return;
        }

        cleanup();
    }

    /// Allocate Object
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return an allocated object. Throws otherwise
    ///
    inline pointer allocate()
    {
        auto objt = free_stack_pop();
        used_stack_push(objt);

        return objt->addr;
    }

    /// Deallocate Object
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param p a pointer to a previously allocated object to be deallocated
    ///
    inline void deallocate(pointer p)
    {
        auto objt = used_stack_pop();
        free_stack_push(objt);

        objt->addr = p;
    }

    /// Contains
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param p to lookup
    /// @return true if the buddy allocator contains p, false otherwise
    ///
    inline bool contains(pointer p) const noexcept
    {
        auto next = m_page_stack_top;

        while (next != nullptr) {

            for (auto i = 0ULL; i < next->index; i++) {
                auto s = next->pool[i].addr;
                auto e = next->pool[i].addr + BAREFLANK_PAGE_SIZE;

                if (p >= s && p < e) {
                    return true;
                }
            }

            next = next->next;
        }

        return false;
    }

    /// Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param ptr a pointer to a previously allocated object
    /// @return the size of ptr
    ///
    inline size_type size(pointer ptr) const
    { bfignored(ptr); return m_size; }

    /// Get Page Stack Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return size of page stack
    ///
    inline size_type page_stack_size() noexcept
    {
        auto size = 0ULL;
        auto next = m_page_stack_top;

        while (next != nullptr) {
            ++size;
            next = next->next;
        }

        return size;
    }

    /// Get Object Stack Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return size of object stack
    ///
    inline size_type objt_stack_size() noexcept
    {
        auto size = 0ULL;
        auto next = m_objt_stack_top;

        while (next != nullptr) {
            ++size;
            next = next->next;
        }

        return size;
    }

    /// Get Number of Allocated Pages
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return number of allocated pages
    ///
    inline size_type num_page() noexcept
    {
        auto size = 0ULL;
        auto next = m_page_stack_top;

        while (next != nullptr) {
            size += next->index;
            next = next->next;
        }

        return size;
    }

    /// Get Free List Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return number of object_t structures in free list
    ///
    inline size_type num_free() noexcept
    {
        auto size = 0ULL;
        auto next = m_free_stack_top;

        while (next != nullptr) {
            ++size;
            next = next->next;
        }

        return size;
    }

    /// Get Free Used Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return number of object_t structures in used list
    ///
    inline size_type num_used() noexcept
    {
        auto size = 0ULL;
        auto next = m_used_stack_top;

        while (next != nullptr) {
            ++size;
            next = next->next;
        }

        return size;
    }

private:

    struct object_t {
        pointer addr;
        object_t *next;
    };

    struct object_stack_t {
        object_t pool[objtpool_size];

        uint64_t index;
        object_stack_t *next;
    };

    struct page_t {
        gsl::byte *addr;
        uint64_t index;
    };

    struct page_stack_t {
        page_t pool[pagepool_size];

        uint64_t index;
        page_stack_t *next;
    };

    object_t *m_free_stack_top{nullptr};
    object_t *m_used_stack_top{nullptr};

    page_stack_t *m_page_stack_top{nullptr};
    object_stack_t *m_objt_stack_top{nullptr};

private:

    inline page_t *get_next_page()
    {
        if (GSL_UNLIKELY(m_max_pages != 0 && m_pages_consumed >= m_max_pages)) {
            throw std::runtime_error("object_allocator: out of memory");
        }

        if (m_page_stack_top == nullptr || m_page_stack_top->index == pagepool_size) {
            expand_page_stack();
        }

        auto page = &gsl::at(m_page_stack_top->pool, m_page_stack_top->index);
        page->addr = static_cast<gsl::byte *>(alloc_page());
        page->index = 0;

        ++m_pages_consumed;
        ++m_page_stack_top->index;

        return page;
    }

    inline object_t *get_next_object()
    {
        if (m_objt_stack_top == nullptr || m_objt_stack_top->index == objtpool_size) {
            expand_object_stack();
        }

        return &gsl::at(m_objt_stack_top->pool, m_objt_stack_top->index++);
    }

    inline void free_stack_push(object_t *next)
    {
        next->next = m_free_stack_top;
        m_free_stack_top = next;
    }

    inline object_t *free_stack_pop()
    {
        if (m_free_stack_top == nullptr) {
            add_to_free_stack();
        }

        auto top = m_free_stack_top;

        m_free_stack_top = m_free_stack_top->next;
        top->next = nullptr;

        return top;
    }

    inline void used_stack_push(object_t *next)
    {
        next->next = m_used_stack_top;
        m_used_stack_top = next;
    }

    inline object_t *used_stack_pop()
    {
        if (GSL_UNLIKELY(m_used_stack_top == nullptr)) {
            bfalert_info(OBJECT_ALLOCATOR_DEBUG, "used_stack_pop empty. memory corruption likely");
            used_stack_push(get_next_object());
        }

        auto top = m_used_stack_top;

        m_used_stack_top = m_used_stack_top->next;
        top->next = nullptr;

        return top;
    }

    inline void expand_page_stack()
    {
        auto next = __oa_alloc<page_stack_t>();

        next->next = m_page_stack_top;
        m_page_stack_top = next;
    }

    inline void expand_object_stack()
    {
        auto next = __oa_alloc<object_stack_t>();

        next->next = m_objt_stack_top;
        m_objt_stack_top = next;
    }

    inline void add_to_free_stack()
    {
        auto page = get_next_page();

        for (auto i = 0ULL; i + m_size <= BAREFLANK_PAGE_SIZE; i += m_size) {
            auto object = get_next_object();
            free_stack_push(object);

            auto view = gsl::make_span(page->addr, BAREFLANK_PAGE_SIZE);
            object->addr = &view[i];
        }
    }

    inline void cleanup() noexcept
    {
        guard_exceptions([&]() {

            bfdebug_ndec(OBJECT_ALLOCATOR_DEBUG, "object_allocator: pages used", num_page());

            while (m_page_stack_top != nullptr) {
                if (m_page_stack_top->index != 0) {
                    for (auto i = 0ULL; i < m_page_stack_top->index; ++i) {
                        auto page = &gsl::at(m_page_stack_top->pool, i);
                        free_page(page->addr);
                    }
                }

                auto next = m_page_stack_top->next;
                __oa_free<page_stack_t>(m_page_stack_top);
                m_page_stack_top = next;
            }

            while (m_objt_stack_top != nullptr) {
                auto next = m_objt_stack_top->next;
                __oa_free<object_stack_t>(m_objt_stack_top);
                m_objt_stack_top = next;
            }

            m_free_stack_top = nullptr;
            m_used_stack_top = nullptr;
            m_page_stack_top = nullptr;
            m_objt_stack_top = nullptr;

            m_size = 0;
            m_max_pages = 0;
            m_pages_consumed = 0;
        });
    }

private:

    size_type m_size{0};
    size_type m_max_pages{0};
    size_type m_pages_consumed{0};

public:

    /// @cond

    object_allocator(object_allocator &&) noexcept = delete;
    object_allocator &operator=(object_allocator &&) noexcept = delete;

    object_allocator(const object_allocator &) = delete;
    object_allocator &operator=(const object_allocator &) = delete;

    /// @endcond
};

#endif
