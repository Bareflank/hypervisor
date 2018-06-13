//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

// -----------------------------------------------------------------------------
// Basic Allocator Definition
// -----------------------------------------------------------------------------

/// Basic Object Allocator
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
/// Windows:
/// A note about MSVC's implementation of the STL containers. Windows assumes
/// the allocators are not stateful (this is a stateful allocator). Since
/// Windows doesn't adhere to the C++11 spec, it assumes allocators of the
/// same type can deallocate even if they are not equal. As a result,
/// containers like std::list allocate without deallocating, and then attempt
/// to deallocate with a new allocator at a later time. For this reason, the
/// destructor does not cleanup memory if the allocator is still holding onto
/// objects in the used list. This object allocator should not be used with
/// Windows MSVC as a result as it will leak memory.
///
/// Limitations:
/// - The largest allocation that can take place is a page. Any
///   allocation larger than this should use the buddy allocator
/// - To achieve O(1) deallocation times, deallocation does not check the
///   validity of the provided pointer. If the pointer provided was not
///   previously allocated using the same allocator, corruption is likely.
///
/// TODO:
/// - For this allocator to be used by the SLAB allocator, the SLAB will have
///   to know what the size of the allocation was based on the address alone.
///   To overcome this issue, the maximum allocation should be a page - 64
///   bytes. The last 64 bytes should be used to store the size of the
///   allocations in that page, plus some reserved bytes for future use.
///   This way, the SLAB can mask off the address to calculate the location of
///   the size of this object without having to do a lookup. The size function
///   should be implemented as a static function that can get the size of an
///   object given any address (likely unsafe, but effective).
///
/// Performance Notes:
/// - Like most allocators, if the object size is small, the overhead of
///   managing this memory is large and vice versa. That being said,
///   the internal fragmentation seen by this allocator is smaller than that
///   of GCC's allocator. Plus, this allocator only allocates a page at a time
///   which means all allocations are aligned, and better suited to pair with
///   a buddy allocator than the default implementation.
/// - When compared to GCC's default allocators for std::list, this allocator
///   outperforms with respect to both allocations, and deallocations with both
///   the limited and unlimited versions. Note that the unit tests use a
///   std::map to ensure memory is not leaked, resulting in additional overhead
///   not seen by the default allocators. A traditional malloc / free version
///   is provided that can be uncommented if needed. Note that GCC's
///   implementation does have a different set of goals including thread-safety.
/// - When compared to Windows, this allocator is significantly better than
///   the default implementation. It should be noted that Windows leaks
///   memory.
///
class basic_object_allocator
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
    basic_object_allocator(size_type size, size_type max_pages) noexcept :
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
    ~basic_object_allocator() noexcept
    {
        if (m_used_stack_top != nullptr) {
            bfalert_nhex(OBJECT_ALLOCATOR_DEBUG, "basic_object_allocator leaked memory", num_used());
            return;
        }

        cleanup();
    }

    /// Move Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the allocator to move from
    ///
    basic_object_allocator(basic_object_allocator &&other) noexcept
    { *this = std::move(other); }

    /// Move Operator
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the allocator to move from
    /// @return this
    ///
    basic_object_allocator &operator=(basic_object_allocator &&other) noexcept
    {
        if (GSL_UNLIKELY(this != &other)) {

            if (m_used_stack_top != nullptr) {
                bfalert_nhex(OBJECT_ALLOCATOR_DEBUG, "basic_object_allocator leaked memory", num_used());
            }
            else {
                cleanup();
            }

            m_free_stack_top = other.m_free_stack_top;
            m_used_stack_top = other.m_used_stack_top;
            m_page_stack_top = other.m_page_stack_top;
            m_objt_stack_top = other.m_objt_stack_top;

            m_size = other.m_size;
            m_max_pages = other.m_max_pages;
            m_pages_consumed = other.m_pages_consumed;

            other.m_free_stack_top = nullptr;
            other.m_used_stack_top = nullptr;
            other.m_page_stack_top = nullptr;
            other.m_objt_stack_top = nullptr;

            other.m_size = 0;
            other.m_max_pages = 0;
            other.m_pages_consumed = 0;
        }

        return *this;
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

            bfdebug_ndec(OBJECT_ALLOCATOR_DEBUG, "basic_object_allocator: pages used", num_page());

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

    basic_object_allocator(const basic_object_allocator &) = delete;
    basic_object_allocator &operator=(const basic_object_allocator &) = delete;

    /// @endcond
};

// -----------------------------------------------------------------------------
// Allocator Definition
// -----------------------------------------------------------------------------

/// Object Allocator
///
/// This is a C++ Allocator wrapper for the basic_object_allocator that conforms
/// to the allocator concept defined here:
/// http://en.cppreference.com/w/cpp/concept/Allocator
///
/// Note that rebind allows a std container to create a new allocator based on
/// the one provided as is needed. For example, std containers will not only
/// have to allocate T, but they will also have to allocate nodes. In some
/// cases, the implementation will embed T in the node resulting in only a
/// single allocation for each T, that is large than T (consisting of the
/// extra overhead needed by the container). For this reason, max_pages should
/// be chosen to not only account for sizeof(T) but also a potential
/// sizeof(node<T>).
///
/// There are a couple of limitations with this wrapper. The copy constructor
/// is not supported as the allocator is stateful, and thus two of the same
/// allocators cannot exist. Also, 'n' is not supported for the allocation and
/// deallocation functions, or in other words, n must always equal 1. For this
/// reason, this allocator should not be used with containers like std::deque
/// which rely on n != 1 to increase efficiency of the standard use cases.
///
template<typename T, std::size_t max_pages = 0>
class object_allocator
{
    static_assert(BAREFLANK_PAGE_SIZE >= sizeof(T), "T is too large");

public:

    using value_type = T;                                               ///< Alloc::value_type
    using pointer = T *;                                                ///< Alloc::pointer
    using const_pointer = const T *;                                    ///< Alloc::const_pointer
    using reference = T &;                                              ///< Alloc::reference
    using const_reference = const T &;                                  ///< Alloc::const_reference
    using size_type = std::size_t;                                      ///< Alloc::size_type
    using propagate_on_container_copy_assignment = std::false_type;     ///< Copy not supported
    using propagate_on_container_move_assignment = std::true_type;      ///< Move supported
    using propagate_on_container_swap = std::true_type;                 ///< Swap supported
    using is_always_equal = std::false_type;                            ///< Not always equal

    /// Rebind
    ///
    /// @expects none
    /// @ensures none
    ///
    template<typename U> struct rebind {
        using other = object_allocator<U, max_pages>;                   ///< Rebind
    };

public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    object_allocator() noexcept :
        m_d {sizeof(T), max_pages}
    { }

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~object_allocator() noexcept
    { }

    /// Move Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the allocator to move from
    ///
    object_allocator(object_allocator &&other) noexcept :
        m_d {std::move(other.m_d)}
    { }

    /// Move Operator
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the allocator to move from
    /// @return this
    ///
    object_allocator &operator=(object_allocator &&other) noexcept
    {
        m_d = std::move(other.m_d);
        return *this;
    }

    /// Rebind Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other not supported
    ///
    template <typename U>
    object_allocator(const object_allocator<U, max_pages> &other) noexcept :
        m_d {sizeof(T), max_pages}
    { bfignored(other); }

    /// Copy Constructor (not supported)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other not supported
    ///
    object_allocator(const object_allocator &other) noexcept :
        m_d {sizeof(T), max_pages}
    { bfignored(other); }

    /// Copy Operator (not supported)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other not supported
    /// @return this
    ///
    object_allocator &operator=(const object_allocator &other) noexcept
    { bfignored(other); }

    /// Allocate
    ///
    /// Allocates an object. If n != 1, the allocator has no other option
    /// than to allocate n * 0x1000 to prevent external fragmentation. The
    /// internal fragmentation would be horrible in this case so it's not
    /// supported. For this reason, stick to STL containers that perform
    /// single allocations.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param n not supported
    /// @return an allocated object. Throws otherwise
    ///
    pointer allocate(size_type n)
    {
        if (n != 1) {
            return reinterpret_cast<pointer>(alloc_page());
        }

        return static_cast<pointer>(m_d.allocate());
    }

    /// Deallocate Object
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param n not supported
    /// @param p a pointer to a previously allocated object to be deallocated
    ///
    void deallocate(pointer p, size_type n)
    {
        if (n != 1) {
            return free_page(p);
        }

        m_d.deallocate(p);
    }

    /// Contains
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param p to lookup
    /// @return true if the allocator contains p, false otherwise
    ///
    bool contains(pointer p) const noexcept
    { return m_d.contains(p); }

    /// Construct
    ///
    /// Constructs each object. In C++11, this was supposed to be optional
    /// but not all compilers provide this function, we do to ensure
    /// compatibility.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param p the location of the new object
    /// @param args the arguments for the new object to be constructed with.
    ///
    template <typename U, typename... Args>
    void construct(U *p, Args &&... args)
    { ::new (reinterpret_cast<void *>(p)) U(std::forward<Args>(args)...); }

    /// Destory
    ///
    /// Destroys each object. In C++11, this was supposed to be optional
    /// but not all compilers provide this function, we do to ensure
    /// compatibility.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param p the location of the new object
    ///
    template <typename U>
    void destroy(U *p)
    { p->~U(); }

public:

    /// @cond

    auto page_stack_size() noexcept
    { return m_d.page_stack_size(); }

    auto objt_stack_size() noexcept
    { return m_d.objt_stack_size(); }

    auto num_page() noexcept
    { return m_d.num_page(); }

    auto num_free() noexcept
    { return m_d.num_free(); }

    auto num_used() noexcept
    { return m_d.num_used(); }

    /// @endcond

private:

    basic_object_allocator m_d;

private:

    /// @cond

    template <typename T1, typename T2, std::size_t MP>
    friend bool operator==(const object_allocator<T1, MP> &lhs, const object_allocator<T2, MP> &rhs);

    template <typename T1, typename T2, std::size_t MP>
    friend bool operator!=(const object_allocator<T1, MP> &lhs, const object_allocator<T2, MP> &rhs);

    /// @endcond
};

/// @cond

template <typename T1, typename T2, std::size_t MP>
bool operator==(const object_allocator<T1, MP> &, const object_allocator<T2, MP> &)
{ return false; }

template <typename T1, typename T2, std::size_t MP>
bool operator!=(const object_allocator<T1, MP> &, const object_allocator<T2, MP> &)
{ return true; }

/// @endcond

#endif
