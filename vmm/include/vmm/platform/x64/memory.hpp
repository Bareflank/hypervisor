#ifndef VMM_MEMORY_VMM_MEMORY_HPP
#define VMM_MEMORY_VMM_MEMORY_HPP

#include <vmm/platform/x64/page_size.hpp>
#include <vmm/platform/x64/memory_type.hpp>
#include <bsl/cstdint.hpp>

namespace vmm
{

class memory
{
public:
    /// @brief Allocate a host virtual address mapping of @param size bytes to the
    ///     given host physical address, using the optional page size as a
    ///     granularity for the mapping (defaults to 4 KB), and optional memory
    ///     type (defaults to write-back)
    ///
    /// @param hpa The host physical address to a create a mapping to
    /// @param size The size of the mapping, in bytes
    /// @param ps The page size (granularity) to be used for the mapping.
    /// @param mt The memory type (caching method) to be used for the mapping.
    ///
    /// @return A host virtual address that may be used to access the mapped host
    ///     physical address range
    virtual void * alloc_hva_map(uintptr_t hpa, uintmax_t size,
                            page_size ps=page_size::page_4k,
                            memory_type mt=memory_type::write_back) = 0;

    /// @brief Allocate a host virtual address mapping of @param size bytes to the
    ///     given host physical address, using the optional page size as a
    ///     granularity for the mapping (defaults to 4 KB)
    ///
    /// @param hpa The host physical address to a create a mapping to
    /// @param size The size of the mapping, in bytes
    /// @param ps The page size (granularity) to be used for the mapping.
    ///
    /// @return A host virtual address that may be used to access the mapped host
    ///     physical address range
    template<typename T>
    T * alloc_hva_map(uintptr_t hpa, uintmax_t size,
                        page_size ps=page_size::page_4k,
                        memory_type mt=memory_type::write_back)
    { return static_cast<T*>(alloc_hva_map(hpa, size, ps, mt)); }
      
    /// @brief Resolve the mapping for the given host virtual address to the host
    ///     physical address it is mapped to.
    ///
    /// @param hva The host virtual address to resolve a mapping for
    ///
    /// @return hpa The host physical address that is mapped to
    virtual uintptr_t hva_to_hpa(void * hva) = 0;

    virtual ~memory() noexcept = default;
protected:
    memory() noexcept = default;
    memory(memory &&) noexcept = default;
    memory &operator=(memory &&) noexcept = default;
    memory(memory const &) = delete;
    memory &operator=(memory const &) & = delete;
};

}

#endif
