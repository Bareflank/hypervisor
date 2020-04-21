#ifndef VMM_MEMORY_VMM_MEMORY_HPP
#define VMM_MEMORY_VMM_MEMORY_HPP

#include <vmm/memory/page_size.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/errc_type.hpp>

namespace vmm
{

/// @brief Allocate a host virtual address space of @param size bytes
///
/// @param size The size of the allocation, in bytes
///
/// @return A pointer to the allocated host virtual memory
void * hva_alloc(uintmax_t size);

/// @brief Allocate a host virtual address space of @param size bytes
///
/// @param size The size of the allocation, in bytes
///
/// @return A pointer to the allocated host virtual memory
template<typename T>
T * hva_alloc(uintmax_t size)
{ return static_cast<T*>(hva_alloc(size)); }

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
void * hva_map_alloc(uintptr_t hpa, uintmax_t size, page_size ps=page_size::page_4k);

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
T * hva_map_alloc(uintptr_t hpa, uintmax_t size, page_size ps=page_size::page_4k)
{ return static_cast<T*>(hva_map_alloc(hpa, size, ps)); }
  
/// @brief Free the given host virtual address
///
/// @param hva The host virtual address to unmap
void hva_free(void * hva);

/// @brief Resolve the mapping for the given host virtual address to the host
///     physical address it is mapped to.
///
/// @param hva The host virtual address to resolve a mapping for
///
/// @return hpa The host physical address that is mapped to
uintptr_t hva_to_hpa(void * hva);

}

#endif
