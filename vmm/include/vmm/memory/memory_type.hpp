#ifndef VMM_MEMORY_MEMORY_TYPE_HPP
#define VMM_MEMORY_MEMORY_TYPE_HPP

namespace vmm
{

/// @brief Defines the memory types (i.e. caching methods) supported by the
///     vmm's memory interfaces
enum class memory_type {
    uncacheable,
    write_back
};

}

#endif
