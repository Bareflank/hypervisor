#ifndef VMM_MEMORY_PAGE_SIZE_HPP
#define VMM_MEMORY_PAGE_SIZE_HPP

namespace vmm
{

/// @brief Defines the page sizes (mapping granularities) supported by the
///     vmm's memory interfaces
enum class page_size {
    page_4k=0x1000,
    page_2m=0x200000,
    page_1g=0x40000000
};

}

#endif
