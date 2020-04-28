#ifndef VMM_MEMORY_LOADER_HPP
#define VMM_MEMORY_LOADER_HPP

#include <bsl/cstdint.hpp>

namespace vmm
{

class loader
{
public:

    /// @brief Returns the host physical address of the vmm loader's wakeup
    ///     routine entry point (such as S3 resume), or 0 if it does not exist
    ///
    /// @return The host physical address of the loader's wakeup entry point
    virtual uintptr_t get_loader_wakeup_entry_point_hpa() noexcept = 0;

    /// @brief Returns true if the loader ran after the root operating system
    ///     was already running (i.e. a vmm late launch scenario)
    ///
    /// @return True if the vmm was loaded in a late launch scenario. else false
    virtual bool is_late_launch() noexcept = 0;

    virtual ~loader() noexcept = default;
protected:
    loader() noexcept = default;
    loader(loader &&) noexcept = default;
    loader &operator=(loader &&) noexcept = default;
    loader(loader const &) = delete;
    loader &operator=(loader const &) & = delete;
};

}

#endif
