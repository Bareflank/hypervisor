#ifndef VMM_VCPU_X64_NESTED_PAGING_HPP
#define VMM_VCPU_X64_NESTED_PAGING_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class nested_paging
{
public:

    /// @brief Enable nested paging
    virtual void enable_nested_paging() noexcept = 0;

    /// @brief Disable nested paging
    virtual void disable_nested_paging() noexcept = 0;

    /// @brief Set the physical address of the base page table structure to be
    ///     used for nested paging
    ///
    /// @param phys_addr The host physical address of a base page table structure
    virtual void set_nested_paging_base_address(uintptr_t phys_addr) noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a memory access violation while a vcpu is executing with nested
    ///     paging enabled.
    ///
    /// @param func The delegate function to be called
    virtual void set_nested_paging_violation_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a page table misconfiguration while a vcpu is executing with
    ///     nested paging enabled.
    ///
    /// @param func The delegate function to be called
    virtual void set_nested_paging_misconfiguration_vmexit_handler(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Returns true if the current vmexit execution context was
    ///     triggered as a result of a memory read operation
    ///
    /// @return True if a memory read caused the current vmexit, else false
    virtual bool is_nested_paging_vmexit_read() noexcept = 0;

    /// @brief Returns true if the current vmexit execution context was
    ///     triggered as a result of a memory write operation
    ///
    /// @return True if a memory write caused the current vmexit, else false
    virtual bool is_nested_paging_vmexit_write() noexcept = 0;

    /// @brief Returns true if the current vmexit execution context was
    ///     triggered as a result of a memory execute operation
    ///
    /// @return True if a memory execute caused the current vmexit, else false
    virtual bool is_nested_paging_vmexit_execute() noexcept = 0;

    /// @brief Returns true if the current vmexit execution context was
    ///     triggered as a result of a nested paging violation operation
    ///
    /// @return True if a nested paging violation caused the current vmexit,
    ///     else false
    virtual bool is_nested_paging_vmexit_violation() noexcept = 0;

    /// @brief Returns true if the current vmexit execution context was
    ///     triggered as a result of a nested paging  misconfiguration operation
    ///
    /// @return True if a nested paging  misconfiguration caused the current
    ///     vmexit, else false
    virtual bool is_nested_paging_vmexit_misconfiguration() noexcept = 0;

    virtual ~nested_paging() noexcept = default;
protected:
    nested_paging() noexcept = default;
    nested_paging(nested_paging &&) noexcept = default;
    nested_paging &operator=(nested_paging &&) noexcept = default;
    nested_paging(nested_paging const &) = delete;
    nested_paging &operator=(nested_paging const &) & = delete;
};

}

#endif
