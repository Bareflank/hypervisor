#ifndef VMM_VCPU_X64_VMCALL_HPP
#define VMM_VCPU_X64_VMCALL_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class vmcall
{
public:

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a vmcall instruction while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void vmcall_vmexit_handler_set(x64_vcpu_delegate func) noexcept = 0;

    virtual ~vmcall() noexcept = default;
protected:
    vmcall() noexcept = default;
    vmcall(vmcall &&) noexcept = default;
    vmcall &operator=(vmcall &&) noexcept = default;
    vmcall(vmcall const &) = delete;
    vmcall &operator=(vmcall const &) & = delete;
};

}

#endif

