#ifndef VMM_VCPU_X64_VMEXIT_HPP
#define VMM_VCPU_X64_VMEXIT_HPP

#include <vmm/vcpu/x64/x64_vcpu_delegate.hpp>

namespace vmm
{

class x64_vcpu;

class vmexit
{
public:

    /// @brief Returns the basic vm exit reason that caused a vmexit while a
    ///     vcpu was running
    ///
    /// @return The basic vm exit reason
    virtual uint32_t vmexit_reason_get() noexcept = 0;

    /// @brief Returns the basic vm exit qualification that caused a vmexit
    ///     while a vcpu was running
    ///
    /// @return The basic vm exit qualification
    virtual uint32_t vmexit_qualification_get() noexcept = 0;

    /// @brief Set a vmexit handler that will be called for all vmexits that
    ///     occur while a vcpu is executing. This handler is called before
    ///     execution of all other user defined vmexit handlers.
    ///
    /// @param func The delegate function to be called
    virtual void vmexit_handler_set(x64_vcpu_delegate func) noexcept = 0;

    /// @brief Set a vmexit handler that gets called in the event that no user
    ///     defined vmexit handlers serviced a vmexit. This handler will get
    ///     called after execution of all user defined vmexit handlers for a
    ///     specific exit reason.
    ///
    /// @param func The delegate function to be called
    virtual void post_vmexit_handler_set(x64_vcpu_delegate func) noexcept = 0;

    virtual ~vmexit() noexcept = default;
protected:
    vmexit() noexcept = default;
    vmexit(vmexit &&) noexcept = default;
    vmexit &operator=(vmexit &&) noexcept = default;
    vmexit(vmexit const &) = delete;
    vmexit &operator=(vmexit const &) & = delete;
};

}

#endif
