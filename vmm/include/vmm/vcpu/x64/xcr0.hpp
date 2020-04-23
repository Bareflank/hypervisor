#ifndef VMM_VCPU_X64_XCR0_HPP
#define VMM_VCPU_X64_XCR0_HPP

namespace vmm
{

class xcr0
{
public:

    /// @brief Set a vmexit handler that will be called for all vmexits caused
    ///     by a write to extended control register xcr0 using the xgetbv
    ///     instruction while a vcpu is executing.
    ///
    /// @param func The delegate function to be called
    virtual void xcr0_write_vmexit_handler_set(x64_vcpu_delegate func) noexcept = 0;

    virtual ~xcr0() noexcept = default;
protected:
    xcr0() noexcept = default;
    xcr0(xcr0 &&) noexcept = default;
    xcr0 &operator=(xcr0 &&) noexcept = default;
    xcr0(xcr0 const &) = delete;
    xcr0 &operator=(xcr0 const &) & = delete;
};

}

#endif
