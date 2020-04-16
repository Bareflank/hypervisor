#ifndef VMM_VCPU_INSTRUCTION_POINTER_HPP
#define VMM_VCPU_INSTRUCTION_POINTER_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class instruction_pointer
{
public:

    /// @brief Advance a vcpu's instruciton pointer to the next instruction
    ///
    /// @return 0 on success, non-0 on failure
    virtual bsl::errc_type instruction_pointer_advance() noexcept = 0;

    virtual ~instruction_pointer() noexcept = default;
protected:
    instruction_pointer() noexcept = default;
    instruction_pointer(instruction_pointer &&) noexcept = default;
    instruction_pointer &operator=(instruction_pointer &&) noexcept = default;
    instruction_pointer(instruction_pointer const &) = delete;
    instruction_pointer &operator=(instruction_pointer const &) & = delete;
};

}

#endif
