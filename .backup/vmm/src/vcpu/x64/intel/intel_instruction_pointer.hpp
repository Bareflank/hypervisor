#ifndef VMM_VCPU_X64_INTEL_INSTRUCTION_POINTER_HPP
#define VMM_VCPU_X64_INTEL_INSTRUCTION_POINTER_HPP

#include <vmm/vcpu/instruction_pointer.hpp>

namespace vmm
{

class intel_instruction_pointer :
    public instruction_pointer
{
public:

    bsl::errc_type
    advance_instruction_pointer() noexcept final
    {
        // TODO: Implement Me!
        return -1;
    }

    intel_instruction_pointer() noexcept = default;
};

}

#endif
