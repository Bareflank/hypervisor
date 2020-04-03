#ifndef VMM_VCPU_X64_INTEL_EXECUTE_HPP
#define VMM_VCPU_X64_INTEL_EXECUTE_HPP

#include <vmm/vcpu/execute.hpp>

namespace vmm
{

class intel_execute :
    public execute
{
public:

    bsl::errc_type load() noexcept final
    {
        // TODO: Implement Me!
        return -1;
    }
    
    bsl::errc_type unload() noexcept final
    {
        // TODO: Implement Me!
        return -1;
    }
    
    bsl::errc_type run() noexcept final
    {
        // TODO: Implement Me!
        return -1;
    }
    
    intel_execute() noexcept = default;
};

}

#endif
