#ifndef VMM_VCPU_VCPU_PROPERTY_HPP
#define VMM_VCPU_VCPU_PROPERTY_HPP

#include <vmm/vcpu/property.hpp>

namespace vmm
{

class vcpu_property :
    public property
{
public:

    id_type id() noexcept
    {
        // TODO: Implement me!
        return 0;
    }

    void set_id(id_type value) noexcept
    {
        // TODO: Implement me!
        return;
    }

    bool is_bootstrap_vcpu() noexcept
    {
        // TODO: Implement me!
        return false;
    }

    void set_is_bootstrap_vcpu(bool value) noexcept
    {
        // TODO: Implement me!
        return;
    }

    bool is_root_vcpu() noexcept
    {
        // TODO: Implement me!
        return false;
    }

    void set_is_root_vcpu(bool value) noexcept
    {
        // TODO: Implement me!
        return;
    }

    vcpu_property() noexcept = default;
};

}

#endif
