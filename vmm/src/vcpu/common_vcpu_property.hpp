#ifndef VMM_VCPU_VCPU_PROPERTY_HPP
#define VMM_VCPU_VCPU_PROPERTY_HPP

#include <vmm/vcpu/vcpu_property.hpp>

namespace vmm
{

class common_vcpu_property :
    public vcpu_property
{
public:

    id_type get_id() noexcept
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

    void is_bootstrap_vcpu_set(bool value) noexcept
    {
        // TODO: Implement me!
        return;
    }

    bool is_root_vcpu() noexcept
    {
        // TODO: Implement me!
        return false;
    }

    void is_root_vcpu_set(bool value) noexcept
    {
        // TODO: Implement me!
        return;
    }

    common_vcpu_property() noexcept = default;
};

}

#endif
