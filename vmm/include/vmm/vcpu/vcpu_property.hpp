#ifndef VMM_VCPU_PROPERTY_HPP
#define VMM_VCPU_PROPERTY_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class vcpu_property
{
public:
    using id_type = uint64_t;

    /// @brief Returns the vcpu's id
    ///
    /// @return The vcpu's id
    virtual id_type id_get() noexcept = 0;

    /// @brief Returns true if this is the vcpu used to bootstrap the rest of
    /// the vmm (i.e. the vcpu that runs first when the vmm is loading)
    ///
    /// @return True if the vcpu is the bootstrap vcpu, else false
    virtual bool is_bootstrap_vcpu() noexcept = 0;

    /// @brief Returns true if this vcpu belongs to a root virtual machine
    ///
    /// @return True if the vcpu is a root vcpu, else false
    virtual bool is_root_vcpu() noexcept = 0;

    virtual ~vcpu_property() noexcept = default;
protected:
    vcpu_property() noexcept = default;
    vcpu_property(vcpu_property &&) noexcept = default;
    vcpu_property &operator=(vcpu_property &&) noexcept = default;
    vcpu_property(vcpu_property const &) = delete;
    vcpu_property &operator=(vcpu_property const &) & = delete;
};

}

#endif
