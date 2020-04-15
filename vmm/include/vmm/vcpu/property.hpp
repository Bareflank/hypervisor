#ifndef VMM_VCPU_PROPERTY_HPP
#define VMM_VCPU_PROPERTY_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class property
{
public:
    using id_type = uint64_t;

    /// @brief returns the vcpu's id
    ///
    /// @return the vcpu's id
    virtual id_type id() noexcept = 0;

    /// @brief returns true if this is the vcpu used to bootstrap the rest of
    /// the vmm (i.e. the vcpu that runs first when the vmm is loading)
    ///
    /// @return true if the vcpu is the bootstrap vcpu, else false
    virtual bool is_bootstrap_vcpu() noexcept = 0;

    /// @brief returns true if this vcpu belongs to a root virtual machine
    ///
    /// @return true if the vcpu is a root vcpu, else false
    virtual bool is_root_vcpu() noexcept = 0;

    virtual ~property() noexcept = default;
protected:
    property() noexcept = default;
    property(property &&) noexcept = default;
    property &operator=(property &&) noexcept = default;
    property(property const &) = delete;
    property &operator=(property const &) & = delete;
};

}

#endif
