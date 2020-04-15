#ifndef VMMCTL_COMPOSITE_CONCRETE_HPP
#define VMMCTL_COMPOSITE_CONCRETE_HPP

#include <composite_interface.hpp>

namespace vmmctl
{

template<
    class vmm_info_type,
    class vmm_loader_type
>
class composite_concrete :
    public composite_interface
{
public:

    bsl::exit_code dump() noexcept final 
    { return m_vmm_info_type.dump(); }
    
    bsl::exit_code status() noexcept final
    { return m_vmm_info_type.status(); }

    bsl::exit_code load() noexcept final
    { return m_vmm_loader_type.load(); }
    
    bsl::exit_code unload() noexcept final
    { return m_vmm_loader_type.unload(); }
    
    bsl::exit_code start() noexcept final
    { return m_vmm_loader_type.start(); }
    
    bsl::exit_code stop() noexcept final
    { return m_vmm_loader_type.stop(); }
    

private:
    /// @brief a
    vmm_info_type m_vmm_info_type{};
    /// @brief a
    vmm_loader_type m_vmm_loader_type{};
};

}

#endif

