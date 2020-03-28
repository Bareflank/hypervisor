#ifndef VMM_VCPU_FINI_ROOT_HPP
#define VMM_VCPU_FINI_ROOT_HPP

#include <bsl/exit_code.hpp>

namespace vmm
{

bsl::exit_code vcpu_fini_root() noexcept;

}

#endif
