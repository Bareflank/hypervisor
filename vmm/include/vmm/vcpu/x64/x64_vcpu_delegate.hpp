#ifndef VMM_VCPU_X64_VCPU_DELEGATE_HPP
#define VMM_VCPU_X64_VCPU_DELEGATE_HPP

namespace vmm
{

using x64_vcpu_delegate = void(*)(class x64_vcpu &);

}

#endif
