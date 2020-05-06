#ifndef MICROV_VMEXIT_DELEGATE_HPP
#define MICROV_VMEXIT_DELEGATE_HPP

namespace microv
{

    using vmexit_delegate = void(*)(vmexit_context &) noexcept;

}

#endif
