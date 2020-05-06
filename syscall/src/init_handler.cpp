#include <microv/init_handler.hpp>
#include <bsl/discard.hpp>

namespace microv
{

void set_init_handler(vmexit_context &vc, vmexit_delegate func) noexcept
{
    bsl::discard(vc);
    bsl::discard(func);

    // TODO: Implement Me!
    return;
}

}
