#include <microv/execute.hpp>
#include <bsl/discard.hpp>

namespace microv
{

bsl::errc_type load(vmexit_context &vc) noexcept
{
    bsl::discard(vc);

    // TODO: Implement Me!
    return bsl::errc_failure;
}

bsl::errc_type unload(vmexit_context &vc) noexcept
{
    bsl::discard(vc);

    // TODO: Implement Me!
    return bsl::errc_failure;
}

bsl::errc_type run(vmexit_context &vc) noexcept
{
    bsl::discard(vc);

    // TODO: Implement Me!
    return bsl::errc_failure;
}

}
