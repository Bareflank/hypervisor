#ifndef VMM_VCPU_NESTED_PAGING_HPP
#define VMM_VCPU_NESTED_PAGING_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class nested_paging
{
public:

    // TODO: Define My Interface!

    virtual ~nested_paging() noexcept = default;
protected:
    nested_paging() noexcept = default;
    nested_paging(nested_paging &&) noexcept = default;
    nested_paging &operator=(nested_paging &&) noexcept = default;
    nested_paging(nested_paging const &) = delete;
    nested_paging &operator=(nested_paging const &) & = delete;
};

}

#endif
