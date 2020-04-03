#ifndef VMM_VCPU_EXECUTE_HPP
#define VMM_VCPU_EXECUTE_HPP

#include <bsl/errc_type.hpp>

namespace vmm
{

class execute
{
public:

    virtual bsl::errc_type load() noexcept = 0;
    virtual bsl::errc_type unload() noexcept = 0;
    virtual bsl::errc_type run() noexcept = 0;

    virtual ~execute() noexcept = default;
protected:
    execute() noexcept = default;
    execute(execute &&) noexcept = default;
    execute &operator=(execute &&) noexcept = default;
    execute(execute const &) = delete;
    execute &operator=(execute const &) & = delete;
};

}

#endif
