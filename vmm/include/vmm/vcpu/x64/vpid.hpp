#ifndef VMM_VCPU_X64_VPID_HPP
#define VMM_VCPU_X64_VPID_HPP

namespace vmm
{

class vpid
{
public:

    virtual void vpid_enable() noexcept = 0;

    virtual ~vpid() noexcept = default;
protected:
    vpid() noexcept = default;
    vpid(vpid &&) noexcept = default;
    vpid &operator=(vpid &&) noexcept = default;
    vpid(vpid const &) = delete;
    vpid &operator=(vpid const &) & = delete;
};

}

#endif
