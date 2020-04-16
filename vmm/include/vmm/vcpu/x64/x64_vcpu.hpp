#ifndef VMM_X64_VCPU_HPP
#define VMM_X64_VCPU_HPP

#include <vmm/vcpu/vcpu.hpp>

#include <vmm/vcpu/x64/cpuid.hpp>
#include <vmm/vcpu/x64/cr0.hpp>
#include <vmm/vcpu/x64/cr3.hpp>
#include <vmm/vcpu/x64/cr4.hpp>
#include <vmm/vcpu/x64/general_register_x64.hpp>
#include <vmm/vcpu/x64/init_signal.hpp>
#include <vmm/vcpu/x64/interrupt.hpp>
#include <vmm/vcpu/x64/interrupt_window.hpp>
#include <vmm/vcpu/x64/io_port.hpp>
#include <vmm/vcpu/x64/monitor_trap.hpp>
#include <vmm/vcpu/x64/nmi.hpp>
#include <vmm/vcpu/x64/nmi_window.hpp>
#include <vmm/vcpu/x64/preemption_timer.hpp>
#include <vmm/vcpu/x64/rdmsr.hpp>
#include <vmm/vcpu/x64/sipi_signal.hpp>
#include <vmm/vcpu/x64/vmexit.hpp>
#include <vmm/vcpu/x64/vpid.hpp>
#include <vmm/vcpu/x64/wrmsr.hpp>
#include <vmm/vcpu/x64/xcr0.hpp>

namespace vmm
{

class x64_vcpu :
    public vcpu,
    public cpuid,
    public cr0,
    public cr3,
    public cr4,
    public general_register_x64,
    public init_signal,
    public interrupt,
    public interrupt_window,
    public io_port,
    public monitor_trap,
    public nmi,
    public nmi_window,
    public preemption_timer,
    public rdmsr,
    public sipi_signal,
    public vmexit,
    public vpid,
    public wrmsr,
    public xcr0
{
public:
    ~x64_vcpu() noexcept override = default;
protected:
    x64_vcpu() noexcept = default;
    x64_vcpu(x64_vcpu &&) noexcept = default;
    x64_vcpu &operator=(x64_vcpu &&) noexcept = default;
    x64_vcpu(x64_vcpu const &) = delete;
    x64_vcpu &operator=(x64_vcpu const &) & = delete;
};

}

#endif
