#ifndef VMM_VCPU_ADVANCE_H
#define VMM_VCPU_ADVANCE_H

namespace vmm
{

/// advance
///
/// Defines the interface for vcpus that support the ability to advance an
/// instruction pointer/program counter to the next instruction
///
class advance
{
public:

    /// advance
    ///
    /// Advance the vcpu's instruction pointer to the next instruction
    void advance(void);
};
    
}

#endif
