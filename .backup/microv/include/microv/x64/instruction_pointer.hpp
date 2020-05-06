#ifndef MICROV_INSTRUCTION_POINTER_HPP
#define MICROV_INSTRUCTION_POINTER_HPP

#include <microv/vmexit_context.hpp>

namespace microv
{

/// @brief Set the given vmexit_context to advance the instruciton pointer to
///     on the next vmentry
///
/// @return 0 on success, non-0 on failure
void advance_instruction_pointer(vmexit_context &vc);

}

#endif
