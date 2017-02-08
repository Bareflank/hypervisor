- Kernels that have CONFIG_DEBUG_STACKOVERFLOW enabled will kernel oops when
  do_IRQ is called because Bareflank uses it's own stack, and this triggers
  the oops as stack_overflow_check thinks the stack has been overrun. The
  oops can be safely ignored, but the best solution at the moment is to
  disable this check from executing or don't use a kernrel with this enabled.
  This is seen on Fedora as installing the kernel source enables a debug kernel
  by default with this enabled.
- If core #0 starts successfully, but the next core fails to start, attempting
  to stop the hypervisor will triple fault the system. Partial failure states
  are not handled well in the driver, and thus such states should be considered
  corrupt.
