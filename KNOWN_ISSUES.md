- Kernels that have CONFIG_DEBUG_STACKOVERFLOW enabled will kernel oops when
  do_IRQ is called because Bareflank uses it's own stack, and this triggers
  the oops as stack_overflow_check thinks the stack has been overrun. The
  oops can be safely ignored, but the best solution at the moment is to
  disable this check from executing or don't use a kernrel with this enabled.
  This is seen on Fedora as installing the kernel source enables a debug kernel
  by default with this enabled.
- At the moment, GCC 6.1 appears to be broken with respect to exceptions. We
  have a hack in the unwinder to deal with this issue, but this hack should be
  removed in the future. Please see:
  https://gcc.gnu.org/bugzilla/show_bug.cgi?id=71978
- Although sleep appears to work with Windows while Bareflank is running,
  any attempt to stop Bareflank after the PC has been woken up results in
  a BSOD.
