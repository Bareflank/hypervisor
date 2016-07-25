- Kernels that have CONFIG_DEBUG_STACKOVERFLOW enabled will kernel oops when
  do_IRQ is called because Bareflank uses it's own stack, and this triggers
  the oops as stack_overflow_check thinks the stack has been overrun. The
  oops can be safely ignored, but the best solution at the moment is to
  disable this check from executing or don't use a kernrel with this enabled.
  This is seen on Fedora as installing the kernel source enables a debug kernel
  by default with this enabled.
- Multi-Core is currently supported, but the code is not thread-safe. For this
  reason, the exit handler cannot allocate memory, which means that C++
  data structures should be pre-allocated, and debugging should not be used as
  std::cout allocates memory when creating strings. If any of this is needed,
  Multi-Core should be disabled my setting MAX_VCPUS to 1, and then
  recompiling. This limitation will be addressed in version 1.2 or higher.
  We plan to add std::mutex support which will provide multi-threading support
  in the future.
- At the moment, GCC 6.1 appears to be broken with respect to exceptions. We
  have a hack in the unwinder to deal with this issue, but this hack should be
  removed in the future. Please see:
  https://gcc.gnu.org/bugzilla/show_bug.cgi?id=71978
