#ifndef ABI_CONVERSION_H
#define ABI_CONVERSION_H

/**
 * Entry Point
 *
 * This typedef defines what an entry point is. All functions that are to
 * be called using the ELF loader should conform to this prototype.
 *
 * @param arg the argument you wish to pass to the entry point
 * @return the return value of the entry point
 */
typedef void * (*entry_point_t)(void *arg);

/**
 * Microsoft 64bit ABI to System V 64bit ABI
 *
 * With the switch to 64bit, there are really only two different types of
 * ABIs that can be used. MS x64 and System V 64bit ABI. Since the cross
 * compiled code is compiled using System V, the code that is compiled using
 * MS x64 that needs to call into the cross-compiled code needs a means to
 * swich from one calling convention to another. This function executes an
 * entry point, while performing this conversion.
 *
 * @param entry_point the entry point you wish to execute
 * @param arg the argument you wish to pass to the entry point
 * @return the return value of the entry point
 */
typedef void * (*exec_ms64tosv64_t)(void *entry_point, void *arg);

#endif
