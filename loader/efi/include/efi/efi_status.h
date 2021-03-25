/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef EFI_STATUS_CODES_H
#define EFI_STATUS_CODES_H

#include <efi/efi_types.h>

/** @brief Status code. Type UINTN. */
typedef UINTN EFI_STATUS;

/** used to construct an error code */
#define EFIERR(a) (((EFI_STATUS)0x8000000000000000) | ((EFI_STATUS)a))
/** used to construct a warning code */
#define EFIWRN(a) ((EFI_STATUS)a)

/**
 * @brief The operation completed successfully.
 */
#define EFI_SUCCESS ((EFI_STATUS)0)

/**
 * @brief The image failed to load.
 */
#define EFI_LOAD_ERROR EFIERR(1)

/**
 * @brief A parameter was incorrect.
 */
#define EFI_INVALID_PARAMETER EFIERR(2)

/**
 * @brief The operation is not supported.
 */
#define EFI_UNSUPPORTED EFIERR(3)

/**
 * @brief The buffer was not the proper size for the request.
 */
#define EFI_BAD_BUFFER_SIZE EFIERR(4)

/**
 * @brief The buffer is not large enough to hold the requested data. The
 *   required buffer size is returned in the appropriate parameter when this
 *   error occurs.
 */
#define EFI_BUFFER_TOO_SMALL EFIERR(5)

/**
 * @brief There is no data pending upon return.
 */
#define EFI_NOT_READY EFIERR(6)

/**
 * @brief The physical device reported an error while attempting the operation.
 */
#define EFI_DEVICE_ERROR EFIERR(7)

/**
 * @brief The device cannot be written to.
 */
#define EFI_WRITE_PROTECTED EFIERR(8)

/**
 * @brief A resource has run out.
 */
#define EFI_OUT_OF_RESOURCES EFIERR(9)

/**
 * @brief An inconstancy was detected on the file system causing the
 *   operating to fail.
 */
#define EFI_VOLUME_CORRUPTED EFIERR(10)

/**
 * @brief There is no more space on the file system.
 */
#define EFI_VOLUME_FULL EFIERR(11)

/**
 * @brief The device does not contain any medium to perform the operation.
 */
#define EFI_NO_MEDIA EFIERR(12)

/**
 * @brief The medium in the device has changed since the last access.
 */
#define EFI_MEDIA_CHANGED EFIERR(13)

/**
 * @brief The item was not found.
 */
#define EFI_NOT_FOUND EFIERR(14)

/**
 * @brief Access was denied.
 */
#define EFI_ACCESS_DENIED EFIERR(15)

/**
 * @brief The server was not found or did not respond to the request.
 */
#define EFI_NO_RESPONSE EFIERR(16)

/**
 * @brief A mapping to a device does not exist.
 */
#define EFI_NO_MAPPING EFIERR(17)

/**
 * @brief The timeout time expired.
 */
#define EFI_TIMEOUT EFIERR(18)

/**
 * @brief The protocol has not been started.
 */
#define EFI_NOT_STARTED EFIERR(19)

/**
 * @brief The protocol has already been started.
 */
#define EFI_ALREADY_STARTED EFIERR(20)

/**
 * @brief The operation was aborted.
 */
#define EFI_ABORTED EFIERR(21)

/**
 * @brief An ICMP error occurred during the network operation.
 */
#define EFI_ICMP_ERROR EFIERR(22)

/**
 * @brief A TFTP error occurred during the network operation.
 */
#define EFI_TFTP_ERROR EFIERR(23)

/**
 * @brief A protocol error occurred during the network operation.
 */
#define EFI_PROTOCOL_ERROR EFIERR(24)

/**
 * @brief The function encountered an internal version that was incompatible
 *   with a version requested by the caller.
 */
#define EFI_INCOMPATIBLE_VERSION EFIERR(25)

/**
 * @brief The function was not performed due to a security violation.
 */
#define EFI_SECURITY_VIOLATION EFIERR(26)

/**
 * @brief A CRC error was detected.
 */
#define EFI_CRC_ERROR EFIERR(27)

/**
 * @brief Beginning or end of media was reached
 */
#define EFI_END_OF_MEDIA EFIERR(28)

/**
 * @brief The end of the file was reached.
 */
#define EFI_END_OF_FILE EFIERR(31)

/**
 * @brief The language specified was invalid.
 */
#define EFI_INVALID_LANGUAGE EFIERR(32)

/**
 * @brief The security status of the data is unknown or compromised and the
 *   data must be updated or replaced to restore a valid security status.
 */
#define EFI_COMPROMISED_DATA EFIERR(33)

/**
 * @brief There is an address conflict address allocation
 */
#define EFI_IP_ADDRESS_CONFLICT EFIERR(34)

/**
 * @brief A HTTP error occurred during the network operation.
 */
#define EFI_HTTP_ERROR EFIERR(35)

/**
 * @brief The string contained one or more characters that the device could
 *   not render and were skipped.
 */
#define EFI_WARN_UNKNOWN_GLYPH EFIWRN(1)

/**
 * @brief The handle was closed, but the file was not deleted.
 */
#define EFI_WARN_DELETE_FAILURE EFIWRN(2)

/**
 * @brief The handle was closed, but the data to the file was not flushed
 *   properly.
 */
#define EFI_WARN_WRITE_FAILURE EFIWRN(3)

/**
 * @brief The resulting buffer was too small, and the data was truncated
 *   to the buffer size.
 */
#define EFI_WARN_BUFFER_TOO_SMALL EFIWRN(4)

/**
 * @brief The data has not been updated within the timeframe set by local
 *   policy for this type of data
 */
#define EFI_WARN_STALE_DATA EFIWRN(5)

/**
 * @brief The resulting buffer contains UEFI-compliant file system.
 */
#define EFI_WARN_FILE_SYSTEM EFIWRN(6)

/**
 * @brief The operation will be processed across a system reset.
 */
#define EFI_WARN_RESET_REQUIRED EFIWRN(7)

/**
 * @brief used to determine if a function has returned an error
 */
#define EFI_ERROR(a) (a != EFI_SUCCESS)

#endif
