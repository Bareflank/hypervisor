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

#ifndef EFI_FILE_PROTOCOL_H
#define EFI_FILE_PROTOCOL_H

#include "efi_file_info.h"
#include "efi_file_io_token.h"
#include "efi_guid.h"
#include "efi_status.h"
#include "efi_types.h"

/** @brief defines the Revision Number 1 for EFI_FILE_PROTOCOL */
#define EFI_FILE_PROTOCOL_REVISION 0x00010000
/** @brief defines the Revision Number 2 for EFI_FILE_PROTOCOL */
#define EFI_FILE_PROTOCOL_REVISION2 0x00020000
/** @brief defines the lastest Revision Number for EFI_FILE_PROTOCOL */
#define EFI_FILE_PROTOCOL_LATEST_REVISION EFI_FILE_PROTOCOL_REVISION2

/** @brief prototype for _EFI_FILE_PROTOCOL */
struct _EFI_FILE_PROTOCOL;

/** @brief prototype for EFI_FILE_PROTOCOL */
typedef struct _EFI_FILE_PROTOCOL EFI_FILE_PROTOCOL;

/** @brief Defined in EFI_FILE_PROTOCOL.Open() */
#define EFI_FILE_MODE_READ 0x0000000000000001
/** @brief Defined in EFI_FILE_PROTOCOL.Open() */
#define EFI_FILE_MODE_WRITE 0x0000000000000002
/** @brief Defined in EFI_FILE_PROTOCOL.Open() */
#define EFI_FILE_MODE_CREATE 0x8000000000000000

/** @brief Defined in EFI_FILE_PROTOCOL.Open() */
#define EFI_FILE_READ_ONLY 0x0000000000000001
/** @brief Defined in EFI_FILE_PROTOCOL.Open() */
#define EFI_FILE_HIDDEN 0x0000000000000002
/** @brief Defined in EFI_FILE_PROTOCOL.Open() */
#define EFI_FILE_SYSTEM 0x0000000000000004
/** @brief Defined in EFI_FILE_PROTOCOL.Open() */
#define EFI_FILE_RESERVED 0x0000000000000008
/** @brief Defined in EFI_FILE_PROTOCOL.Open() */
#define EFI_FILE_DIRECTORY 0x0000000000000010
/** @brief Defined in EFI_FILE_PROTOCOL.Open() */
#define EFI_FILE_ARCHIVE 0x0000000000000020
/** @brief Defined in EFI_FILE_PROTOCOL.Open() */
#define EFI_FILE_VALID_ATTR 0x0000000000000037

/** @brief Defines the attributes for all non-create modes */
#define EFI_FILE_NONE 0x0000000000000000

/**
 * <!-- description -->
 *   @brief Opens a new file relative to the source file’s location.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle to the source location. This would typically be an open handle
 *     to a directory. See the type EFI_FILE_PROTOCOL description.
 *   @param NewHandle A pointer to the location to return the opened handle
 *     for the new file. See the type EFI_FILE_PROTOCOL description.
 *   @param FileName The Null-terminated string of the name of the file to be
 *     opened. The file name may contain the following path modifiers: “\”,
 *     “.”, and “..”.
 *   @param OpenMode The mode to open the file. The only valid combinations
 *     that the file may be opened with are: Read, Read/Write, or
 *     Create/Read/Write.
 *   @param Attributes Only valid for EFI_FILE_MODE_CREATE, in which case these
 *     are the attribute bits for the newly created file
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_OPEN)(
    IN EFI_FILE_PROTOCOL *This,
    OUT EFI_FILE_PROTOCOL **NewHandle,
    IN CHAR16 *FileName,
    IN UINT64 OpenMode,
    IN UINT64 Attributes);

/**
 * <!-- description -->
 *   @brief Closes a specified file handle.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle to close. See the type EFI_FILE_PROTOCOL description.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_CLOSE)(IN EFI_FILE_PROTOCOL *This);

/**
 * <!-- description -->
 *   @brief Closes and deletes a file.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the handle
 *     to the file to delete. See the type EFI_FILE_PROTOCOL description.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_DELETE)(IN EFI_FILE_PROTOCOL *This);

/**
 * <!-- description -->
 *   @brief Reads data from a file.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle to read data from. See the type EFI_FILE_PROTOCOL description.
 *   @param BufferSize On input, the size of the Buffer. On output, the amount
 *     of data returned in Buffer. In both cases, the size is measured in
 *     bytes.
 *   @param Buffer The buffer into which the data is read.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_READ)(
    IN EFI_FILE_PROTOCOL *This, IN OUT UINTN *BufferSize, OUT VOID *Buffer);

/**
 * <!-- description -->
 *   @brief Writes data to a file.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle to write data to. See the type EFI_FILE_PROTOCOL description.
 *   @param BufferSize On input, the size of the Buffer. On output, the amount
 *     of data actually written. In both cases, the size is measured in bytes.
 *   @param Buffer The buffer of data to write.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_WRITE)(
    IN EFI_FILE_PROTOCOL *This, IN OUT UINTN *BufferSize, IN VOID *Buffer);

/**
 * <!-- description -->
 *   @brief Returns a file’s current position.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle to get the current position on. See the type EFI_FILE_PROTOCOL
 *     description.
 *   @param Position The address to return the file’s current position value.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_GET_POSITION)(IN EFI_FILE_PROTOCOL *This, OUT UINT64 *Position);

/**
 * <!-- description -->
 *   @brief Sets a file’s current position.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the he
 *     file handle to set the requested position on. See the type
 *     EFI_FILE_PROTOCOL description.
 *   @param Position The byte position from the start of the file to set.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_SET_POSITION)(IN EFI_FILE_PROTOCOL *This, IN UINT64 Position);

/**
 * <!-- description -->
 *   @brief Returns information about a file.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle the requested information is for. See the type EFI_FILE_PROTOCOL
 *     description.
 *   @param InformationType The type identifier for the information being
 *     requested. Type EFI_GUID is defined on page 176. See the EFI_FILE_INFO
 *     and EFI_FILE_SYSTEM_INFO descriptions for the related GUID definitions.
 *   @param BufferSize On input, the size of Buffer. On output, the amount of
 *     data returned in Buffer. In both cases, the size is measured in bytes.
 *   @param Buffer A pointer to the data buffer to return. The buffer’s type is
 *     indicated by InformationType.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_GET_INFO)(
    IN EFI_FILE_PROTOCOL *This,
    IN EFI_GUID *InformationType,
    IN OUT UINTN *BufferSize,
    OUT VOID *Buffer);

/**
 * <!-- description -->
 *   @brief Sets information about a file.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle the information is for. See the type EFI_FILE_PROTOCOL
 *     description.
 *   @param InformationType The type identifier for the information being set.
 *     Type EFI_GUID is defined in page 176. See the EFI_FILE_INFO and
 *     EFI_FILE_SYSTEM_INFO descriptions in this section for the related GUID
 *     definitions.
 *   @param BufferSize The size, in bytes, of Buffer.
 *   @param Buffer A pointer to the data buffer to write. The buffer’s type is
 *     indicated by InformationType.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_SET_INFO)(
    IN EFI_FILE_PROTOCOL *This, IN EFI_GUID *InformationType, IN UINTN BufferSize, IN VOID *Buffer);

/**
 * <!-- description -->
 *   @brief Flushes all modified data associated with a file to a device.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle to flush. See the type EFI_FILE_PROTOCOL description.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_FLUSH)(IN EFI_FILE_PROTOCOL *This);

/**
 * <!-- description -->
 *   @brief Opens a new file relative to the source directory’s location.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle to read data from. See the type EFI_FILE_PROTOCOL description.
 *   @param NewHandle A pointer to the location to return the opened handle for
 *     the new file. See the type EFI_FILE_PROTOCOL description. For
 *     asynchronous I/O, this pointer must remain valid for the duration of the
 *     asynchronous operation.
 *   @param FileName The Null-terminated string of the name of the file to be
 *     opened. The file name may contain the following path modifiers: “\”,
 *     “.”, and “..”.
 *   @param OpenMode The mode to open the file. The only valid combinations
 *     that the file may be opened with are: Read, Read/Write, or
 *     Create/Read/Write.
 *   @param Attributes Only valid for EFI_FILE_MODE_CREATE, in which case these
 *     are the attribute bits for the
 *   @param Token A pointer to the token associated with the transaction.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_OPEN_EX)(
    IN EFI_FILE_PROTOCOL *This,
    OUT EFI_FILE_PROTOCOL **NewHandle,
    IN CHAR16 *FileName,
    IN UINT64 OpenMode,
    IN UINT64 Attributes,
    IN OUT EFI_FILE_IO_TOKEN *Token);

/**
 * <!-- description -->
 *   @brief Reads data from a file.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle to read data from. See the type EFI_FILE_PROTOCOL description.
 *   @param Token A pointer to the token associated with the transaction.
 *     Type EFI_FILE_IO_TOKEN is defined in "Related Definitions" below.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_READ_EX)(
    IN EFI_FILE_PROTOCOL *This, IN OUT EFI_FILE_IO_TOKEN *Token);

/**
 * <!-- description -->
 *   @brief Writes data to a file.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle to write data to. See the type EFI_FILE_PROTOCOL description.
 *   @param Token A pointer to the token associated with the transaction.
 *     Type EFI_FILE_IO_TOKEN is defined in "Related Definitions" above.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_WRITE_EX)(
    IN EFI_FILE_PROTOCOL *This, IN OUT EFI_FILE_IO_TOKEN *Token);

/**
 * <!-- description -->
 *   @brief Flushes all modified data associated with a file to a device.
 *
 * <!-- inputs/outputs -->
 *   @param This A pointer to the EFI_FILE_PROTOCOL instance that is the file
 *     handle to flush. See the type EFI_FILE_PROTOCOL description.
 *   @param Token A pointer to the token associated with the transaction.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FILE_FLUSH_EX)(
    IN EFI_FILE_PROTOCOL *This, IN OUT EFI_FILE_IO_TOKEN *Token);

/**
 * @struct EFI_FILE_PROTOCOL
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_FILE_PROTOCOL struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct _EFI_FILE_PROTOCOL
{
    /**
     * @brief The version of the EFI_FILE_PROTOCOL interface. The version
     *   specified by this specification is EFI_FILE_PROTOCOL_LATEST_REVISION.
     *   Future versions are required to be backward compatible to version 1.0.
     */
    UINT64 Revision;

    /**
     * @brief Opens or creates a new file. See the Open() function description.
     */
    EFI_FILE_OPEN Open;

    /**
     * @brief Closes the current file handle. See the Close() function
     *   description.
     */
    EFI_FILE_CLOSE Close;

    /**
     * @brief Deletes a file. See the Delete() function description.
     */
    EFI_FILE_DELETE Delete;

    /**
     * @brief Reads bytes from a file. See the Read() function description.
     */
    EFI_FILE_READ Read;

    /**
     * @brief Writes bytes to a file. See the Write() function description.
     */
    EFI_FILE_WRITE Write;

    /**
     * @brief Returns the current file position. See the GetPosition() function
     *   description.
     */
    EFI_FILE_GET_POSITION GetPosition;

    /**
     * @brief Sets the current file position. See the SetPosition() function
     *   description.
     */
    EFI_FILE_SET_POSITION SetPosition;

    /**
     * @brief Gets the requested file or volume information. See the GetInfo()
     *   function description.
     */
    EFI_FILE_GET_INFO GetInfo;

    /**
     * @brief Sets the requested file information. See the SetInfo() function
     *   description.
     */
    EFI_FILE_SET_INFO SetInfo;

    /**
     * @brief Flushes all modified data associated with the file to the device.
     *   See the Flush() function description.
     */
    EFI_FILE_FLUSH Flush;

    /**
     * @brief Opens a new file relative to the source directory’s location.
     */
    EFI_FILE_OPEN_EX OpenEx;

    /**
     * @brief Reads data from a file.
     */
    EFI_FILE_READ_EX ReadEx;

    /**
     * @brief Writes data to a file.
     */
    EFI_FILE_WRITE_EX WriteEx;

    /**
     * @brief Flushes all modified data associated with a file to a device.
     */
    EFI_FILE_FLUSH_EX FlushEx;

} EFI_FILE_PROTOCOL;

#endif
