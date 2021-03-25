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

#ifndef EFI_SHELL_PROTOCOL_H
#define EFI_SHELL_PROTOCOL_H

#include <efi/efi_device_path_protocol.h>
#include <efi/efi_shell_file_info.h>
#include <efi/efi_types.h>

/** @brief defines the GUID for EFI_SHELL_PROTOCOL_GUID */
#define EFI_SHELL_PROTOCOL_GUID                                                                    \
    {                                                                                              \
        0x6302d008, 0x7f9b, 0x4f30,                                                                \
        {                                                                                          \
            0x87, 0xac, 0x60, 0xc9, 0xfe, 0xf5, 0xda, 0x4e                                         \
        }                                                                                          \
    }

/** @brief prototype for _EFI_SHELL_PROTOCOL */
struct _EFI_SHELL_PROTOCOL;

/** @brief prototype for EFI_SHELL_PROTOCOL */
typedef struct _EFI_SHELL_PROTOCOL EFI_SHELL_PROTOCOL;

/**
 * <!-- description -->
 *   @brief Returns whether any script files are currently being processed.
 *
 * <!-- inputs/outputs -->
 *   @return Returns an EFI_STATUS
 */
typedef BOOLEAN(EFIAPI *EFI_SHELL_BATCH_IS_ACTIVE)(VOID);

/**
 * <!-- description -->
 *   @brief Closes the file handle.
 *
 * <!-- inputs/outputs -->
 *   @param FileHandle The file handle to be closed
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_CLOSE_FILE)(IN SHELL_FILE_HANDLE FileHandle);

/**
 * <!-- description -->
 *   @brief Creates a file or directory by name.
 *
 * <!-- inputs/outputs -->
 *   @param FileName Points to the null-terminated file path.
 *   @param FileAttribs The new file’s attributes. The different attributes
 *     are described in EFI_FILE_PROTOCOL.Open().
 *   @param FileHandle On return, points to the created file or directory’s
 *     handle.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_CREATE_FILE)(
    IN CONST CHAR16 *FileName, IN UINT64 FileAttribs, OUT SHELL_FILE_HANDLE *FileHandle);

/**
 * <!-- description -->
 *   @brief Deletes the file specified by the file handle.
 *
 * <!-- inputs/outputs -->
 *   @param FileHandle The file handle to delete.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_DELETE_FILE)(IN SHELL_FILE_HANDLE FileHandle);

/**
 * <!-- description -->
 *   @brief Deletes the file specified by the file handle.
 *
 * <!-- inputs/outputs -->
 *   @param FileName Points to the null-terminated file name.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_DELETE_FILE_BY_NAME)(IN CONST CHAR16 *FileName);

/**
 * <!-- description -->
 *   @brief Disables the page break output mode.
 *
 * <!-- inputs/outputs -->
 *   @return Returns an EFI_STATUS
 */
typedef VOID(EFIAPI *EFI_SHELL_DISABLE_PAGE_BREAK)(VOID);

/**
 * <!-- description -->
 *   @brief Enables the page break output mode.
 *
 * <!-- inputs/outputs -->
 *   @return Returns an EFI_STATUS
 */
typedef VOID(EFIAPI *EFI_SHELL_ENABLE_PAGE_BREAK)(VOID);

/**
 * <!-- description -->
 *   @brief Execute the command line.
 *
 * <!-- inputs/outputs -->
 *   @param ParentImageHandle A handle of the image that is executing the
 *     specified command line.
 *   @param CommandLine Points to the null-terminated UCS-2 encoded string
 *     containing the command line. If NULL then the command-line will be
 *     empty.
 *   @param Environment Points to a null-terminated array of environment
 *     variables with the format ‘x=y’, where x is the environment variable
 *     name and y is the value. If this is NULL, then the current shell
 *     environment is used.
 *   @param ErrorCode Points to the status code returned by the command.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_EXECUTE)(
    IN EFI_HANDLE *ParentImageHandle,
    IN CHAR16 *CommandLine OPTIONAL,
    IN CHAR16 **Environment OPTIONAL,
    OUT EFI_STATUS *StatusCode OPTIONAL);

/**
 * <!-- description -->
 *   @brief Find files that match a specified pattern.
 *
 * <!-- inputs/outputs -->
 *   @param FilePattern Points to a null-terminated shell file path,
 *     including wildcards.
 *   @param FileList On return, points to the start of a file list containing
 *     the names of all matching files or else points to NULL if no matching
 *     files were found.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_FIND_FILES)(
    IN CONST CHAR16 *FilePattern, OUT EFI_SHELL_FILE_INFO **FileList);

/**
 * <!-- description -->
 *   @brief Find all files in a specified directory.
 *
 * <!-- inputs/outputs -->
 *   @param FileDirHandle Handle of the directory to search.
 *   @param FileList On return, points to the list of files in the directory
 *     or NULL if there are no files in the directory.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_FIND_FILES_IN_DIR)(
    IN SHELL_FILE_HANDLE FileDirHandle, OUT EFI_SHELL_FILE_INFO **FileList);

/**
 * <!-- description -->
 *   @brief Flushes data back to a device
 *
 * <!-- inputs/outputs -->
 *   @param FileHandle The handle of the file to flush.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_FLUSH_FILE)(IN SHELL_FILE_HANDLE FileHandle);

/**
 * <!-- description -->
 *   @brief Frees the file list.
 *
 * <!-- inputs/outputs -->
 *   @param FileList The file list to free. Type EFI_SHELL_FILE_INFO is
 *     defined in OpenFileList()
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_FREE_FILE_LIST)(IN EFI_SHELL_FILE_INFO **FileList);

/**
 * <!-- description -->
 *   @brief Retrieves a shell command alias.
 *
 * <!-- inputs/outputs -->
 *   @param Alias Points to the null-terminated alias. If Alias is not NULL,
 *     this function returns the associated null-terminated command. If Alias
 *     is NULL, this function returns a ‘;’ delimited list of all the defined
 *     aliases (e.g. ReturnedData = “md;rd;cp;mfp”) that is null-terminated.
 *   @param Volatile If the return value is not NULL and Alias is not NULL,
 *     the Volatile parameter being TRUE indicates that the Alias is stored
 *     in a volatile fashion. If the return value is not NULL and Alias is
 *     not NULL, the Volatile parameter being FALSE indicates that the Alias
 *     is stored in a non-volatile fashion. For all other situations, this
 *     output parameter must be ignored.
 *   @return Returns an EFI_STATUS
 */
typedef CONST
    CHAR16 *(EFIAPI *EFI_SHELL_GET_ALIAS)(IN CONST CHAR16 *Alias, OUT BOOLEAN *Volatile OPTIONAL);

/**
 * <!-- description -->
 *   @brief Returns the current directory on the specified device.
 *
 * <!-- inputs/outputs -->
 *   @param FileSystemMapping A pointer to the file system mapping. If NULL,
 *     then the current working directory is returned.
 *   @return Returns an EFI_STATUS
 */
typedef CONST CHAR16 *(EFIAPI *EFI_SHELL_GET_CUR_DIR)(IN CONST CHAR16 *FileSystemMapping OPTIONAL);

/** @brief n/a */
typedef UINT32 EFI_DEVICE_NAME_FLAGS;
/** @brief n/a */
#define EFI_DEVICE_NAME_USE_COMPONENT_NAME 0x00000001
/** @brief n/a */
#define EFI_DEVICE_NAME_USE_DEVICE_PATH 0x00000002

/**
 * <!-- description -->
 *   @brief Gets the name of the device specified by the device handle.
 *
 * <!-- inputs/outputs -->
 *   @param DeviceHandle The handle of the device.
 *   @param Flags Determines the possible sources of component names. See
 *     “Related Definitions” below for more information.
 *   @param Language A pointer to the language specified for the device name,
 *     in the same format as described in the UEFI specification, Appendix M
 *   @param BestDeviceName On return, points to the callee-allocated
 *     null-terminated name of the device. If no device name could be found,
 *     points to NULL. The name must be freed by the caller.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS (*EFI_SHELL_GET_DEVICE_NAME)(
    IN EFI_HANDLE DeviceHandle,
    IN EFI_DEVICE_NAME_FLAGS Flags,
    IN CHAR8 *Language,
    OUT CHAR16 **BestDeviceName);

/**
 * <!-- description -->
 *   @brief Gets the device path from the mapping.
 *
 * <!-- inputs/outputs -->
 *   @param Mapping A pointer to the mapping.
 *   @return Returns an EFI_STATUS
 */
typedef CONST EFI_DEVICE_PATH_PROTOCOL *(EFIAPI *EFI_SHELL_GET_DEVICE_PATH_FROM_MAP)(
    IN CONST CHAR16 *Mapping);

/**
 * <!-- description -->
 *   @brief Converts a file system style name to a device path.
 *
 * <!-- inputs/outputs -->
 *   @param Path The pointer to the path.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_DEVICE_PATH_PROTOCOL *(EFIAPI *EFI_SHELL_GET_DEVICE_PATH_FROM_FILE_PATH)(
    IN CONST CHAR16 *Path);

/**
 * <!-- description -->
 *   @brief Gets the environment variable or list of environment variables.
 *
 * <!-- inputs/outputs -->
 *   @param Name A pointer to the environment variable name. If Name is NULL,
 *     then the function will return all of the defined shell environment
 *     variables. In the case where multiple environment variables are being
 *     returned, each variable will be terminated by a NULL,and the list will
 *     be terminated by a double NULL.
 *   @return Returns an EFI_STATUS
 */
typedef CONST CHAR16 *(EFIAPI *EFI_SHELL_GET_ENV)(IN CONST CHAR16 *Name);

/**
 * <!-- description -->
 *   @brief Gets the environment variable and Attributes, or list of
 *     environment variables. Can be used instead of GetEnv().
 *
 * <!-- inputs/outputs -->
 *   @param Name A pointer to the environment variable name. If Name is NULL,
 *     then the function will return all of the defined shell environment
 *     variables. In the case where multiple environment variables are being
 *     returned, each variable will be terminated by a NULL, and the list
 *     will be terminated by a double NULL.
 *   @param Attributes If not NULL, a pointer to the returned attributes
 *     bitmask for the environment variable. In the case where Name is NULL,
 *     and multiple environment variables are being returned, Attributes is
 *     undefined.
 *   @return Returns an EFI_STATUS
 */
typedef CONST
    CHAR16 *(EFIAPI *EFI_SHELL_GET_ENV_EX)(IN CONST CHAR16 *Name, OUT UINT32 *Attributes OPTIONAL);

/**
 * <!-- description -->
 *   @brief Gets the file information from an open file handle.
 *
 * <!-- inputs/outputs -->
 *   @param FileHandle A file handle
 *   @return Returns an EFI_STATUS
 */
typedef EFI_FILE_INFO *(EFIAPI *EFI_SHELL_GET_FILE_INFO)(IN SHELL_FILE_HANDLE FileHandle);

/**
 * <!-- description -->
 *   @brief Converts a device path to a file system-style path.
 *
 * <!-- inputs/outputs -->
 *   @param Path The pointer to the device path.
 *   @return Returns an EFI_STATUS
 */
typedef CHAR16 *(EFIAPI *EFI_SHELL_GET_FILE_PATH_FROM_DEVICE_PATH)(
    IN CONST EFI_DEVICE_PATH_PROTOCOL *Path);

/**
 * <!-- description -->
 *   @brief Gets a file’s current position
 *
 * <!-- inputs/outputs -->
 *   @param FileHandle The file handle on which to get the current position.
 *   @param Position Byte position from the start of the file
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_GET_FILE_POSITION)(
    IN SHELL_FILE_HANDLE FileHandle, OUT UINT64 *Position);

/**
 * <!-- description -->
 *   @brief Gets the size of a file.
 *
 * <!-- inputs/outputs -->
 *   @param FileHandle The handle of the file.
 *   @param Size The size of this file.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_GET_FILE_SIZE)(
    IN SHELL_FILE_HANDLE FileHandle, OUT UINT64 *Size);

/**
 * <!-- description -->
 *   @brief Get the GUID value from a human readable name.
 *
 * <!-- inputs/outputs -->
 *   @param GuidName A pointer to the localized name for the GUID being queried.
 *   @param Guid A pointer to the GUID structure to be filled in.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_GET_GUID_FROM_NAME)(
    IN CONST CHAR16 *GuidName, OUT EFI_GUID *Guid);

/**
 * <!-- description -->
 *   @brief Get the human readable name for a GUID from the value.
 *
 * <!-- inputs/outputs -->
 *   @param Guid A pointer to the GUID being queried.
 *   @param GuidName A pointer to a pointer the localized to name for the GUID
 *     being requested.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_GET_GUID_NAME)(
    IN CONST EFI_GUID *Guid, OUT CONST CHAR16 **GuidName);

/**
 * <!-- description -->
 *   @brief Return help information about a specific command.
 *
 * <!-- inputs/outputs -->
 *   @param Command Points to the null-terminated UEFI Shell command name.
 *   @param Sections Points to the null-terminated comma-delimited section
 *     names to return. If NULL, then all sections will be returned.
 *   @param HelpText On return, points to a callee-allocated buffer containing
 *     all specified help text.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_GET_HELP_TEXT)(
    IN CONST CHAR16 *Command, IN CONST CHAR16 *Sections, OUT CHAR16 **HelpText);

/**
 * <!-- description -->
 *   @brief Gets one or more mapping entries that most closely matches the
 *     device path.
 *
 * <!-- inputs/outputs -->
 *   @param DevicePath On entry, points to a device path pointer. On exit,
 *     updates the pointer to point to the portion of the device path after
 *     the mapping.
 *   @return Returns an EFI_STATUS
 */
typedef CONST CHAR16 *(EFIAPI *EFI_SHELL_GET_MAP_FROM_DEVICE_PATH)(
    IN OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath);

/**
 * <!-- description -->
 *   @brief Gets the enable status of the page break output mode.
 *
 * <!-- inputs/outputs -->
 *   @return Returns an EFI_STATUS
 */
typedef BOOLEAN(EFIAPI *EFI_SHELL_GET_PAGE_BREAK)(VOID);

/**
 * <!-- description -->
 *   @brief Judges whether the active shell is the root shell.
 *
 * <!-- inputs/outputs -->
 *   @return Returns an EFI_STATUS
 */
typedef BOOLEAN(EFIAPI *EFI_SHELL_IS_ROOT_SHELL)(VOID);

/**
 * <!-- description -->
 *   @brief Opens a file or a directory by file name.
 *
 * <!-- inputs/outputs -->
 *   @param FileName Points to the null-terminated UCS-2 encoded file name.
 *   @param FileHandle On return, points to the file handle.
 *   @param OpenMode File open mode. Either EFI_FILE_MODE_READ or
 *     EFI_FILE_MODE_WRITE from section 12.4 of the UEFI Specification.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_OPEN_FILE_BY_NAME)(
    IN CONST CHAR16 *FileName, OUT SHELL_FILE_HANDLE *FileHandle, IN UINT64 OpenMode);

/**
 * <!-- description -->
 *   @brief Opens the files that match the path specified.
 *
 * <!-- inputs/outputs -->
 *   @param Path A pointer to the path string.
 *   @param OpenMode Specifies the mode used to open each file,
 *     EFI_FILE_MODE_READ or EFI_FILE_MODE_WRITE.
 *   @param FileList Points to the start of a list of files opened.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_OPEN_FILE_LIST)(
    IN CHAR16 *Path, IN UINT64 OpenMode, OUT EFI_SHELL_FILE_INFO **FileList);

/**
 * <!-- description -->
 *   @brief Opens the root directory of a device.
 *
 * <!-- inputs/outputs -->
 *   @param DevicePath Points to the device path corresponding to the device
 *     where the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL is installed.
 *   @param FileHandle On exit, points to the file handle corresponding to the
 *     root directory on the device.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_OPEN_ROOT)(
    IN EFI_DEVICE_PATH_PROTOCOL *DevicePath, OUT SHELL_FILE_HANDLE *FileHandle);

/**
 * <!-- description -->
 *   @brief Opens the root directory of a device on a handle
 *
 * <!-- inputs/outputs -->
 *   @param DeviceHandle The handle of the device that contains the volume.
 *   @param FileHandle On exit, points to the file handle corresponding to the
 *     root directory on the device.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_OPEN_ROOT_BY_HANDLE)(
    IN EFI_HANDLE DeviceHandle, OUT SHELL_FILE_HANDLE *FileHandle);

/**
 * <!-- description -->
 *   @brief Reads data from the file.
 *
 * <!-- inputs/outputs -->
 *   @param FileHandle The opened file handle for read
 *   @param ReadSize On input, the size of Buffer, in bytes. On output,
 *     the amount of data read.
 *   @param Buffer The buffer in which data is read.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_READ_FILE)(
    IN SHELL_FILE_HANDLE FileHandle, IN OUT UINTN *ReadSize, OUT VOID *Buffer);

/**
 * <!-- description -->
 *   @brief Register a GUID and a localized human readable name for it.
 *
 * <!-- inputs/outputs -->
 *   @param Guid A pointer to the GUID being registered.
 *   @param GuidName A pointer to the localized name for the GUID being
 *     registered.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_REGISTER_GUID_NAME)(
    IN CONST EFI_GUID *Guid, IN CONST CHAR16 *GuidName);

/**
 * <!-- description -->
 *   @brief Deletes the duplicate file names files in the given file list.
 *
 * <!-- inputs/outputs -->
 *   @param FileList A pointer to the first entry in the file list.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_REMOVE_DUP_IN_FILE_LIST)(IN EFI_SHELL_FILE_INFO **FileList);

/**
 * <!-- description -->
 *   @brief Changes a shell command alias.
 *
 * <!-- inputs/outputs -->
 *   @param Command Points to the null-terminated shell command or existing
 *     alias.
 *   @param Alias Points to the null-terminated alias for the shell command.
 *     If this is NULL, and Command refers to an alias, that alias will be
 *     deleted.
 *   @param Replace If TRUE and the alias already exists, then the existing
 *     alias will be replaced. If FALSE and the alias already exists, then
 *     the existing alias is unchanged and EFI_ACCESS_DENIED is returned.
 *   @param Volatile If TRUE, the Alias being set will be stored in a volatile
 *     fashion. If FALSE, the Alias will be stored in a nonvolatile fashion.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_SET_ALIAS)(
    IN CONST CHAR16 *Command, IN CONST CHAR16 *Alias, IN BOOLEAN Replace, IN BOOLEAN Volatile);

/**
 * <!-- description -->
 *   @brief Changes the current directory on the specified device.
 *
 * <!-- inputs/outputs -->
 *   @param FileSystem A pointer to the file system’s mapped name. If NULL,
 *     then the current working directory is changed.
 *   @param Dir Points to the null-terminated directory on the device
 *     specified by FileSystem.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_SET_CUR_DIR)(
    IN CONST CHAR16 *FileSystem OPTIONAL, IN CONST CHAR16 *Dir);

/**
 * <!-- description -->
 *   @brief Sets the environment variable.
 *
 * <!-- inputs/outputs -->
 *   @param Name Points to the null-terminated environment variable name.
 *   @param Value Points to the null-terminated environment variable value.
 *     If the value is an empty string then the environment variable is deleted.
 *   @param Volatile Indicates whether the variable is non-volatile (FALSE)
 *     or volatile (TRUE).
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_SET_ENV)(
    IN CONST CHAR16 *Name, IN CONST CHAR16 *Value, IN BOOLEAN Volatile);

/**
 * <!-- description -->
 *   @brief Sets the file information to an opened file handle.
 *
 * <!-- inputs/outputs -->
 *   @param FileHandle A file handle
 *   @param FileInfo A file handle
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_SET_FILE_INFO)(
    IN SHELL_FILE_HANDLE FileHandle, IN CONST EFI_FILE_INFO *FileInfo);

/**
 * <!-- description -->
 *   @brief Sets a file’s current position
 *
 * <!-- inputs/outputs -->
 *   @param FileHandle The file handle on which requested position will be set.
 *   @param Position The file handle on which requested position will be set.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_SET_FILE_POSITION)(
    IN SHELL_FILE_HANDLE FileHandle, IN UINT64 Position);

/**
 * <!-- description -->
 *   @brief Changes a shell device mapping.
 *
 * <!-- inputs/outputs -->
 *   @param DevicePath DevicePath
 *   @param Mapping Points to the null-terminated mapping for the device path.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_SET_MAP)(
    IN CONST EFI_DEVICE_PATH_PROTOCOL *DevicePath, IN CONST CHAR16 *Mapping);

/**
 * <!-- description -->
 *   @brief Writes data to the file.
 *
 * <!-- inputs/outputs -->
 *   @param FileHandle The opened file handle for writing.
 *   @param BufferSize On input, size of Buffer.
 *   @param Buffer The buffer in which data to write.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SHELL_WRITE_FILE)(
    IN SHELL_FILE_HANDLE FileHandle, IN OUT UINTN *BufferSize, OUT VOID *Buffer);

/**
 * @struct EFI_SHELL_PROTOCOL
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_SHELL_PROTOCOL struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Shell_2_2.pdf
 */
typedef struct _EFI_SHELL_PROTOCOL
{
    /**
     * @brief Causes the shell to parse and execute the command line.
     */
    EFI_SHELL_EXECUTE Execute;

    /**
     * @brief Gets the environment variable.
     */
    EFI_SHELL_GET_ENV GetEnv;

    /**
     * @brief Changes a specific environment variable.
     */
    EFI_SHELL_SET_ENV SetEnv;

    /**
     * @brief Retrieves the alias for a specific shell command.
     */
    EFI_SHELL_GET_ALIAS GetAlias;

    /**
     * @brief Adds or removes the alias for a specific shell command.
     */
    EFI_SHELL_SET_ALIAS SetAlias;

    /**
     * @brief n/a
     */
    EFI_SHELL_GET_HELP_TEXT GetHelpText;

    /**
     * @brief Returns the mapping that corresponds to a particular device path.
     */
    EFI_SHELL_GET_DEVICE_PATH_FROM_MAP GetDevicePathFromMap;

    /**
     * @brief Converts a file path to a device path, where all mappings have
     *   been replaced with the corresponding device paths.
     */
    EFI_SHELL_GET_MAP_FROM_DEVICE_PATH GetMapFromDevicePath;

    /**
     * @brief Converts a file path to a device path, where all mappings have
     *   been replaced with the corresponding device paths.
     */
    EFI_SHELL_GET_DEVICE_PATH_FROM_FILE_PATH GetDevicePathFromFilePath;

    /**
     * @brief Converts a device path to a file path, where the portion of the
     *   device path corresponding to one of the mappings is replaced with that
     *   mapping.
     */
    EFI_SHELL_GET_FILE_PATH_FROM_DEVICE_PATH GetFilePathFromDevicePath;

    /**
     * @brief Creates, updates or deletes a mapping between a device and a
     *   device path.
     */
    EFI_SHELL_SET_MAP SetMap;

    /**
     * @brief Returns the current directory on a device.
     */
    EFI_SHELL_GET_CUR_DIR GetCurDir;

    /**
     * @brief Changes the current directory on a device.
     */
    EFI_SHELL_SET_CUR_DIR SetCurDir;

    /**
     * @brief Opens the files that match the path pattern specified.
     */
    EFI_SHELL_OPEN_FILE_LIST OpenFileList;

    /**
     * @brief Frees the file list that created by OpenFileList().
     */
    EFI_SHELL_FREE_FILE_LIST FreeFileList;

    /**
     * @brief Deletes the duplicate files in the given file list.
     */
    EFI_SHELL_REMOVE_DUP_IN_FILE_LIST RemoveDupInFileList;

    /**
     * @brief Returns whether any script files are currently being processed.
     */
    EFI_SHELL_BATCH_IS_ACTIVE BatchIsActive;

    /**
     * @brief Judges whether the active Shell is the root shell.
     */
    EFI_SHELL_IS_ROOT_SHELL IsRootShell;

    /**
     * @brief Enables the page break output mode.
     */
    EFI_SHELL_ENABLE_PAGE_BREAK EnablePageBreak;

    /**
     * @brief Disables the page break output mode.
     */
    EFI_SHELL_DISABLE_PAGE_BREAK DisablePageBreak;

    /**
     * @brief Gets the enable status of the page break output mode.
     */
    EFI_SHELL_GET_PAGE_BREAK GetPageBreak;

    /**
     * @brief Gets the name of the device specified by the device handle.
     */
    EFI_SHELL_GET_DEVICE_NAME GetDeviceName;

    /**
     * @brief Return information about a specific file handle.
     */
    EFI_SHELL_GET_FILE_INFO GetFileInfo;

    /**
     * @brief Change information about a specific file handle.
     */
    EFI_SHELL_SET_FILE_INFO SetFileInfo;

    /**
     * @brief Given a file name, open a file and return a file handle.
     */
    EFI_SHELL_OPEN_FILE_BY_NAME OpenFileByName;

    /**
     * @brief Close an open file.
     */
    EFI_SHELL_CLOSE_FILE CloseFile;

    /**
     * @brief Create a new file.
     */
    EFI_SHELL_CREATE_FILE CreateFile;

    /**
     * @brief Read data from a file.
     */
    EFI_SHELL_READ_FILE ReadFile;

    /**
     * @brief Write data to a file.
     */
    EFI_SHELL_WRITE_FILE WriteFile;

    /**
     * @brief Delete a file.
     */
    EFI_SHELL_DELETE_FILE DeleteFile;

    /**
     * @brief Delete a file by name.
     */
    EFI_SHELL_DELETE_FILE_BY_NAME DeleteFileByName;

    /**
     * @brief Change the current read/write position within a file.
     */
    EFI_SHELL_GET_FILE_POSITION GetFilePosition;

    /**
     * @brief Return the current read/write position within a file.
     */
    EFI_SHELL_SET_FILE_POSITION SetFilePosition;

    /**
     * @brief Write all buffered data to a file.
     */
    EFI_SHELL_FLUSH_FILE FlushFile;

    /**
     * @brief Return all files that match a pattern in a file list.
     */
    EFI_SHELL_FIND_FILES FindFiles;

    /**
     * @brief Return all files in a specified directory in a file list.
     */
    EFI_SHELL_FIND_FILES_IN_DIR FindFilesInDir;

    /**
     * @brief Return the size of a file.
     */
    EFI_SHELL_GET_FILE_SIZE GetFileSize;

    /**
     * @brief Return the root directory of a file system.
     */
    EFI_SHELL_OPEN_ROOT OpenRoot;

    /**
     * @brief Return the root directory of a file system on a particular handle.
     */
    EFI_SHELL_OPEN_ROOT_BY_HANDLE OpenRootByHandle;

    /**
     * @brief Event signaled by the UEFI Shell when the user presses CTRL-C
     *   to indicate that the current UEFI Shell command execution should be
     *   interrupted.
     */
    EFI_EVENT ExecutionBreak;

    /**
     * @brief This field contains the EFI_SHELL_MAJOR_VERSION value referenced
     *   in the related definitions section. This will define what functions
     *   are available in the protocol.
     */
    UINT32 MajorVersion;

    /**
     * @brief This field contains the EFI_SHELL_MINOR_VERSION value referenced
     *   in the related definitions section. This will define what functions
     *   are available in the protocol.
     */
    UINT32 MinorVersion;

    /**
     * @brief Register a GUID and a localized human readable name for it.
     */
    EFI_SHELL_REGISTER_GUID_NAME RegisterGuidName;

    /**
     * @brief Get the human readable name for a GUID from the value.
     */
    EFI_SHELL_GET_GUID_NAME GetGuidName;

    /**
     * @brief Get the GUID value from a human readable name.
     */
    EFI_SHELL_GET_GUID_FROM_NAME GetGuidFromName;

    /**
     * @brief Gets the environment variable and Attributes.
     */
    EFI_SHELL_GET_ENV_EX GetEnvEx;

} EFI_SHELL_PROTOCOL;

#endif
