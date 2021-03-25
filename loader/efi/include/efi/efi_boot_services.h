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

#ifndef EFI_BOOT_SERVICES_H
#define EFI_BOOT_SERVICES_H

#include <efi/efi_allocate_type.h>
#include <efi/efi_device_path_protocol.h>
#include <efi/efi_guid.h>
#include <efi/efi_interface_type.h>
#include <efi/efi_locate_search_type.h>
#include <efi/efi_memory_descriptor.h>
#include <efi/efi_memory_type.h>
#include <efi/efi_open_protocol_information_entry.h>
#include <efi/efi_status.h>
#include <efi/efi_table_header.h>
#include <efi/efi_timer_delay.h>
#include <efi/efi_types.h>

/** @brief Defines EFI_BOOT_SERVICES_SIGNATURE */
#define EFI_BOOT_SERVICES_SIGNATURE 0x56524553544f4f42
/** @brief Defines EFI_BOOT_SERVICES_REVISION */
#define EFI_BOOT_SERVICES_REVISION EFI_SPECIFICATION_VERSION

/** @brief Defined in EFI_BOOT_SERVICES.RaiseTPL() */
#define TPL_APPLICATION 4
/** @brief Defined in EFI_BOOT_SERVICES.RaiseTPL() */
#define TPL_CALLBACK 8
/** @brief Defined in EFI_BOOT_SERVICES.RaiseTPL() */
#define TPL_NOTIFY 16
/** @brief Defined in EFI_BOOT_SERVICES.RaiseTPL() */
#define TPL_HIGH_LEVEL 31

/**
 * <!-- description -->
 *   @brief Raises a task’s priority level and returns its previous level.
 *
 * <!-- inputs/outputs -->
 *   @param NewTpl The new task priority level. It must be greater than or
 *     equal to the current task priority level.
 *   @return Unlike other UEFI interface functions, EFI_BOOT_SERVICES.RaiseTPL()
 *     does not return a status code. Instead, it returns the previous task
 *     priority level, which is to be restored later with a matching call to
 *     RestoreTPL().
 */
typedef EFI_TPL(EFIAPI *EFI_RAISE_TPL)(IN EFI_TPL NewTpl);

/**
 * <!-- description -->
 *   @brief Restores a task’s priority level to its previous value.
 *
 * <!-- inputs/outputs -->
 *   @param OldTpl The previous task priority level to restore (the value from
 *     a previous, matching call to EFI_BOOT_SERVICES.RaiseTPL()). Type EFI_TPL
 *     is defined in the RaiseTPL() function description.
 */
typedef VOID(EFIAPI *EFI_RESTORE_TPL)(IN EFI_TPL OldTpl);

/**
 * <!-- description -->
 *   @brief Allocates memory pages from the system.
 *
 * <!-- inputs/outputs -->
 *   @param Type The type of allocation to perform.
 *   @param MemoryType The type of memory to allocate.
 *   @param Pages The number of contiguous 4 KiB pages to allocate.
 *   @param Memory Pointer to a physical address. On input, the way in which
 *     the address is used depends on the value of Type.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_ALLOCATE_PAGES)(
    IN EFI_ALLOCATE_TYPE Type,
    IN EFI_MEMORY_TYPE MemoryType,
    IN UINTN Pages,
    IN OUT EFI_PHYSICAL_ADDRESS *Memory);

/**
 * <!-- description -->
 *   @brief Frees memory pages.
 *
 * <!-- inputs/outputs -->
 *   @param Memory The base physical address of the pages to be freed.
 *     Type EFI_PHYSICAL_ADDRESS is defined in the
 *     EFI_BOOT_SERVICES.AllocatePages() function description.
 *   @param Pages The number of contiguous 4 KiB pages to free.
 *   @return Returns an EFI_STATUS
 */

typedef EFI_STATUS(EFIAPI *EFI_FREE_PAGES)(IN EFI_PHYSICAL_ADDRESS Memory, IN UINTN Pages);

/** @brief Defined in EFI_BOOT_SERVICES.GetMemoryMap() */
#define EFI_MEMORY_DESCRIPTOR_VERSION 1

/**
 * <!-- description -->
 *   @brief Returns the current memory map.
 *
 * <!-- inputs/outputs -->
 *   @param MemoryMapSize A pointer to the size, in bytes, of the MemoryMap
 *     buffer. On input, this is the size of the buffer allocated by the
 *     caller. On output, it is the size of the buffer returned by the firmware
 *     if the buffer was large enough, or the size of the buffer needed to
 *     contain the map if the buffer was too small.
 *   @param MemoryMap A pointer to the buffer in which firmware places the
 *     current memory map
 *   @param MapKey A pointer to the location in which firmware returns the
 *     key for the current memory map.
 *   @param DescriptorSize A pointer to the location in which firmware returns
 *     the size, in bytes, of an individual EFI_MEMORY_DESCRIPTOR.
 *   @param DescriptorVersion A pointer to the location in which firmware
 *     returns the version number associated with the EFI_MEMORY_DESCRIPTOR.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_GET_MEMORY_MAP)(
    IN OUT UINTN *MemoryMapSize,
    IN OUT EFI_MEMORY_DESCRIPTOR *MemoryMap,
    OUT UINTN *MapKey,
    OUT UINTN *DescriptorSize,
    OUT UINT32 *DescriptorVersion);

/**
 * <!-- description -->
 *   @brief Allocates pool memory.
 *
 * <!-- inputs/outputs -->
 *   @param PoolType The type of pool to allocate. Type EFI_MEMORY_TYPE is
 *     defined in the EFI_BOOT_SERVICES.AllocatePages() function description.
 *     PoolType values in the range 0x70000000..0x7FFFFFFF are reserved for
 *     OEM use. PoolType values in the range 0x80000000..0xFFFFFFFF are
 *     reserved for use by UEFI OS loaders that are provided by operating
 *     system vendors.
 *   @param Size The number of bytes to allocate from the pool.
 *   @param Buffer A pointer to a pointer to the allocated buffer if the call
 *     succeeds; undefined otherwise.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_ALLOCATE_POOL)(
    IN EFI_MEMORY_TYPE PoolType, IN UINTN Size, OUT VOID **Buffer);

/**
 * <!-- description -->
 *   @brief Returns pool memory to the system.
 *
 * <!-- inputs/outputs -->
 *   @param Buffer Pointer to the buffer to free.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_FREE_POOL)(IN VOID *Buffer);

/**
 * @brief The event is a timer event and may be passed to
 *   EFI_BOOT_SERVICES.SetTimer(). Note that timers only function during boot
 *   services time.
 */
#define EVT_TIMER 0x80000000

/**
 * @brief The event is allocated from runtime memory. If an event is to be
 *   signaled after the call to EFI_BOOT_SERVICES.ExitBootServices(), the
 *   event’s data structure and notification function need to be allocated
 *   from runtime memory. For more information, see SetVirtualAddressMap().
 */
#define EVT_RUNTIME 0x40000000

/**
 * @brief If an event of this type is not already in the signaled state,
 *   then the event’s NotificationFunction will be queued at the event’s
 *   NotifyTpl whenever the event is being waited on via
 *   EFI_BOOT_SERVICES.WaitForEvent() or EFI_BOOT_SERVICES.CheckEvent().
 */
#define EVT_NOTIFY_WAIT 0x00000100

/**
 * @brief The event’s NotifyFunction is queued whenever the event is signaled.
 */
#define EVT_NOTIFY_SIGNAL 0x00000200

/**
 * @brief This event is to be notified by the system when ExitBootServices()
 *   is invoked. This event is of type EVT_NOTIFY_SIGNAL and should not be
 *   combined with any other event types. The notification function for this
 *   event is not allowed to use the Memory Allocation Services, or call any
 *   functions that use the Memory Allocation Services and must only call
 *   functions that are known not to use Memory Allocation Services, because
 *   these services modify the current memory map.The notification function
 *   must not depend on timer events since timer services will be deactivated
 *   before any notification functions are called.
 */
#define EVT_SIGNAL_EXIT_BOOT_SERVICES 0x00000201

/**
 * @brief The event is to be notified by the system when SetVirtualAddressMap()
 *   is performed. This event type is a composite of EVT_NOTIFY_SIGNAL,
 *   EVT_RUNTIME, and EVT_RUNTIME_CONTEXT and should not be combined with any
 *   other event types.
 */
#define EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE 0x60000202

/**
 * <!-- description -->
 *   @brief Defined in EFI_BOOT_SERVICES.CreateEvent()
 *
 * <!-- inputs/outputs -->
 *   @param Event Event whose notification function is being invoked.
 *   @param Context Pointer to the notification function’s context, which is
 *     implementation-dependent. Context corresponds to NotifyContext in
 *     EFI_BOOT_SERVICES.CreateEventEx().
 */
typedef VOID(EFIAPI *EFI_EVENT_NOTIFY)(IN EFI_EVENT Event, IN VOID *Context);

/**
 * <!-- description -->
 *   @brief Creates an event.
 *
 * <!-- inputs/outputs -->
 *   @param Type The type of event to create and its mode and attributes.
 *   @param NotifyTpl The task priority level of event notifications, if
 *     needed. See EFI_BOOT_SERVICES.RaiseTPL().
 *   @param NotifyFunction Pointer to the event’s notification function, if
 *     any.
 *   @param NotifyContext Pointer to the notification function’s context;
 *     corresponds to parameter Context in the notification function.
 *   @param Event Pointer to the newly created event if the call succeeds;
 *     undefined otherwise.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_CREATE_EVENT)(
    IN UINT32 Type,
    IN EFI_TPL NotifyTpl,
    IN EFI_EVENT_NOTIFY NotifyFunction,
    OPTIONAL IN VOID *NotifyContext,
    OPTIONAL OUT EFI_EVENT *Event);

/**
 * <!-- description -->
 *   @brief Sets the type of timer and the trigger time for a timer event.
 *
 * <!-- inputs/outputs -->
 *   @param Event The timer event that is to be signaled at the specified time.
 *     Type EFI_EVENT is defined in the CreateEvent() function description.
 *   @param Type The type of time that is specified in TriggerTime.
 *   @param TriggerTime The number of 100ns units until the timer expires.
 *     A TriggerTime of 0 is legal. If Type is TimerRelative and TriggerTime is
 *     0, then the timer event will be signaled on the next timer tick. If Type
 *     is TimerPeriodic and TriggerTime is 0, then the timer event will be
 *     signaled on every timer tick.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SET_TIMER)(
    IN EFI_EVENT Event, IN EFI_TIMER_DELAY Type, IN UINT64 TriggerTime);

/**
 * <!-- description -->
 *   @brief Stops execution until an event is signaled.
 *
 * <!-- inputs/outputs -->
 *   @param NumberOfEvents The number of events in the Event array.
 *   @param Event An array of EFI_EVENT. Type EFI_EVENT is defined in the
 *     CreateEvent() function description.
 *   @param Index Pointer to the index of the event which satisfied the wait
 *     condition.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_WAIT_FOR_EVENT)(
    IN UINTN NumberOfEvents, IN EFI_EVENT *Event, OUT UINTN *Index);

/**
 * <!-- description -->
 *   @brief Signals an event.
 *
 * <!-- inputs/outputs -->
 *   @param Event The event to signal. Type EFI_EVENT is defined in the
 *     EFI_BOOT_SERVICES.CheckEvent() function description.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SIGNAL_EVENT)(IN EFI_EVENT Event);

/**
 * <!-- description -->
 *   @brief Closes an event.
 *
 * <!-- inputs/outputs -->
 *   @param Event The event to close. Type EFI_EVENT is defined in the
 *     CreateEvent() function description.
 *   @return Returns an EFI_STATUS
 */

typedef EFI_STATUS(EFIAPI *EFI_CLOSE_EVENT)(IN EFI_EVENT Event);

/**
 * <!-- description -->
 *   @brief Checks whether an event is in the signaled state.
 *
 * <!-- inputs/outputs -->
 *   @param Event The event to check. Type EFI_EVENT is defined in the
 *     CreateEvent() function description.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_CHECK_EVENT)(IN EFI_EVENT Event);

/**
 * <!-- description -->
 *   @brief Installs a protocol interface on a device handle. If the handle
 *     does not exist, it is created and added to the list of handles in the
 *     system. InstallMultipleProtocolInterfaces() performs more error checking
 *     than InstallProtocolInterface(), so it is recommended that
 *     InstallMultipleProtocolInterfaces() be used in place of
 *     InstallProtocolInterface()
 *
 * <!-- inputs/outputs -->
 *   @param Handle A pointer to the EFI_HANDLE on which the interface is to
 *     be installed. If *Handle is NULL on input, a new handle is created and
 *     returned on output. If *Handle is not NULL on input, the protocol is
 *     added to the handle, and the handle is returned unmodified. The type
 *     EFI_HANDLE is defined in “Related Definitions.” If *Handle is not a
 *     valid handle, then EFI_INVALID_PARAMETER is returned.
 *   @param Protocol The numeric ID of the protocol interface. The type
 *     EFI_GUID is defined in “Related Definitions.” It is the caller’s
 *     responsibility to pass in a valid GUID.
 *   @param InterfaceType Indicates whether Interface is supplied in native
 *     form. This value indicates the original execution environment of the
 *     request.
 *   @param Interface A pointer to the protocol interface. The Interface must
 *     adhere to the structure defined by Protocol. NULL can be used if a
 *     structure is not associated with Protocol.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_INSTALL_PROTOCOL_INTERFACE)(
    IN OUT EFI_HANDLE *Handle,
    IN EFI_GUID *Protocol,
    IN EFI_INTERFACE_TYPE InterfaceType,
    IN VOID *Interface);

/**
 * <!-- description -->
 *   @brief Reinstalls a protocol interface on a device handle.
 *
 * <!-- inputs/outputs -->
 *   @param Handle Handle on which the interface is to be reinstalled. If
 *     Handle is not a valid handle, then EFI_INVALID_PARAMETER is returned.
 *     Type EFI_HANDLE is defined in the
 *     EFI_BOOT_SERVICES.InstallProtocolInterface() function description.
 *   @param Protocol The numeric ID of the interface. It is the caller’s
 *     responsibility to pass in a valid GUID.
 *   @param OldInterface A pointer to the old interface.
 *     NULL can be used if a structure is not associated with Protocol.
 *   @param NewInterface A pointer to the new interface.
 *     NULL can be used if a structure is not associated with Protocol.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_REINSTALL_PROTOCOL_INTERFACE)(
    IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, IN VOID *OldInterface, IN VOID *NewInterface);

/**
 * <!-- description -->
 *   @brief Removes a protocol interface from a device handle. It is
 *     recommended that UninstallMultipleProtocolInterfaces() be used in place
 *     of UninstallProtocolInterface().
 *
 * <!-- inputs/outputs -->
 *   @param Handle The handle on which the interface was installed. If Handle
 *     is not a valid handle, then EFI_INVALID_PARAMETER is returned. Type
 *     EFI_HANDLE is defined in the
 *     EFI_BOOT_SERVICES.InstallProtocolInterface() function description.
 *   @param Protocol The numeric ID of the interface. It is the caller’s
 *     responsibility to pass in a valid GUID.
 *   @param Interface A pointer to the interface. NULL can be used if a
 *     structure is not associated with Protocol.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_UNINSTALL_PROTOCOL_INTERFACE)(
    IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, IN VOID *Interface);

/**
 * <!-- description -->
 *   @brief Queries a handle to determine if it supports a specified protocol.
 *
 * <!-- inputs/outputs -->
 *   @param Handle The handle being queried. If Handle is NULL, then
 *     EFI_INVALID_PARAMETER is returned. Type EFI_HANDLE is defined in the
 *     EFI_BOOT_SERVICES.InstallProtocolInterface() function description.
 *   @param Protocol The published unique identifier of the protocol. It is
 *     the caller’s responsibility to pass in a valid GUID.
 *   @param Interface Supplies the address where a pointer to the corresponding
 *     Protocol Interface is returned. NULL will be returned in *Interface if a
 *     structure is not associated with Protocol.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_HANDLE_PROTOCOL)(
    IN EFI_HANDLE Handle, IN EFI_GUID *Protocol, OUT VOID **Interface);

/**
 * <!-- description -->
 *   @brief Creates an event that is to be signaled whenever an interface is
 *     installed for a specified protocol.
 *
 * <!-- inputs/outputs -->
 *   @param Protocol The numeric ID of the protocol for which the event is to
 *     be registered. Type EFI_GUID is defined in the
 *     EFI_BOOT_SERVICES.InstallProtocolInterface() function description.
 *   @param Event Event that is to be signaled whenever a protocol interface
 *     is registered for Protocol. The type EFI_EVENT is defined in the
 *     CreateEvent() function description. The same EFI_EVENT may be used
 *     for multiple protocol notify registrations.
 *   @param Registration A pointer to a memory location to receive the
 *     registration value. This value must be saved and used by the
 *     notification function of Event to retrieve the list of handles that
 *     have added a protocol interface of type Protocol.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_REGISTER_PROTOCOL_NOTIFY)(
    IN EFI_GUID *Protocol, IN EFI_EVENT Event, OUT VOID **Registration);

/**
 * <!-- description -->
 *   @brief Returns an array of handles that support a specified protocol.
 *
 * <!-- inputs/outputs -->
 *   @param SearchType Specifies which handle(s) are to be returned.
 *   @param Protocol Specifies the protocol to search by. This parameter is
 *     only valid if SearchType is ByProtocol. Type EFI_GUID is defined in the
 *     EFI_BOOT_SERVICES.InstallProtocolInterface() function description.
 *   @param SearchKey Specifies the search key. This parameter is ignored if
 *     SearchType is AllHandles or ByProtocol. If SearchType is
 *     ByRegisterNotify, the parameter must be the Registration value returned
 *     by function EFI_BOOT_SERVICES.RegisterProtocolNotify().
 *   @param BufferSize On input, the size in bytes of Buffer. On output, the
 *     size in bytes of the array returned in Buffer (if the buffer was large
 *     enough) or the size, in bytes, of the buffer needed to obtain the array
 *     (if the buffer was not large enough).
 *   @param Buffer The buffer in which the array is returned. Type EFI_HANDLE
 *     is defined in the InstallProtocolInterface() function description.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_LOCATE_HANDLE)(
    IN EFI_LOCATE_SEARCH_TYPE SearchType,
    IN EFI_GUID *Protocol OPTIONAL,
    IN VOID *SearchKey OPTIONAL,
    IN OUT UINTN *BufferSize,
    OUT EFI_HANDLE *Buffer);

/**
 * <!-- description -->
 *   @brief Locates the handle to a device on the device path that supports
 *     the specified protocol.
 *
 * <!-- inputs/outputs -->
 *   @param Protocol The protocol to search for. Type EFI_GUID is defined in
 *     the EFI_BOOT_SERVICES.InstallProtocolInterface() function description.
 *   @param DevicePath On input, a pointer to a pointer to the device path.
 *     On output, the device path pointer is modified to point to the remaining
 *     part of the device path—that is, when the function finds the closest
 *     handle, it splits the device path into two parts, stripping off the
 *     front part, and returning the remaining portion.
 *   @param Device A pointer to the returned device handle. Type EFI_HANDLE is
 *     defined in the InstallProtocolInterface() function description.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_LOCATE_DEVICE_PATH)(
    IN EFI_GUID *Protocol, IN OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath, OUT EFI_HANDLE *Device);

/**
 * <!-- description -->
 *   @brief Adds, updates, or removes a configuration table entry from the EFI System Table.
 *
 * <!-- inputs/outputs -->
 *   @param Guid A pointer to the GUID for the entry to add, update, or remove.
 *   @param Table A pointer to the configuration table for the entry to add,
 *     update, or remove. May be NULL.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_INSTALL_CONFIGURATION_TABLE)(IN EFI_GUID *Guid, IN VOID *Table);

/**
 * <!-- description -->
 *   @brief Loads an EFI image into memory.
 *
 * <!-- inputs/outputs -->
 *   @param BootPolicy If TRUE, indicates that the request originates from
 *     the boot manager, and that the boot manager is attempting to load
 *     DevicePath as a boot selection. Ignored if SourceBuffer is not NULL.
 *   @param ParentImageHandle The caller’s image handle. Type EFI_HANDLE is
 *     defined in the EFI_BOOT_SERVICES.InstallProtocolInterface() function
 *     description. This field is used to initialize the ParentHandle field
 *     of the EFI_LOADED_IMAGE_PROTOCOL for the image that is being loaded.
 *   @param DevicePath The DeviceHandle specific file path from which the
 *     image is loaded.
 *   @param SourceBuffer If not NULL, a pointer to the memory location
 *     containing a copy of the image to be loaded.
 *   @param SourceSize The size in bytes of SourceBuffer. Ignored if
 *     SourceBuffer is NULL.
 *   @param ImageHandle Pointer to the returned image handle that is created
 *     when the image is successfully loaded. Type EFI_HANDLE is defined in
 *     the InstallProtocolInterface() function description.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_IMAGE_LOAD)(
    IN BOOLEAN BootPolicy,
    IN EFI_HANDLE ParentImageHandle,
    IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
    IN VOID *SourceBuffer OPTIONAL,
    IN UINTN SourceSize,
    OUT EFI_HANDLE *ImageHandle);

/**
 * <!-- description -->
 *   @brief Transfers control to a loaded image’s entry point.
 *
 * <!-- inputs/outputs -->
 *   @param ImageHandle Handle of image to be started. Type EFI_HANDLE is
 *     defined in the EFI_BOOT_SERVICES.InstallProtocolInterface() function
 *     description.
 *   @param ExitDataSize Pointer to the size, in bytes, of ExitData.
 *     If ExitData is NULL, then this parameter is ignored and the contents
 *     of ExitDataSize are not modified.
 *   @param ExitData Pointer to a pointer to a data buffer that includes a
 *     Null-terminated string, optionally followed by additional binary data.
 *     The string is a description that the caller may use to further indicate
 *     the reason for the image’s exit.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_IMAGE_START)(
    IN EFI_HANDLE ImageHandle, OUT UINTN *ExitDataSize, OUT CHAR16 **ExitData OPTIONAL);

/**
 * <!-- description -->
 *   @brief Terminates a loaded EFI image and returns control to boot services.
 *
 * <!-- inputs/outputs -->
 *   @param ImageHandle Handle that identifies the image. This parameter is
 *     passed to the image on entry.
 *   @param ExitStatus The image’s exit code.
 *   @param ExitDataSize The size, in bytes, of ExitData. Ignored if
 *     ExitStatus is EFI_SUCCESS.
 *   @param ExitData Pointer to a data buffer that includes a Null-terminated
 *     string, optionally followed by additional binary data. The string is a
 *     description that the caller may use to further indicate the reason for
 *     the image’s exit. ExitData is only valid if ExitStatus is something
 *     other than EFI_SUCCESS. The ExitData buffer must be allocated by calling
 *     EFI_BOOT_SERVICES.AllocatePool().
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_EXIT)(
    IN EFI_HANDLE ImageHandle,
    IN EFI_STATUS ExitStatus,
    IN UINTN ExitDataSize,
    IN CHAR16 *ExitData OPTIONAL);

/**
 * <!-- description -->
 *   @brief Unloads an image.
 *
 * <!-- inputs/outputs -->
 *   @param ImageHandle Handle that identifies the image to be unloaded.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_IMAGE_UNLOAD)(IN EFI_HANDLE ImageHandle);

/**
 * <!-- description -->
 *   @brief Terminates all boot services.
 *
 * <!-- inputs/outputs -->
 *   @param ImageHandle Handle that identifies the exiting image. Type
 *     EFI_HANDLE is defined in the EFI_BOOT_SERVICES.InstallProtocolInterface()
 *     function description.
 *   @param MapKey Key to the latest memory map.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_EXIT_BOOT_SERVICES)(IN EFI_HANDLE ImageHandle, IN UINTN MapKey);

/**
 * <!-- description -->
 *   @brief Returns a monotonically increasing count for the platform.
 *
 * <!-- inputs/outputs -->
 *   @param Count Pointer to returned value.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_GET_NEXT_MONOTONIC_COUNT)(OUT UINT64 *Count);

/**
 * <!-- description -->
 *   @brief Induces a fine-grained stall.
 *
 * <!-- inputs/outputs -->
 *   @param Microseconds The number of microseconds to stall execution.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_STALL)(IN UINTN Microseconds);

/**
 * <!-- description -->
 *   @brief Sets the system’s watchdog timer.
 *
 * <!-- inputs/outputs -->
 *   @param Timeout The number of seconds to set the watchdog timer to. A
 *     value of zero disables the timer.
 *   @param WatchdogCode The numeric code to log on a watchdog timer timeout
 *     event. The firmware reserves codes 0x0000 to 0xFFFF. Loaders and
 *     operating systems may use other timeout codes.
 *   @param DataSize The size, in bytes, of WatchdogData.
 *   @param WatchdogData A data buffer that includes a Null-terminated string,
 *     optionally followed by additional binary data. The string is a
 *     description that the call may use to further indicate the reason to be
 *     logged with a watchdog event.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_SET_WATCHDOG_TIMER)(
    IN UINTN Timeout, IN UINT64 WatchdogCode, IN UINTN DataSize, IN CHAR16 *WatchdogData OPTIONAL);

/**
 * <!-- description -->
 *   @brief Connects one or more drivers to a controller.
 *
 * <!-- inputs/outputs -->
 *   @param ControllerHandle The handle of the controller to which driver(s)
 *     are to be connected.
 *   @param DriverImageHandle A pointer to an ordered list handles that support
 *     the EFI_DRIVER_BINDING_PROTOCOL. The list is terminated by a NULL handle
 *     value. These handles are candidates for the Driver Binding Protocol(s)
 *     that will manage the controller specified by ControllerHandle. This is
 *     an optional parameter that may be NULL. This parameter is typically used
 *     to debug new drivers.
 *   @param RemainingDevicePath A pointer to the device path that specifies a
 *     child of the controller specified by ControllerHandle. This is an
 *     optional parameter that may be NULL. If it is NULL, then handles for all
 *     the children of ControllerHandle will be created. This parameter is
 *     passed unchanged to the Supported() and Start() services of the
 *     EFI_DRIVER_BINDING_PROTOCOL attached to ControllerHandle.
 *   @param Recursive If TRUE, then ConnectController() is called recursively
 *     until the entire tree of controllers below the controller specified by
 *     ControllerHandle have been created. If FALSE, then the tree of
 *     controllers is only expanded one level.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_CONNECT_CONTROLLER)(
    IN EFI_HANDLE ControllerHandle,
    IN EFI_HANDLE *DriverImageHandle OPTIONAL,
    IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath OPTIONAL,
    IN BOOLEAN Recursive);

/**
 * <!-- description -->
 *   @brief Disconnects one or more drivers from a controller
 *
 * <!-- inputs/outputs -->
 *   @param ControllerHandle The handle of the controller from which driver(s)
 *     are to be disconnected.
 *   @param DriverImageHandle The driver to disconnect from ControllerHandle.
 *     If DriverImageHandle is NULL, then all the drivers currently managing
 *     ControllerHandle are disconnected from ControllerHandle.
 *   @param ChildHandle The handle of the child to destroy. If ChildHandle is
 *     NULL, then all the children of ControllerHandle are destroyed before the
 *     drivers are disconnected from ControllerHandle.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_DISCONNECT_CONTROLLER)(
    IN EFI_HANDLE ControllerHandle,
    IN EFI_HANDLE DriverImageHandle OPTIONAL,
    IN EFI_HANDLE ChildHandle OPTIONAL);

/**
 * @brief Used in the implementation of
 *   EFI_BOOT_SERVICES.HandleProtocol(). Since
 *   EFI_BOOT_SERVICES.OpenProtocol() performs the same
 *   function as HandleProtocol() with additional functionality,
 *   HandleProtocol() can simply call OpenProtocol() with this
 *   Attributes value.
 */
#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL 0x00000001

/**
 * @brief Used by a driver to get a protocol interface from a handle. Care must
 *   be taken when using this open mode because the driver that opens a
 *   protocol interface in this manner will not be informed if the protocol
 *   interface is uninstalled or reinstalled. The caller is also not required
 *   to close the protocol interface with
 *   EFI_BOOT_SERVICES.CloseProtocol().
 */
#define EFI_OPEN_PROTOCOL_GET_PROTOCOL 0x00000002

/**
 * @brief Used by a driver to test for the existence of a protocol interface on a
 *   handle. Interface is optional for this attribute value, so it is ignored,
 *   and the caller should only use the return status code. The caller is
 *   also not required to close the protocol interface with
 *   CloseProtocol().
 */
#define EFI_OPEN_PROTOCOL_TEST_PROTOCOL 0x00000004

/**
 * @brief Used by bus drivers to show that a protocol interface is being used
 *   by one of the child controllers of a bus. This information is used by
 *   the boot service EFI_BOOT_SERVICES.ConnectController()
 *   to recursively connect all child controllers and by the boot service
 *   EFI_BOOT_SERVICES.DisconnectController() to get the list
 *   of child controllers that a bus driver created.
 */
#define EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER 0x00000008

/**
 * @brief Used by a driver to gain access to a protocol interface. When this
 *   mode is used, the driver’s Stop() function will be called by
 *   EFI_BOOT_SERVICES.DisconnectController() if the
 *   protocol interface is reinstalled or uninstalled. Once a protocol
 *   interface is opened by a driver with this attribute, no other drivers
 *   will be allowed to open the same protocol interface with the
 *   BY_DRIVER attribute.
 */
#define EFI_OPEN_PROTOCOL_BY_DRIVER 0x00000010

/**
 * @brief Used by a driver to gain exclusive access to a protocol interface. If
 *   any other drivers have the protocol interface opened with an
 *   attribute of BY_DRIVER, then an attempt will be made to remove
 *   them with DisconnectController().
 */
#define EFI_OPEN_PROTOCOL_EXCLUSIVE 0x00000020

/**
 * <!-- description -->
 *   @brief Queries a handle to determine if it supports a specified protocol.
 *     If the protocol is supported by the handle, it opens the protocol on
 *     behalf of the calling agent. This is an extended version of the EFI boot
 *     service EFI_BOOT_SERVICES.HandleProtocol().
 *
 * <!-- inputs/outputs -->
 *   @param Handle The handle for the protocol interface that is being opened.
 *   @param Protocol The published unique identifier of the protocol. It is
 *     the caller’s responsibility to pass in a valid GUID.
 *   @param Interface Supplies the address where a pointer to the corresponding
 *     Protocol Interface is returned. NULL will be returned in *Interface if
 *     a structure is not associated with Protocol. This parameter is optional,
 *     and will be ignored if Attributes is EFI_OPEN_PROTOCOL_TEST_PROTOCOL.
 *   @param AgentHandle The handle of the agent that is opening the protocol
 *     interface specified by Protocol and Interface. For agents that follow
 *     the UEFI Driver Model, this parameter is the handle that contains the
 *     EFI_DRIVER_BINDING_PROTOCOL instance that is produced by the UEFI driver
 *     that is opening the protocol interface. For UEFI applications, this is
 *     the image handle of the UEFI application that is opening the protocol
 *     interface. For applications that use HandleProtocol() to open a protocol
 *     interface, this parameter is the image handle of the EFI firmware.
 *   @param ControllerHandle If the agent that is opening a protocol is a
 *     driver that follows the UEFI Driver Model, then this parameter is the
 *     controller handle that requires the protocol interface. If the agent
 *     does not follow the UEFI Driver Model, then this parameter is optional
 *     and may be NULL.
 *   @param Attributes The open mode of the protocol interface specified by
 *     Handle and Protocol. See "Related Definitions" for the list of legal
 *     attributes.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_OPEN_PROTOCOL)(
    IN EFI_HANDLE Handle,
    IN EFI_GUID *Protocol,
    OUT VOID **Interface OPTIONAL,
    IN EFI_HANDLE AgentHandle,
    IN EFI_HANDLE ControllerHandle,
    IN UINT32 Attributes);

/**
 * <!-- description -->
 *   @brief Closes a protocol on a handle that was opened using
 *     EFI_BOOT_SERVICES.OpenProtocol().
 *
 * <!-- inputs/outputs -->
 *   @param Handle The handle for the protocol interface that was previously
 *     opened with OpenProtocol(), and is now being closed.
 *   @param Protocol The published unique identifier of the protocol.
 *     It is the caller’s responsibility to pass in a valid GUID.
 *   @param AgentHandle The handle of the agent that is closing the protocol
 *     interface. For agents that follow the UEFI Driver Model, this parameter
 *     is the handle that contains the EFI_DRIVER_BINDING_PROTOCOL instance
 *     that is produced by the UEFI driver that is opening the protocol
 *     interface. For UEFI applications, this is the image handle of the UEFI
 *     application. For applications that used
 *     EFI_BOOT_SERVICES.HandleProtocol() to open the protocol interface, this
 *     will be the image handle of the EFI firmware.
 *   @param ControllerHandle If the agent that opened a protocol is a driver
 *     that follows the UEFI Driver Model, then this parameter is the
 *     controller handle that required the protocol interface. If the agent
 *     does not follow the UEFI Driver Model, then this parameter is optional
 *     and may be NULL.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_CLOSE_PROTOCOL)(
    IN EFI_HANDLE Handle,
    IN EFI_GUID *Protocol,
    IN EFI_HANDLE AgentHandle,
    IN EFI_HANDLE ControllerHandle);

/**
 * <!-- description -->
 *   @brief Retrieves the list of agents that currently have a protocol
 *     interface opened.
 *
 * <!-- inputs/outputs -->
 *   @param Handle The handle for the protocol interface that is being queried.
 *   @param Protocol The published unique identifier of the protocol. It is
 *     the caller’s responsibility to pass in a valid GUID.
 *   @param EntryBuffer A pointer to a buffer of open protocol information in
 *     the form of EFI_OPEN_PROTOCOL_INFORMATION_ENTRY structures.
 *   @param EntryCount A pointer to the number of entries in EntryBuffer.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_OPEN_PROTOCOL_INFORMATION)(
    IN EFI_HANDLE Handle,
    IN EFI_GUID *Protocol,
    OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **EntryBuffer,
    OUT UINTN *EntryCount);

/**
 * <!-- description -->
 *   @brief Retrieves the list of protocol interface GUIDs that are installed
 *     on a handle in a buffer allocated from pool.
 *
 * <!-- inputs/outputs -->
 *   @param Handle The handle from which to retrieve the list of protocol
 *     interface GUIDs.
 *   @param ProtocolBuffer A pointer to the list of protocol interface
 *     GUID pointers that are installed on Handle. This buffer is allocated
 *     with a call to the Boot Service EFI_BOOT_SERVICES.AllocatePool(). It is
 *     the caller's responsibility to call the Boot Service
 *     EFI_BOOT_SERVICES.FreePool() when the caller no longer requires the
 *     contents of ProtocolBuffer
 *   @param ProtocolBufferCount A pointer to the number of GUID pointers
 *     present in ProtocolBuffer.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_PROTOCOLS_PER_HANDLE)(
    IN EFI_HANDLE Handle, OUT EFI_GUID ***ProtocolBuffer, OUT UINTN *ProtocolBufferCount);

/**
 * <!-- description -->
 *   @brief Returns an array of handles that support the requested protocol in
 *     a buffer allocated from pool.
 *
 * <!-- inputs/outputs -->
 *   @param SearchType Specifies which handle(s) are to be returned.
 *   @param Protocol Provides the protocol to search by. This parameter is only
 *     valid for a SearchType of ByProtocol.
 *   @param SearchKey Supplies the search key depending on the SearchType.
 *   @param NoHandles The number of handles returned in Buffer.
 *   @param Buffer A pointer to the buffer to return the requested array of
 *     handles that support Protocol. This buffer is allocated with a call to
 *     the Boot Service EFI_BOOT_SERVICES.AllocatePool(). It is the caller's
 *     responsibility to call the Boot Service EFI_BOOT_SERVICES.FreePool()
 *     when the caller no longer requires the contents of Buffer.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_LOCATE_HANDLE_BUFFER)(
    IN EFI_LOCATE_SEARCH_TYPE SearchType,
    IN EFI_GUID *Protocol OPTIONAL,
    IN VOID *SearchKey OPTIONAL,
    IN OUT UINTN *NoHandles,
    OUT EFI_HANDLE **Buffer);

/**
 * <!-- description -->
 *   @brief Returns the first protocol instance that matches the given
 *     protocol.
 *
 * <!-- inputs/outputs -->
 *   @param Protocol Provides the protocol to search for.
 *   @param Registration Optional registration key returned from
 *     EFI_BOOT_SERVICES.RegisterProtocolNotify(). If Registration is NULL,
 *     then it is ignored.
 *   @param Interface On return, a pointer to the first interface that matches
 *     Protocol and Registration.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_LOCATE_PROTOCOL)(
    IN EFI_GUID *Protocol, IN VOID *Registration OPTIONAL, OUT VOID **Interface);

/**
 * <!-- description -->
 *   @brief Installs one or more protocol interfaces into the boot services
 *     environment.
 *
 * <!-- inputs/outputs -->
 *   @param Handle The pointer to a handle to install the new protocol
 *     interfaces on, or a pointer to NULL if a new handle is to be allocated.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES)(
    IN OUT EFI_HANDLE *Handle, ...);

/**
 * <!-- description -->
 *   @brief Removes one or more protocol interfaces into the boot services
 *     environment.
 *
 * <!-- inputs/outputs -->
 *   @param Handle The handle to remove the protocol interfaces from.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES)(IN EFI_HANDLE Handle, ...);

/**
 * <!-- description -->
 *   @brief Computes and returns a 32-bit CRC for a data buffer.
 *
 * <!-- inputs/outputs -->
 *   @param Data A pointer to the buffer on which the 32-bit CRC is to be
 *     computed.
 *   @param DataSize The number of bytes in the buffer Data.
 *   @param Crc32 The 32-bit CRC that was computed for the data buffer
 *     specified by Data and DataSize.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_CALCULATE_CRC32)(
    IN VOID *Data, IN UINTN DataSize, OUT UINT32 *Crc32);

/**
 * <!-- description -->
 *   @brief The CopyMem() function copies the contents of one buffer to
 *     another buffer.
 *
 * <!-- inputs/outputs -->
 *   @param Destination Pointer to the destination buffer of the memory copy.
 *   @param Source Pointer to the source buffer of the memory copy.
 *   @param Length Number of bytes to copy from Source to Destination.
 *   @return Returns an EFI_STATUS
 */
typedef VOID(EFIAPI *EFI_COPY_MEM)(IN VOID *Destination, IN VOID *Source, IN UINTN Length);

/**
 * <!-- description -->
 *   @brief The SetMem() function fills a buffer with a specified value.
 *
 * <!-- inputs/outputs -->
 *   @param Buffer Pointer to the buffer to fill.
 *   @param Size Number of bytes in Buffer to fill.
 *   @param Value Value to fill Buffer with.
 *   @return Returns an EFI_STATUS
 */
typedef VOID(EFIAPI *EFI_SET_MEM)(IN VOID *Buffer, IN UINTN Size, IN UINT8 Value);

/**
 * <!-- description -->
 *   @brief Creates an event in a group.
 *
 * <!-- inputs/outputs -->
 *   @param Type The type of event to create and its mode and attributes.
 *   @param NotifyTpl The task priority level of event notifications, if
 *     needed. See EFI_BOOT_SERVICES.RaiseTPL().
 *   @param NotifyFunction Pointer to the event’s notification function,
 *     if any.
 *   @param NotifyContext Pointer to the notification function’s context;
 *     corresponds to parameter Context in the notification function.
 *   @param EventGroup Pointer to the unique identifier of the group to which
 *     this event belongs. If this is NULL, then the function behaves as if
 *     the parameters were passed to CreateEvent.
 *   @param Event Pointer to the newly created event if the call succeeds;
 *     undefined otherwise.
 *   @return Returns an EFI_STATUS
 */
typedef EFI_STATUS(EFIAPI *EFI_CREATE_EVENT_EX)(
    IN UINT32 Type,
    IN EFI_TPL NotifyTpl,
    IN EFI_EVENT_NOTIFY NotifyFunction OPTIONAL,
    IN CONST VOID *NotifyContext OPTIONAL,
    IN CONST EFI_GUID *EventGroup OPTIONAL,
    OUT EFI_EVENT *Event);

/**
 * @struct EFI_BOOT_SERVICES
 *
 * <!-- description -->
 *   @brief Defines the layout of the EFI_BOOT_SERVICES struct:
 *     https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
 */
typedef struct
{
    /**
     * @brief The table header for the EFI Boot Services Table. This header
     *   contains the EFI_BOOT_SERVICES_SIGNATURE and
     *   EFI_BOOT_SERVICES_REVISION values along with the size of the
     *   EFI_BOOT_SERVICES structure and a 32-bit CRC to verify that the
     *   contents of the EFI Boot Services Table are valid.
     */
    EFI_TABLE_HEADER Hdr;

    /**
     * @brief Raises the task priority level.
     */
    EFI_RAISE_TPL RaiseTPL;

    /**
     * @brief Restores/lowers the task priority level.
     */
    EFI_RESTORE_TPL RestoreTPL;

    /**
     * @brief Allocates pages of a particular type.
     */
    EFI_ALLOCATE_PAGES AllocatePages;

    /**
     * @brief Frees allocated pages.
     */
    EFI_FREE_PAGES FreePages;

    /**
     * @brief Returns the current boot services memory map and memory map key
     */
    EFI_GET_MEMORY_MAP GetMemoryMap;

    /**
     * @brief Allocates a pool of a particular type.
     */
    EFI_ALLOCATE_POOL AllocatePool;

    /**
     * @brief Frees allocated pool.
     */
    EFI_FREE_POOL FreePool;

    /**
     * @brief Creates a general-purpose event structure.
     */
    EFI_CREATE_EVENT CreateEvent;

    /**
     * @brief Sets an event to be signaled at a particular time.
     */
    EFI_SET_TIMER SetTimer;

    /**
     * @brief Stops execution until an event is signaled.
     */
    EFI_WAIT_FOR_EVENT WaitForEvent;

    /**
     * @brief Signals an event.
     */
    EFI_SIGNAL_EVENT SignalEvent;

    /**
     * @brief Closes and frees an event structure.
     */
    EFI_CLOSE_EVENT CloseEvent;

    /**
     * @brief Checks whether an event is in the signaled state.
     */
    EFI_CHECK_EVENT CheckEvent;

    /**
     * @brief Installs a protocol interface on a device handle.
     */
    EFI_INSTALL_PROTOCOL_INTERFACE InstallProtocolInterface;

    /**
     * @brief Reinstalls a protocol interface on a device handle.
     */
    EFI_REINSTALL_PROTOCOL_INTERFACE ReinstallProtocolInterface;

    /**
     * @brief Removes a protocol interface from a device handle.
     */
    EFI_UNINSTALL_PROTOCOL_INTERFACE UninstallProtocolInterface;

    /**
     * @brief Queries a handle to determine if it supports a specified
     *   protocol.
     */
    EFI_HANDLE_PROTOCOL HandleProtocol;

    /**
     * @brief Reserved. Must be NULL.
     */
    VOID *Reserved;

    /**
     * @brief Registers an event that is to be signaled whenever an interface
     *   is installed for a specified protocol.
     */
    EFI_REGISTER_PROTOCOL_NOTIFY RegisterProtocolNotify;

    /**
     * @brief Returns an array of handles that support a specified protocol.
     */
    EFI_LOCATE_HANDLE LocateHandle;

    /**
     * @brief Locates all devices on a device path that support a specified
     *   protocol and returns the handle to the device that is closest to
     *   the path.
     */
    EFI_LOCATE_DEVICE_PATH LocateDevicePath;

    /**
     * @brief Adds, updates, or removes a configuration table from the
     *   EFI System Table.
     */
    EFI_INSTALL_CONFIGURATION_TABLE InstallConfigurationTable;

    /**
     * @brief Loads an EFI image into memory.
     */
    EFI_IMAGE_LOAD LoadImage;

    /**
     * @brief Transfers control to a loaded image’s entry point.
     */
    EFI_IMAGE_START StartImage;

    /**
     * @brief Exits the image’s entry point.
     */
    EFI_EXIT Exit;

    /**
     * @brief Unloads an image.
     */
    EFI_IMAGE_UNLOAD UnloadImage;

    /**
     * @brief Terminates boot services.
     */
    EFI_EXIT_BOOT_SERVICES ExitBootServices;

    /**
     * @brief Returns a monotonically increasing count for the platform.
     */
    EFI_GET_NEXT_MONOTONIC_COUNT GetNextMonotonicCount;

    /**
     * @brief Stalls the processor.
     */
    EFI_STALL Stall;

    /**
     * @brief Resets and sets a watchdog timer used during boot services time.
     */
    EFI_SET_WATCHDOG_TIMER SetWatchdogTimer;

    /**
     * @brief Uses a set of precedence rules to find the best set of drivers
     *   to manage a controller.
     */
    EFI_CONNECT_CONTROLLER ConnectController;

    /**
     * @brief Informs a set of drivers to stop managing a controller.
     */
    EFI_DISCONNECT_CONTROLLER DisconnectController;

    /**
     * @brief Adds elements to the list of agents consuming a protocol
     *   interface.
     */
    EFI_OPEN_PROTOCOL OpenProtocol;

    /**
     * @brief Removes elements from the list of agents consuming a protocol
     *   interface.
     */
    EFI_CLOSE_PROTOCOL CloseProtocol;

    /**
     * @brief Retrieve the list of agents that are currently consuming a
     *   protocol interface.
     */
    EFI_OPEN_PROTOCOL_INFORMATION OpenProtocolInformation;

    /**
     * @brief Retrieves the list of protocols installed on a handle. The
     *   return buffer is automatically allocated.
     */
    EFI_PROTOCOLS_PER_HANDLE ProtocolsPerHandle;

    /**
     * @brief Retrieves the list of handles from the handle database that
     *   meet the search criteria. The return buffer is automatically
     *   allocated.
     */
    EFI_LOCATE_HANDLE_BUFFER LocateHandleBuffer;

    /**
     * @brief Finds the first handle in the handle database the supports
     *   the requested protocol.
     */
    EFI_LOCATE_PROTOCOL LocateProtocol;

    /**
     * @brief Installs one or more protocol interfaces onto a handle.
     */
    EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES InstallMultipleProtocolInterfaces;

    /**
     * @brief Uninstalls one or more protocol interfaces from a handle.
     */
    EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES UninstallMultipleProtocolInterfaces;

    /**
     * @brief Computes and returns a 32-bit CRC for a data buffer.
     */
    EFI_CALCULATE_CRC32 CalculateCrc32;

    /**
     * @brief Copies the contents of one buffer to another buffer.
     */
    EFI_COPY_MEM CopyMem;

    /**
     * @brief Fills a buffer with a specified value.
     */
    EFI_SET_MEM SetMem;

    /**
     * @brief Creates an event structure as part of an event group.
     */
    EFI_CREATE_EVENT_EX CreateEventEx;

} EFI_BOOT_SERVICES;

#endif
