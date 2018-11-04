
#include <ntifs.h>
#include "preprocessor.h"
#include "allocator.h"
#include "kernel-shared.h"
#include "ioctls.h"
#include "utils.h"
#include "utils-dym-array.h"
#include "handle-table.h"
#include "hook.h"
#include "req-queue.h"
#include "pnp-driver-watch.h"
#include "um-services.h"


/************************************************************************/
/*                     GLOBAL VARIABLES                                 */
/************************************************************************/

static PCHANDLE_TABLE _driverHandleTable = NULL;
static PCHANDLE_TABLE _deviceHandleTable = NULL;

/************************************************************************/
/*                     HELPER FUNCTIONS                                 */
/************************************************************************/

static VOID NTAPI _DriverHandleCreated(PCHANDLE_TABLE HandleTable, PVOID Object, HANDLE Handle)
{
	PDRIVER_HOOK_RECORD driverRecord = (PDRIVER_HOOK_RECORD)Object;
	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "_DriverHandleCreated\n");

	UNREFERENCED_PARAMETER(HandleTable);
	UNREFERENCED_PARAMETER(Handle);

	DriverHookRecordReference(driverRecord);

	return;
}

static VOID NTAPI _DriverHandleTranslated(PCHANDLE_TABLE HandleTable, PVOID Object, HANDLE Handle)
{
	PDRIVER_HOOK_RECORD driverRecord = (PDRIVER_HOOK_RECORD)Object;

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\n_DriverHandleTranslated");
	UNREFERENCED_PARAMETER(HandleTable);
	UNREFERENCED_PARAMETER(Handle);

	DriverHookRecordReference(driverRecord);

	return;
}

static VOID NTAPI _DriverHandleDeleted(PCHANDLE_TABLE HandleTable, PVOID Object, HANDLE Handle)
{
	PDRIVER_HOOK_RECORD driverRecord = (PDRIVER_HOOK_RECORD)Object;
	
	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\n_DriverHandleDeleted");
	UNREFERENCED_PARAMETER(HandleTable);
	UNREFERENCED_PARAMETER(Handle);

	DriverHookRecordDereference(driverRecord);

	return;
}


static VOID NTAPI _DeviceHandleCreated(PCHANDLE_TABLE HandleTable, PVOID Object, HANDLE Handle)
{
	PDEVICE_HOOK_RECORD deviceRecord = (PDEVICE_HOOK_RECORD)Object;

	UNREFERENCED_PARAMETER(HandleTable);
	UNREFERENCED_PARAMETER(Handle);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\n_DeviceHandleCreated");
	DeviceHookRecordReference(deviceRecord);

	return;
}

static VOID NTAPI _DevicerHandleTranslated(PCHANDLE_TABLE HandleTable, PVOID Object, HANDLE Handle)
{
	PDEVICE_HOOK_RECORD deviceRecord = (PDEVICE_HOOK_RECORD)Object;

	UNREFERENCED_PARAMETER(HandleTable);
	UNREFERENCED_PARAMETER(Handle);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\n_DevicerHandleTranslated");
	DeviceHookRecordReference(deviceRecord);
	return;
}

static VOID NTAPI _DeviceHandleDeleted(PCHANDLE_TABLE HandleTable, PVOID Object, HANDLE Handle)
{
	PDEVICE_HOOK_RECORD deviceRecord = (PDEVICE_HOOK_RECORD)Object;

	UNREFERENCED_PARAMETER(HandleTable);
	UNREFERENCED_PARAMETER(Handle);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\n_DeviceHandleDeleted");
	DeviceHookRecordDereference(deviceRecord);

	return;
}


/************************************************************************/
/*                    PUBLIC FUNCTIONS                                  */
/************************************************************************/

NTSTATUS UMHookDriver(PIOCTL_IRPMNDRV_HOOK_DRIVER_INPUT InputBuffer, ULONG InputBufferLength, PIOCTL_IRPMNDRV_HOOK_DRIVER_OUTPUT OutputBuffer, ULONG OutputBufferLength)
{
	PWCHAR tmp = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IOCTL_IRPMNDRV_HOOK_DRIVER_INPUT input = {0};
	IOCTL_IRPMNDRV_HOOK_DRIVER_OUTPUT output = {0};
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u; OutputBuffer=0x%p; OutputBufferLength=%u", InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMHookDriver");
	if (InputBufferLength >= sizeof(IOCTL_IRPMNDRV_HOOK_DRIVER_INPUT) &&
		OutputBufferLength >= sizeof(IOCTL_IRPMNDRV_HOOK_DRIVER_OUTPUT)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, sizeof(IOCTL_IRPMNDRV_HOOK_DRIVER_INPUT), 1);
				input = *InputBuffer;
				ProbeForWrite(OutputBuffer, sizeof(IOCTL_IRPMNDRV_HOOK_DRIVER_OUTPUT), 1);
				tmp = (PWCHAR)HeapMemoryAllocPaged(input.DriverNameLength + sizeof(WCHAR));
				if (tmp != NULL) {
					ProbeForRead(input.DriverName, input.DriverNameLength, 1);
					memcpy(tmp, input.DriverName, input.DriverNameLength);
					tmp[input.DriverNameLength / sizeof(WCHAR)] = L'\0';
					input.DriverName = tmp;
					status = STATUS_SUCCESS;
				} else status = STATUS_INSUFFICIENT_RESOURCES;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
				if (tmp != NULL)
					HeapMemoryFree(tmp);
			}
		} else {
			input = *InputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PDRIVER_OBJECT targetDriver = NULL;
			UNICODE_STRING uDriverName;

			RtlInitUnicodeString(&uDriverName, input.DriverName);
			status = GetDriverObjectByName(&uDriverName, &targetDriver);
			if (NT_SUCCESS(status)) {
				PDRIVER_HOOK_RECORD driverRecord = NULL;

				status = HookDriverObject(targetDriver, &input.MonitorSettings, &driverRecord);
				if (NT_SUCCESS(status)) {
					status = HandleTableHandleCreate(_driverHandleTable, driverRecord, &output.HookHandle);
					if (NT_SUCCESS(status)) {
						output.ObjectId = driverRecord;
						if (ExGetPreviousMode() == UserMode) {
							__try {
								*OutputBuffer = output;
							} __except (EXCEPTION_EXECUTE_HANDLER) {
								status = GetExceptionCode();
							}
						} else *OutputBuffer = output;

						if (!NT_SUCCESS(status))
							HandleTableHandleClose(_driverHandleTable, output.HookHandle);
					}

					if (!NT_SUCCESS(status))
						UnhookDriverObject(driverRecord);

					DriverHookRecordDereference(driverRecord);
				}
				
				ObDereferenceObject(targetDriver);
			}

			HeapMemoryFree(input.DriverName);
		}
	} else status = STATUS_INFO_LENGTH_MISMATCH;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

NTSTATUS UMUnhookDriver(PIOCTL_IRPMNDRV_UNHOOK_DRIVER_INPUT InputBuffer, ULONG InputBufferLength)
{
	IOCTL_IRPMNDRV_UNHOOK_DRIVER_INPUT input = {0};
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u", InputBuffer, InputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMUnhookDriver");
	if (InputBufferLength == sizeof(IOCTL_IRPMNDRV_UNHOOK_DRIVER_INPUT)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, InputBufferLength, 1);
				input = *InputBuffer;
				status = STATUS_SUCCESS;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else {
			input = *InputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PDRIVER_HOOK_RECORD driverRecord = NULL;

			status = HandleTablehandleTranslate(_driverHandleTable, input.HookHandle, (PVOID *)&driverRecord);
			if (NT_SUCCESS(status)) {
				status = UnhookDriverObject(driverRecord);
				DriverHookRecordDereference(driverRecord);
				if (NT_SUCCESS(status))
					HandleTableHandleClose(_driverHandleTable, input.HookHandle);
			}
		}
	} else status = STATUS_INFO_LENGTH_MISMATCH;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

NTSTATUS UMHookAddDevice(PIOCTL_IRPMNDRV_HOOK_ADD_DEVICE_INPUT InputBUffer, ULONG InputBufferLength, PIOCTL_IRPMNDRV_HOOK_ADD_DEVICE_OUTPUT OutputBuffer, ULONG OutputBufferLength)
{
	PWCHAR deviceName = NULL;
	IOCTL_IRPMNDRV_HOOK_ADD_DEVICE_INPUT input = {0};
	IOCTL_IRPMNDRV_HOOK_ADD_DEVICE_OUTPUT output = {0};
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("InputBufer=0x%p; InputBufferLength=%u; OutputBuffer=0x%p; OutputBufferLength=%u", InputBUffer, InputBufferLength, OutputBuffer, OutputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMHookAddDevice");
	if (InputBufferLength == sizeof(IOCTL_IRPMNDRV_HOOK_ADD_DEVICE_INPUT) &&
		OutputBufferLength == sizeof(IOCTL_IRPMNDRV_HOOK_ADD_DEVICE_OUTPUT)) {
		if (ExGetPreviousMode() == UserMode) {
			PUCHAR irpSettings = NULL;
			PUCHAR fastIoSettings = NULL;
			
			__try {
				status = STATUS_SUCCESS;
				ProbeForRead(InputBUffer, InputBufferLength, 1);
				input = *InputBUffer;
				ProbeForWrite(OutputBuffer, OutputBufferLength, 1);
				if (input.HookByName) {
					deviceName = (PWCHAR)HeapMemoryAllocPaged(input.DeviceNameLength + sizeof(WCHAR));
					if (deviceName != NULL) {
						ProbeForRead(input.DeviceName, input.DeviceNameLength, 1);
						memcpy(deviceName, input.DeviceName, input.DeviceNameLength);
						deviceName[input.DeviceNameLength / sizeof(WCHAR)] = L'\0';
						input.DeviceName = deviceName;
					} else status = STATUS_INSUFFICIENT_RESOURCES;
				} else input.DeviceName = NULL;

				if (NT_SUCCESS(status) && input.IRPSettings != NULL) {
					irpSettings = (PUCHAR)HeapMemoryAllocPaged(sizeof(UCHAR)*(IRP_MJ_MAXIMUM_FUNCTION + 1));
					if (irpSettings != NULL) {
						ProbeForRead(input.IRPSettings, sizeof(UCHAR)*(IRP_MJ_MAXIMUM_FUNCTION + 1), 1);
						memcpy(irpSettings, input.IRPSettings, sizeof(UCHAR)*(IRP_MJ_MAXIMUM_FUNCTION + 1));
						input.IRPSettings = irpSettings;
					} else status = STATUS_INSUFFICIENT_RESOURCES;
				}

				if (NT_SUCCESS(status) && input.FastIoSettings != NULL) {
					fastIoSettings = (PUCHAR)HeapMemoryAllocPaged(sizeof(UCHAR)*FastIoMax);
					if (irpSettings != NULL) {
						ProbeForRead(input.FastIoSettings, sizeof(UCHAR)*FastIoMax, 1);
						memcpy(fastIoSettings, input.FastIoSettings, sizeof(UCHAR)*FastIoMax);
						input.FastIoSettings = fastIoSettings;
					} else status = STATUS_INSUFFICIENT_RESOURCES;
				}

				if (!NT_SUCCESS(status))
					ExRaiseStatus(status);
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
				if (fastIoSettings != NULL)
					HeapMemoryFree(fastIoSettings);

				if (irpSettings != NULL)
					HeapMemoryFree(irpSettings);

				if (deviceName != NULL)
					HeapMemoryFree(deviceName);
			}
		} else {
			input = *InputBUffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PDEVICE_OBJECT targetDevice = NULL;

			if (input.HookByName) {
				UNICODE_STRING uDeviceName;

				RtlInitUnicodeString(&uDeviceName, deviceName);
				status = _GetDeviceAddress(&uDeviceName, TRUE, TRUE, &targetDevice);
			} else status = VerifyDeviceByAddress(input.DeviceAddress, TRUE, TRUE, &targetDevice);

			if (NT_SUCCESS(status)) {
				PDRIVER_HOOK_RECORD driverRecord = DriverHookRecordGet(targetDevice->DriverObject);

				if (driverRecord != NULL) {
					PDEVICE_HOOK_RECORD deviceRecord = NULL;

					status = DriverHookRecordAddDevice(driverRecord, targetDevice, input.IRPSettings, input.FastIoSettings, TRUE, &deviceRecord);
					if (NT_SUCCESS(status)) {
						status = HandleTableHandleCreate(_deviceHandleTable, deviceRecord, &output.DeviceHandle);
						if (NT_SUCCESS(status)) {
							output.ObjectId = deviceRecord;
							if (ExGetPreviousMode() == UserMode) {
								__try {
									*OutputBuffer = output;
								} __except (EXCEPTION_EXECUTE_HANDLER) {
									status = GetExceptionCode();
								}
							} else *OutputBuffer = output;
						
							if (!NT_SUCCESS(status))
								HandleTableHandleClose(_deviceHandleTable, output.DeviceHandle);
						}

						if (!NT_SUCCESS(status))
							DriverHookRecordDeleteDevice(deviceRecord);

						DeviceHookRecordDereference(deviceRecord);
					}

					DriverHookRecordDereference(driverRecord);
				} else status = STATUS_NOT_FOUND;

				ObDereferenceObject(targetDevice);
			}

			if (ExGetPreviousMode() == UserMode) {
				if (input.FastIoSettings != NULL)
					HeapMemoryFree(input.FastIoSettings);

				if (input.IRPSettings != NULL)
					HeapMemoryFree(input.IRPSettings);

				if (deviceName != NULL)
					HeapMemoryFree(deviceName);
			}
		}
	} else status = STATUS_INFO_LENGTH_MISMATCH;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

NTSTATUS UMHookDeleteDevice(PIOCTL_IRPMNDRV_HOOK_REMOVE_DEVICE_INPUT InputBuffer, ULONG InputBufferLength)
{
	IOCTL_IRPMNDRV_HOOK_REMOVE_DEVICE_INPUT input = {0};
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("InputBUffer=0x%p; InputBufferLength=%u", InputBuffer, InputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMHookDeleteDevice");
	if (InputBufferLength == sizeof(IOCTL_IRPMNDRV_HOOK_REMOVE_DEVICE_INPUT)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, InputBufferLength, 1);
				input = *InputBuffer;
				status = STATUS_SUCCESS;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else {
			input = *InputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PDEVICE_HOOK_RECORD deviceRecord = NULL;

			status = HandleTablehandleTranslate(_deviceHandleTable, input.DeviceHandle, &deviceRecord);
			if (NT_SUCCESS(status)) {
				status = DriverHookRecordDeleteDevice(deviceRecord);
				DeviceHookRecordDereference(deviceRecord);
				if (NT_SUCCESS(status))
					HandleTableHandleClose(_deviceHandleTable, input.DeviceHandle);
			}
		}
	} else status = STATUS_INFO_LENGTH_MISMATCH;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

NTSTATUS UMGetRequestRecord(PVOID Buffer, ULONG BufferLength, PULONG ReturnLength)
{
	REQUEST_GENERAL request;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("Buffer=0x%p; BufferLength=%u; ReturnLength=0x%p", Buffer, BufferLength, ReturnLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMGetRequestRecord");
	if (BufferLength >= sizeof(REQUEST_HEADER)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForWrite(Buffer, BufferLength, 1);
				status = STATUS_SUCCESS;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else status = STATUS_SUCCESS;

		if (NT_SUCCESS(status)) {
			status = RequestQueueGet(&request.RequestTypes.Other, &BufferLength);
			if (NT_SUCCESS(status)) {
				if (ExGetPreviousMode() == UserMode) {
					__try {
						memcpy(Buffer, &request, BufferLength);
						*ReturnLength = BufferLength;
					} __except (EXCEPTION_EXECUTE_HANDLER) {
						status = GetExceptionCode();
					}
				} else {
					memcpy(Buffer, &request, BufferLength);
					*ReturnLength = BufferLength;
				}
			}
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

NTSTATUS UMEnumDriversDevices(PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength)
{
	PDRIVER_OBJECT *driverDir = NULL;
	SIZE_T driverDirCount = 0;
	PDRIVER_OBJECT *fsDir = NULL;
	SIZE_T fsDirCount = 0;
	UNICODE_STRING uDirName;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("OutputBuffer=0x%p; OutputBufferLength=%u; ReturnLength=0x%p", OutputBuffer, OutputBufferLength, ReturnLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMEnumDriversDevices");
	*ReturnLength = 0;
	RtlInitUnicodeString(&uDirName, L"\\Driver");
	status = _GetDriversInDirectory(&uDirName, &driverDir, &driverDirCount);
	if (NT_SUCCESS(status)) {
		RtlInitUnicodeString(&uDirName, L"\\FileSystem");
		status = _GetDriversInDirectory(&uDirName, &fsDir, &fsDirCount);
		if (NT_SUCCESS(status)) {
			ULONG i = 0;
			PUM_DRIVER_INFO driverInfoArray = NULL;
			PUM_DRIVER_INFO tmp = NULL;
			ULONG driversCount = (ULONG)(driverDirCount + fsDirCount);

			driverInfoArray = (PUM_DRIVER_INFO)HeapMemoryAllocNonPaged(sizeof(UM_DRIVER_INFO)*driversCount);
			if (driverInfoArray != NULL) {
				// ULONG DriverCount
				ULONG requiredLength = sizeof(ULONG);

				tmp = driverInfoArray;
				for (i = 0; i < driversCount; ++i) {
					tmp->DriverObject = (i < driverDirCount) ? driverDir[i] : fsDir[i - driverDirCount];
					status = _EnumDriverDevices(tmp->DriverObject, &tmp->Devices, &tmp->DeviceCount);
					if (NT_SUCCESS(status)) {
						status = _GetObjectName(tmp->DriverObject, &tmp->DriverName);
						if (NT_SUCCESS(status)) {
							// PVOID Address, ULONG NameLen, WCHAR[] Name, ULONG DeviceCount
							requiredLength += sizeof(PDRIVER_OBJECT) + sizeof(ULONG) + tmp->DriverName.Length + sizeof(ULONG);
							tmp->DeviceInfo = (PUM_DEVICE_INFO)HeapMemoryAllocNonPaged(sizeof(UM_DEVICE_INFO)*tmp->DeviceCount);
							if (tmp->DeviceInfo != NULL) {
								ULONG k = 0;
								PUM_DEVICE_INFO tmpDeviceInfo = tmp->DeviceInfo;

								for (k = 0; k < tmp->DeviceCount; ++k) {
									tmpDeviceInfo->DeviceObject = tmp->Devices[k];
									tmpDeviceInfo->AttachedDevice = tmpDeviceInfo->DeviceObject->AttachedDevice;
									status = _GetObjectName(tmpDeviceInfo->DeviceObject, &tmpDeviceInfo->DeviceName);
									if (NT_SUCCESS(status))
										// PVOID Address, PVOID AttachedDevice, ULONG NameLen, WCHAR[] Name
										requiredLength += sizeof(PDEVICE_OBJECT) + sizeof(PDEVICE_OBJECT) + sizeof(ULONG) + tmpDeviceInfo->DeviceName.Length;
									
									if (!NT_SUCCESS(status)) {
										ULONG l = 0;

										--tmpDeviceInfo;
										for (l = 0; l < k; ++l) {
											if (tmpDeviceInfo->DeviceName.Buffer != NULL)
												HeapMemoryFree(tmpDeviceInfo->DeviceName.Buffer);

											--tmpDeviceInfo;
										}
									}

									++tmpDeviceInfo;
								}

								if (!NT_SUCCESS(status))
									HeapMemoryFree(tmp->DeviceInfo);
							} else status = STATUS_INSUFFICIENT_RESOURCES;
						
							if (!NT_SUCCESS(status)) {
								if (tmp->DriverName.Length > 0)
									HeapMemoryFree(tmp->DriverName.Buffer);
							}
						}
						
						if (!NT_SUCCESS(status))
							_ReleaseDeviceArray(tmp->Devices, tmp->DeviceCount);
					}

					if (!NT_SUCCESS(status)) {
						ULONG j = 0;

						--tmp;
						for (j = 0; j < i; ++j) {
							if (tmp->DriverName.Buffer != NULL)
								HeapMemoryFree(tmp->DriverName.Buffer);

							_ReleaseDeviceArray(tmp->Devices, tmp->DeviceCount);
							ObDereferenceObject(tmp->DriverObject);
							--tmp;
						}

						break;
					}

					++tmp;
				}

				if (NT_SUCCESS(status)) {
					if (OutputBufferLength >= requiredLength) {
						PMDL mdl = NULL;
						PUCHAR kernelBuffer = NULL;

						if (ExGetPreviousMode() == UserMode) {
							__try {
								ProbeForWrite(OutputBuffer, requiredLength, 1);
								mdl = IoAllocateMdl(OutputBuffer, requiredLength, FALSE, FALSE, NULL);
								if (mdl != NULL) {
									MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
									kernelBuffer = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
									if (kernelBuffer != NULL) {
										status = STATUS_SUCCESS;
									} else status = STATUS_INSUFFICIENT_RESOURCES;

									if (!NT_SUCCESS(status)) {
										MmUnlockPages(mdl);
										IoFreeMdl(mdl);
									}
								} else status = STATUS_INSUFFICIENT_RESOURCES;
							} __except (EXCEPTION_EXECUTE_HANDLER) {
								status = GetExceptionCode();								
								if (mdl != NULL)
									IoFreeMdl(mdl);
							}
						} else {
							kernelBuffer = (PUCHAR)OutputBuffer;
							status = STATUS_SUCCESS;
						}

						if (NT_SUCCESS(status)) {
							PUCHAR tmpKernelBuffer = kernelBuffer;

							tmp = driverInfoArray;
							memcpy(tmpKernelBuffer, &driversCount, sizeof(driversCount));
							tmpKernelBuffer += sizeof(driversCount);
							for (i = 0; i < driversCount; ++i) {
								ULONG j = 0;
								ULONG nameLen = tmp->DriverName.Length;
								PUM_DEVICE_INFO tmpDeviceInfo = tmp->DeviceInfo;

								memcpy(tmpKernelBuffer, &tmp->DriverObject, sizeof(PDRIVER_OBJECT));
								tmpKernelBuffer += sizeof(PDRIVER_OBJECT);
								memcpy(tmpKernelBuffer, &tmp->DeviceCount, sizeof(tmp->DeviceCount));
								tmpKernelBuffer += sizeof(tmp->DeviceCount);
								memcpy(tmpKernelBuffer, &nameLen, sizeof(nameLen));
								tmpKernelBuffer += sizeof(nameLen);
								memcpy(tmpKernelBuffer, tmp->DriverName.Buffer, nameLen);
								tmpKernelBuffer += nameLen;
								for (j = 0; j < tmp->DeviceCount; ++j) {
									memcpy(tmpKernelBuffer, &tmpDeviceInfo->DeviceObject, sizeof(PDEVICE_OBJECT));
									tmpKernelBuffer += sizeof(PDEVICE_OBJECT);
									memcpy(tmpKernelBuffer, &tmpDeviceInfo->AttachedDevice, sizeof(PDEVICE_OBJECT));
									tmpKernelBuffer += sizeof(PDEVICE_OBJECT);
									nameLen = tmpDeviceInfo->DeviceName.Length;
									memcpy(tmpKernelBuffer, &nameLen, sizeof(nameLen));
									tmpKernelBuffer += sizeof(nameLen);
									memcpy(tmpKernelBuffer, tmpDeviceInfo->DeviceName.Buffer, nameLen);
									tmpKernelBuffer += nameLen;
									++tmpDeviceInfo;
								}

								++tmp;
							}

							if (ExGetPreviousMode() == UserMode) {
								MmUnmapLockedPages(kernelBuffer, mdl);
								MmUnlockPages(mdl);
								IoFreeMdl(mdl);
							}

							*ReturnLength = requiredLength;
						}
					} else status = STATUS_BUFFER_TOO_SMALL;

					tmp = driverInfoArray;
					for (i = 0; i < driversCount; ++i) {
						ULONG j = 0;
						PUM_DEVICE_INFO tmpDeviceInfo = tmp->DeviceInfo;

						for (j = 0; j < tmp->DeviceCount; ++j) {
							if (tmpDeviceInfo->DeviceName.Buffer != NULL)
								HeapMemoryFree(tmpDeviceInfo->DeviceName.Buffer);

							++tmpDeviceInfo;
						}

						HeapMemoryFree(tmp->DeviceInfo);
						if (tmp->DriverName.Buffer != NULL)
							HeapMemoryFree(tmp->DriverName.Buffer);

						_ReleaseDeviceArray(tmp->Devices, tmp->DeviceCount);
						++tmp;
					}
				}

				HeapMemoryFree(driverInfoArray);
			} else status = STATUS_INSUFFICIENT_RESOURCES;

			_ReleaseDriverArray(fsDir, fsDirCount);
		}

		_ReleaseDriverArray(driverDir, driverDirCount);
	} 
	

	DEBUG_EXIT_FUNCTION("0x%x, *ReturnLength=%u", status, *ReturnLength);
	return status;
}

NTSTATUS UMRequestQueueConnect(PIOCTL_IRPMNDRV_CONNECT_INPUT InputBuffer, ULONG InputBufferLength)
{
	IOCTL_IRPMNDRV_CONNECT_INPUT input = {0};
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u", InputBuffer, InputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMRequestQueueConnect");
	if (InputBufferLength == sizeof(input)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, InputBufferLength, 1);
				input = *InputBuffer;
				status = STATUS_SUCCESS;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else {
			input = *InputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) 
			status = RequestQueueConnect(input.SemaphoreHandle);
	} else status = STATUS_INFO_LENGTH_MISMATCH;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

VOID UMRequestQueueDisconnect(VOID)
{
	DEBUG_ENTER_FUNCTION_NO_ARGS();

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMRequestQueueDisconnect");
	RequestQueueDisconnect();

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}

NTSTATUS UMHookedDriverSetInfo(PIOCTL_IRPMNDRV_HOOK_DRIVER_SET_INFO_INPUT InputBuffer, ULONG InputBufferLength)
{
	IOCTL_IRPMNDRV_HOOK_DRIVER_SET_INFO_INPUT input = {0};
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u", InputBuffer, InputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMHookedDriverSetInfo");
	if (InputBufferLength >= sizeof(input)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, sizeof(input), 1);
				input = *InputBuffer;
				status = STATUS_SUCCESS;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else {
			input = *InputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PDRIVER_HOOK_RECORD driverRecord = NULL;
		
			status = HandleTablehandleTranslate(_driverHandleTable, input.DriverHandle, &driverRecord);
			if (NT_SUCCESS(status)) {
				status = DriverHookRecordSetInfo(driverRecord, &input.Settings);
				DriverHookRecordDereference(driverRecord);
			}
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

NTSTATUS UMHookedDriverGetInfo(PIOCTL_IRPMNDRV_HOOK_DRIVER_GET_INFO_INPUT InputBuffer, ULONG InputBufferLength, PIOCTL_IRPMNDRV_HOOK_DRIVER_GET_INFO_OUTPUT OutputBuffer, ULONG OutputBufferLength)
{
	IOCTL_IRPMNDRV_HOOK_DRIVER_GET_INFO_INPUT input = {0};
	IOCTL_IRPMNDRV_HOOK_DRIVER_GET_INFO_OUTPUT output;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u; OutputBuffer=0x%p; OutputBufferLength=%u", InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMHookedDriverGetInfo");
	if (InputBufferLength >= sizeof(input) && OutputBufferLength >= sizeof(output)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, sizeof(input), 1);
				input = *InputBuffer;
				ProbeForWrite(OutputBuffer, sizeof(output), 1);
				status = STATUS_SUCCESS;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else {
			input = *InputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PDRIVER_HOOK_RECORD driverRecord = NULL;

			status = HandleTablehandleTranslate(_driverHandleTable, input.DriverHandle, &driverRecord);
			if (NT_SUCCESS(status)) {
				DriverHookRecordGetInfo(driverRecord, &output.Settings, &output.MonitoringEnabled);
				DriverHookRecordDereference(driverRecord);
				if (ExGetPreviousMode() == UserMode) {
					__try {
						*OutputBuffer = output;
					} __except (EXCEPTION_EXECUTE_HANDLER) {
						status = GetExceptionCode();
					}
				} else {
					*OutputBuffer = output;
				}
			}
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


NTSTATUS UMHookedDeviceSetInfo(PIOCTL_IRPMNDRV_HOOK_DEVICE_SET_INFO_INPUT InputBuffer, ULONG InputBufferLength)
{
	IOCTL_IRPMNDRV_HOOK_DEVICE_SET_INFO_INPUT input = { 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u", InputBuffer, InputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMHookedDeviceSetInfo");
	if (InputBufferLength >= sizeof(input)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				PUCHAR tmp = NULL;

				ProbeForRead(InputBuffer, sizeof(input), 1);
				input = *InputBuffer;
				status = STATUS_SUCCESS;
				if (input.IRPSettings != NULL) {
					tmp = (PUCHAR)HeapMemoryAllocNonPaged(sizeof(UCHAR)*0x1C);
					if (tmp != NULL) {
						__try {
							ProbeForRead(input.IRPSettings, sizeof(UCHAR) * 0x1C, 1);
							memcpy(tmp, input.IRPSettings, sizeof(UCHAR) * 0x1C);
							input.IRPSettings = tmp;
							status = STATUS_SUCCESS;
						} __except (EXCEPTION_EXECUTE_HANDLER) {
							status = GetExceptionCode();
						}

						if (!NT_SUCCESS(status))
							HeapMemoryFree(tmp);
					} else status = STATUS_INSUFFICIENT_RESOURCES;
				}

				if (NT_SUCCESS(status)) {
					if (input.FastIoSettings != NULL) {
						tmp = (PUCHAR)HeapMemoryAllocNonPaged(sizeof(UCHAR) * FastIoMax);
						if (tmp != NULL) {
							__try {
								ProbeForRead(input.FastIoSettings, sizeof(UCHAR) * FastIoMax, 1);
								memcpy(tmp, input.FastIoSettings, sizeof(UCHAR) * FastIoMax);
								input.FastIoSettings = tmp;
								status = STATUS_SUCCESS;
							} __except (EXCEPTION_EXECUTE_HANDLER) {
								status = GetExceptionCode();
							}

							if (!NT_SUCCESS(status))
								HeapMemoryFree(tmp);
						} else status = STATUS_INSUFFICIENT_RESOURCES;
					}

					if (!NT_SUCCESS(status)) {
						if (input.IRPSettings != NULL)
							HeapMemoryFree(input.IRPSettings);
					}
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		}
		else {
			input = *InputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PDEVICE_HOOK_RECORD deviceRecord = NULL;

			status = HandleTablehandleTranslate(_deviceHandleTable, input.DeviceHandle, &deviceRecord);
			if (NT_SUCCESS(status)) {
				status = DeviceHookRecordSetInfo(deviceRecord, input.IRPSettings, input.FastIoSettings, input.MonitoringEnabled);
				DeviceHookRecordDereference(deviceRecord);
			}

			if (ExGetPreviousMode() == UserMode) {
				if (input.FastIoSettings != NULL)
					HeapMemoryFree(input.FastIoSettings);

				if (input.IRPSettings != NULL)
					HeapMemoryFree(input.IRPSettings);
			}
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

NTSTATUS UMHookedDeviceGetInfo(PIOCTL_IRPMNDRV_HOOK_DEVICE_GET_INFO_INPUT InputBuffer, ULONG InputBufferLength, PIOCTL_IRPMNDRV_HOOK_DEVICE_GET_INFO_OUTPUT OutputBuffer, ULONG OutputBufferLength)
{
	IOCTL_IRPMNDRV_HOOK_DEVICE_GET_INFO_INPUT input = {0};
	IOCTL_IRPMNDRV_HOOK_DEVICE_GET_INFO_OUTPUT output;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u; OutputBuffer=0x%p; OutputBufferLength=%u", InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMHookedDeviceGetInfo");
	if (InputBufferLength >= sizeof(input) && OutputBufferLength >= sizeof(output)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, sizeof(input), 1);
				input = *InputBuffer;
				ProbeForWrite(OutputBuffer, sizeof(output), 1);
				status = STATUS_SUCCESS;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		}
		else {
			input = *InputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PDEVICE_HOOK_RECORD deviceRecord = NULL;

			status = HandleTablehandleTranslate(_deviceHandleTable, input.DeviceHandle, &deviceRecord);
			if (NT_SUCCESS(status)) {
				DeviceHookRecordGetInfo(deviceRecord, output.IRPSettings, output.FastIoSettings, &output.MonitoringEnabled);
				DeviceHookRecordDereference(deviceRecord);
				if (ExGetPreviousMode() == UserMode) {
					__try {
						*OutputBuffer = output;
					} __except (EXCEPTION_EXECUTE_HANDLER) {
						status = GetExceptionCode();
					}
				} else *OutputBuffer = output;
			}
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


NTSTATUS UMHookedDriverMonitoringEnable(PIOCTL_IRPMNDRV_HOOK_DRIVER_MONITORING_CHANGE_INPUT InputBuffer, ULONG InputBufferLength)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IOCTL_IRPMNDRV_HOOK_DRIVER_MONITORING_CHANGE_INPUT input = {0};
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u", InputBuffer, InputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMHookedDriverMonitoringEnable");
	if (InputBufferLength >= sizeof(IOCTL_IRPMNDRV_HOOK_DRIVER_MONITORING_CHANGE_INPUT)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, sizeof(IOCTL_IRPMNDRV_HOOK_DRIVER_MONITORING_CHANGE_INPUT), 1);
				input = *InputBuffer;
				status = STATUS_SUCCESS;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else {
			input = *InputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PDRIVER_HOOK_RECORD driverRecord = NULL;

			status = HandleTablehandleTranslate(_driverHandleTable, input.DriverHandle, (PVOID *)&driverRecord);
			if (NT_SUCCESS(status)) {
				status = DriverHookRecordEnable(driverRecord, input.EnableMonitoring);
				DriverHookRecordDereference(driverRecord);
			}
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

NTSTATUS UMHookedObjectsEnumerate(PIOCTL_IRPMONDRV_HOOK_GET_INFO_OUTPUT OutputBuffer, ULONG OutputBufferLength)
{
	PMDL mdl = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PIOCTL_IRPMONDRV_HOOK_GET_INFO_OUTPUT kernelAddress = NULL;
	DEBUG_ENTER_FUNCTION("OutputBuffer=0x%p; OutputBufferLength=%u", OutputBuffer, OutputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMHookedObjectsEnumerate");
	if (OutputBufferLength >=  sizeof(IOCTL_IRPMONDRV_HOOK_GET_INFO_OUTPUT)) {
		if (ExGetPreviousMode() == UserMode) {
			mdl = IoAllocateMdl(OutputBuffer, OutputBufferLength, FALSE, FALSE, NULL);
			if (mdl != NULL) {
				__try {
					MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
					status = STATUS_SUCCESS;
				} __except (EXCEPTION_EXECUTE_HANDLER) {
					status = GetExceptionCode();
				}

				if (NT_SUCCESS(status)) {
					kernelAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
					if (kernelAddress == NULL) {
						MmUnlockPages(mdl);
						status = STATUS_INSUFFICIENT_RESOURCES;
					}
				}

				if (!NT_SUCCESS(status))
					IoFreeMdl(mdl);
			} else status = STATUS_INSUFFICIENT_RESOURCES;
		} else {
			kernelAddress = OutputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			status= HookObjectsEnumerate(&kernelAddress->Info, OutputBufferLength, &OutputBufferLength);
			if (ExGetPreviousMode() == UserMode) {
				MmUnmapLockedPages(kernelAddress, mdl);
				MmUnlockPages(mdl);
				IoFreeMdl(mdl);
			}
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

VOID UMDeleteHandlesForProcess(PEPROCESS Process)
{
	DEBUG_ENTER_FUNCTION("Process=0x%p", Process);

	UNREFERENCED_PARAMETER(Process);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMDeleteHandlesForProcess");
	HandleTableClear(_deviceHandleTable);
	HandleTableClear(_driverHandleTable);

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}

NTSTATUS UMOpenObjectById(PIOCTL_IRPMONDRV_HOOK_OPEN_INPUT InputBuffer, ULONG InputBufferLength, PIOCTL_IRPMONDRV_HOOK_OPEN_OUTPUT OutputBuffer, ULONG OutputBufferLength)
{
	IOCTL_IRPMONDRV_HOOK_OPEN_INPUT input = {0};
	IOCTL_IRPMONDRV_HOOK_OPEN_OUTPUT output = {0};
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u; OutputBuffer=0x%p; OutputBufferLength=%u", InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMOpenObjectById");
	if (InputBufferLength == sizeof(IOCTL_IRPMONDRV_HOOK_OPEN_INPUT) &&
		OutputBufferLength == sizeof(IOCTL_IRPMONDRV_HOOK_OPEN_OUTPUT)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, InputBufferLength, 1);
				input = *InputBuffer;
				ProbeForWrite(OutputBuffer, OutputBufferLength, 1);
				status = STATUS_SUCCESS;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else {
			input = *InputBuffer;
			output = *OutputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PVOID record = NULL;
			BOOLEAN verified = FALSE;
			PCHANDLE_TABLE handleTable = NULL;

			record = input.ObjectId;
			switch (input.ObjectType) {
				case ehtDriver:
					handleTable = _driverHandleTable;
					verified = DriverHookRecordValid((PDRIVER_HOOK_RECORD)record);
					break;
				case ehtDevice:
					handleTable = _deviceHandleTable;
					verified = DeviceHookRecordValid((PDEVICE_HOOK_RECORD)record);
					break;
				default:
					status = STATUS_INVALID_PARAMETER_1;
					break;
			}

			if (NT_SUCCESS(status) && !verified)
				status = STATUS_INVALID_PARAMETER_2;
		
			if (NT_SUCCESS(status)) {
				status = HandleTableHandleCreate(handleTable, record, &output.Handle);
				if (NT_SUCCESS(status)) {
					if (ExGetPreviousMode() == UserMode) {
						__try {
							*OutputBuffer = output;
						} __except (EXCEPTION_EXECUTE_HANDLER) {
							status = GetExceptionCode();
						}
					} else *OutputBuffer = output;

					if (!NT_SUCCESS(status))
						HandleTableHandleClose(handleTable, output.Handle);
				}

				switch (input.ObjectType) {
					case ehtDriver:
						DriverHookRecordDereference((PDRIVER_HOOK_RECORD)record);
						break;
					case ehtDevice:
						DeviceHookRecordDereference((PDEVICE_HOOK_RECORD)record);
						break;
					default:
						ASSERT(FALSE);
						break;
				}
			}
		}
	} else status = STATUS_INFO_LENGTH_MISMATCH;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

NTSTATUS UMCloseHandle(PIOCTL_IRPMONDRV_HOOK_CLOSE_INPUT InputBuffer, ULONG InputBufferLength)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IOCTL_IRPMONDRV_HOOK_CLOSE_INPUT input = {0};
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u", InputBuffer, InputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMCloseHandle");
	if (InputBufferLength == sizeof(IOCTL_IRPMONDRV_HOOK_CLOSE_INPUT)) {
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, InputBufferLength, 1);
				input = *InputBuffer;
				status = STATUS_SUCCESS;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else {
			input = *InputBuffer;
			status = STATUS_SUCCESS;
		}

		if (NT_SUCCESS(status)) {
			PCHANDLE_TABLE handleTable = NULL;

			switch (input.ObjectType) {
				case ehtDriver:
					handleTable = _driverHandleTable;
					break;
				case ehtDevice:
					handleTable = _deviceHandleTable;
					break;
				default:
					status = STATUS_INVALID_PARAMETER;
					break;
			}

			if (NT_SUCCESS(status))
				status = HandleTableHandleClose(handleTable, input.Handle);
		}
	} else status = STATUS_INFO_LENGTH_MISMATCH;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


NTSTATUS UMClassWatchRegister(PIOCTL_IRPMNDRV_CLASS_WATCH_REGISTER_INPUT InputBuffer, ULONG InputBufferLength)
{
	GUID classGuid;
	UNICODE_STRING uClassGuid;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IOCTL_IRPMNDRV_CLASS_WATCH_REGISTER_INPUT input = {0};
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u", InputBuffer, InputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMClassWatchRegister");
	if (InputBufferLength >= sizeof(IOCTL_IRPMNDRV_CLASS_WATCH_REGISTER_INPUT)) {
		status = STATUS_SUCCESS;
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, sizeof(input), 1);
				input = *InputBuffer;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else input = *InputBuffer;

		if (NT_SUCCESS(status)) {
			if ((input.Flags & CLASS_WATCH_FLAG_BINARY) == 0) {
				uClassGuid.Length = sizeof(input.Data.ClassGuidString);
				uClassGuid.MaximumLength = uClassGuid.Length;
				uClassGuid.Buffer = input.Data.ClassGuidString;
				status = RtlGUIDFromString(&uClassGuid, &classGuid);
			} else classGuid = input.Data.ClassGuidBinary;

			if (NT_SUCCESS(status))
				status = PDWClassRegister(&classGuid, (input.Flags & CLASS_WATCH_FLAG_UPPERFILTER), (input.Flags & CLASS_WATCH_FLAG_BEGINNING));
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


NTSTATUS UMClassWatchUnregister(PIOCTL_IRPMNDRV_CLASS_WATCH_UNREGISTER_INPUT InputBuffer, ULONG InputBUfferLength)
{
	GUID classGuid;
	UNICODE_STRING uClassGuid;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IOCTL_IRPMNDRV_CLASS_WATCH_UNREGISTER_INPUT input = { 0 };
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBUfferLength=%u", InputBuffer, InputBUfferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMClassWatchUnregister");
	if (InputBUfferLength >= sizeof(IOCTL_IRPMNDRV_CLASS_WATCH_UNREGISTER_INPUT)) {
		status = STATUS_SUCCESS;
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, sizeof(input), 1);
				input = *InputBuffer;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
			}
		} else input = *InputBuffer;

		if (NT_SUCCESS(status)) {
			if ((input.Flags & CLASS_WATCH_FLAG_BINARY) == 0) {
				uClassGuid.Length = sizeof(input.Data.ClassGuidString);
				uClassGuid.MaximumLength = uClassGuid.Length;
				uClassGuid.Buffer = input.Data.ClassGuidString;
				status = RtlGUIDFromString(&uClassGuid, &classGuid);
			} else classGuid = input.Data.ClassGuidBinary;

			if (NT_SUCCESS(status))
				status = PDWClassUnregister(&classGuid, (input.Flags & CLASS_WATCH_FLAG_UPPERFILTER), (input.Flags & CLASS_WATCH_FLAG_BEGINNING));
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


NTSTATUS UMDriverNameWatchRegister(PIOCTL_IRPMNDRV_DRIVER_WATCH_REGISTER_INPUT InputBuffer, ULONG InputBufferLength)
{
	UNICODE_STRING uDriverName;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IOCTL_IRPMNDRV_DRIVER_WATCH_REGISTER_INPUT input = {0};
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBufferLength=%u", InputBuffer, InputBufferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMDriverNameWatchRegister");
	if (InputBufferLength >= sizeof(IOCTL_IRPMNDRV_DRIVER_WATCH_REGISTER_INPUT)) {
		RtlSecureZeroMemory(&uDriverName, sizeof(uDriverName));
		InputBufferLength -= sizeof(IOCTL_IRPMNDRV_DRIVER_WATCH_REGISTER_INPUT);
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, sizeof(input), 1);
				input = *InputBuffer;
				if (input.NameLength <= InputBufferLength) {
					ProbeForRead(InputBuffer + 1, input.NameLength, 1);
					uDriverName.Length = input.NameLength;
					uDriverName.MaximumLength = uDriverName.Length;
					uDriverName.Buffer = (PWCHAR)HeapMemoryAllocPaged(uDriverName.Length);
					if (uDriverName.Buffer != NULL) {
						memcpy(uDriverName.Buffer, InputBuffer + 1, uDriverName.Length);
						status = STATUS_SUCCESS;
					} else status = STATUS_INSUFFICIENT_RESOURCES;
				} else status = STATUS_BUFFER_TOO_SMALL;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
				if (uDriverName.Buffer != NULL)
					HeapMemoryFree(uDriverName.Buffer);
			}
		} else {
			input = *InputBuffer;
			if (input.NameLength <= InputBufferLength) {
				uDriverName.Length = input.NameLength;
				uDriverName.MaximumLength = uDriverName.Length;
				uDriverName.Buffer = (PWCHAR)HeapMemoryAllocPaged(uDriverName.Length);
				if (uDriverName.Buffer != NULL) {
					memcpy(uDriverName.Buffer, InputBuffer + 1, uDriverName.Length);
					status = STATUS_SUCCESS;
				} else status = STATUS_INSUFFICIENT_RESOURCES;
			} else status = STATUS_BUFFER_TOO_SMALL;
		}

		if (NT_SUCCESS(status)) {
			status = PWDDriverNameRegister(&uDriverName, &input.MonitorSettings);
			HeapMemoryFree(uDriverName.Buffer);
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


NTSTATUS UMDriverNamehUnregister(PIOCTL_IRPMNDRV_DRIVER_WATCH_UNREGISTER_INPUT InputBuffer, ULONG InputBUfferLength)
{
	UNICODE_STRING uDriverName;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IOCTL_IRPMNDRV_DRIVER_WATCH_UNREGISTER_INPUT input = { 0 };
	DEBUG_ENTER_FUNCTION("InputBuffer=0x%p; InputBUfferLength=%u", InputBuffer, InputBUfferLength);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMDriverNamehUnregister");
	if (InputBUfferLength >= sizeof(IOCTL_IRPMNDRV_DRIVER_WATCH_UNREGISTER_INPUT)) {
		RtlSecureZeroMemory(&uDriverName, sizeof(uDriverName));
		InputBUfferLength -= sizeof(IOCTL_IRPMNDRV_DRIVER_WATCH_UNREGISTER_INPUT);
		if (ExGetPreviousMode() == UserMode) {
			__try {
				ProbeForRead(InputBuffer, sizeof(input), 1);
				input = *InputBuffer;
				if (input.NameLength <= InputBUfferLength) {
					ProbeForRead(InputBuffer + 1, input.NameLength, 1);
					uDriverName.Length = input.NameLength;
					uDriverName.MaximumLength = uDriverName.Length;
					uDriverName.Buffer = (PWCHAR)HeapMemoryAllocPaged(uDriverName.Length);
					if (uDriverName.Buffer != NULL) {
						memcpy(uDriverName.Buffer, InputBuffer + 1, uDriverName.Length);
						status = STATUS_SUCCESS;
					} else status = STATUS_INSUFFICIENT_RESOURCES;
				} else status = STATUS_BUFFER_TOO_SMALL;
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				status = GetExceptionCode();
				if (uDriverName.Buffer != NULL)
					HeapMemoryFree(uDriverName.Buffer);
			}
		} else {
			input = *InputBuffer;
			if (input.NameLength <= InputBUfferLength) {
				uDriverName.Length = input.NameLength;
				uDriverName.MaximumLength = uDriverName.Length;
				uDriverName.Buffer = (PWCHAR)HeapMemoryAllocPaged(uDriverName.Length);
				if (uDriverName.Buffer != NULL) {
					memcpy(uDriverName.Buffer, InputBuffer + 1, uDriverName.Length);
					status = STATUS_SUCCESS;
				} else status = STATUS_INSUFFICIENT_RESOURCES;
			} else status = STATUS_BUFFER_TOO_SMALL;
		}

		if (NT_SUCCESS(status)) {
			status = PWDDriverNameUnregister(&uDriverName);
			HeapMemoryFree(uDriverName.Buffer);
		}
	} else status = STATUS_BUFFER_TOO_SMALL;

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}



/************************************************************************/
/*                   INITIALIZATION AND FINALIZATION                    */
/************************************************************************/

NTSTATUS UMServicesModuleInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath, PVOID Context)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p; RegistryPath=\"%wZ\"; Context=0x%p", DriverObject, RegistryPath, Context);

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(Context);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMServicesModuleInit");
	status = HandleTableCreate(httPassiveLevel, _DriverHandleCreated, _DriverHandleDeleted, _DriverHandleTranslated, &_driverHandleTable);
	if (NT_SUCCESS(status)) {
		status = HandleTableCreate(httPassiveLevel, _DeviceHandleCreated, _DeviceHandleDeleted, _DevicerHandleTranslated, &_deviceHandleTable);
		if (!NT_SUCCESS(status)) 
			HandleTableDestroy(_driverHandleTable);
	}

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}

VOID UMServicesModuleFinit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath, PVOID Context)
{
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p; PUNICODE_STRING RegistryPath=\"%wZ\"; Context=0x%p", DriverObject, RegistryPath, Context);

	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nUMServicesModuleFinit");
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(Context);

	HandleTableDestroy(_deviceHandleTable);
	HandleTableDestroy(_driverHandleTable);

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}
