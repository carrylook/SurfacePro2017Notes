
#include <ntifs.h>
#include <Ntddstor.h>
#include <fltkernel.h>
#include <poclass.h>
#include "preprocessor.h"
#include "allocator.h"
#include "kernel-shared.h"
#include "utils.h"
#include "hook.h"
#include "req-queue.h"
#include "hook-handlers.h"
#include "spb1.h"


#undef DEBUG_TRACE_ENABLED
#define DEBUG_TRACE_ENABLED 0

void DbgAcpiNotifyIoctl(PIRP Irp, PIO_STACK_LOCATION irpStack, int requestType);

/************************************************************************/
/*                       GLOBAL VARIABLES                               */
/************************************************************************/

static IO_REMOVE_LOCK _rundownLock;
PDRIVER_OBJECT surfaceAcpiNotifyObject = 0;
PDRIVER_OBJECT cmBattObject = 0;



/************************************************************************/
/*                        HELPER ROUTINES                               */
/************************************************************************/


static PREQUEST_FASTIO _CreateFastIoRequest(EFastIoOperationType FastIoType, PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT DeviceObject, PVOID FileObject, PVOID Arg1, PVOID Arg2, PVOID Arg3, PVOID Arg4, PVOID Arg5, PVOID Arg6, PVOID Arg7)
{
	PREQUEST_FASTIO ret = NULL;

	ret = (PREQUEST_FASTIO)HeapMemoryAllocNonPaged(sizeof(REQUEST_FASTIO));
	if (ret != NULL) {
		RequestHeaderInit(&ret->Header, DriverObject, DeviceObject, ertFastIo);
		ret->FastIoType = FastIoType;
		ret->FileObject = FileObject;
		ret->PreviousMode = ExGetPreviousMode();
		ret->Arg1 = Arg1;
		ret->Arg2 = Arg2;
		ret->Arg3 = Arg3;
		ret->Arg4 = Arg4;
		ret->Arg5 = Arg5;
		ret->Arg6 = Arg6;
		ret->Arg7 = Arg7;
		ret->IOSBInformation = 0;
		ret->IOSBStatus = STATUS_UNSUCCESSFUL;
	}

	return ret;
}


static BOOLEAN _CatchRequest(PDRIVER_HOOK_RECORD DriverHookRecord, PDEVICE_HOOK_RECORD DeviceHookRecord, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (DriverHookRecord->MonitoringEnabled) {
		if (DriverHookRecord->MonitorNewDevices && DeviceHookRecord == NULL) {
			if (DeviceObject != NULL) {
				status = DriverHookRecordAddDevice(DriverHookRecord, DeviceObject, NULL, NULL, TRUE, &deviceRecord);
				if (NT_SUCCESS(status)) {
					PREQUEST_HEADER rq = NULL;

					status = RequestXXXDetectedCreate(ertDeviceDetected, DeviceObject->DriverObject, DeviceObject, &rq);
					if (NT_SUCCESS(status))
						RequestQueueInsert(rq);

					DeviceHookRecordDereference(deviceRecord);
				}

				ret = TRUE;
			}
		} else ret = (DeviceHookRecord != NULL && DeviceHookRecord->MonitoringEnabled);
	}

	return ret;
}


#define GetDeviceObject(aFileObject)			\
	(((aFileObject)->Vpb != NULL) ? (aFileObject)->Vpb->DeviceObject : (aFileObject)->DeviceObject)		\


/************************************************************************/
/*                        FAST IO ROUTINES                              */
/************************************************************************/

BOOLEAN HookHandlerFastIoCheckIfPossible(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, ULONG LockKey, BOOLEAN CheckForReadOperation, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoCheckIfPossible, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, (PVOID)Length, (PVOID)CheckForReadOperation, (PVOID)Wait, (PVOID)LockKey, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoCheckIfPossible(FileObject, FileOffset, Length, Wait, LockKey, CheckForReadOperation, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				request->IOSBStatus = IoStatusBlock->Status;
				request->IOSBInformation = IoStatusBlock->Information;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


VOID HookHandlerFastIoDetachDevice(PDEVICE_OBJECT SourceDevice, PDEVICE_OBJECT TargetDevice)
{
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(SourceDevice->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, SourceDevice);
		if (_CatchRequest(driverRecord, deviceRecord, SourceDevice))
			request = _CreateFastIoRequest(FastIoDetachDevice, SourceDevice->DriverObject, SourceDevice, NULL, SourceDevice, TargetDevice, NULL, NULL, NULL, NULL, NULL);

		driverRecord->OldFastIoDisptach.FastIoDetachDevice(SourceDevice, TargetDevice);
		if (request != NULL)
			RequestQueueInsert(&request->Header);

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", SourceDevice->DriverObject);
	}

	return;
}


BOOLEAN HookHandlerFastIoDeviceControl(PFILE_OBJECT FileObject, BOOLEAN Wait, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, ULONG ControlCode, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoDeviceControl, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)OutputBufferLength, (PVOID)InputBufferLength, (PVOID)ControlCode, (PVOID)Wait, InputBuffer, OutputBuffer, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoDeviceControl(FileObject, Wait, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ControlCode, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoLock(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PLARGE_INTEGER Length, PEPROCESS ProcessId, ULONG Key, BOOLEAN FailImmediately, BOOLEAN Exclusive, PIO_STATUS_BLOCK StatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoLock, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, (PVOID)Length->LowPart, (PVOID)Length->HighPart, (PVOID)(((FailImmediately != 0) << 1) + (Exclusive != 0)), ProcessId, (PVOID)Key);

		ret = driverRecord->OldFastIoDisptach.FastIoLock(FileObject, FileOffset, Length, ProcessId, Key, FailImmediately, Exclusive, StatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && StatusBlock != NULL) {
				request->IOSBInformation = StatusBlock->Information;
				request->IOSBStatus = StatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoQueryBasicInfo(PFILE_OBJECT FileObject, BOOLEAN Wait, PFILE_BASIC_INFORMATION Buffer, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoQueryBasicInfo, DeviceObject->DriverObject, DeviceObject, FileObject, Buffer, (PVOID)Wait, NULL, NULL, NULL, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoQueryBasicInfo(FileObject, Wait, Buffer, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				if (NT_SUCCESS(IoStatusBlock->Status)) {
					request->Arg1 = (PVOID)Buffer->CreationTime.LowPart;
					request->Arg2 = (PVOID)Buffer->CreationTime.HighPart;
					request->Arg3 = (PVOID)Buffer->LastAccessTime.LowPart;
					request->Arg4 = (PVOID)Buffer->LastAccessTime.HighPart;
					request->Arg5 = (PVOID)Buffer->LastWriteTime.LowPart;
					request->Arg6 = (PVOID)Buffer->LastWriteTime.HighPart;
					request->Arg7 = (PVOID)Buffer->FileAttributes;
					/* TODO: Add more members */
				}

				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoQueryNetworkOpenInfo(PFILE_OBJECT FileObject, BOOLEAN Wait, PFILE_NETWORK_OPEN_INFORMATION Buffer, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoQueryNetworkOpenInfo, DeviceObject->DriverObject, DeviceObject, FileObject, Buffer, (PVOID)Wait, NULL, NULL, NULL, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoQueryNetworkOpenInfo(FileObject, Wait, Buffer, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				if (NT_SUCCESS(IoStatusBlock->Status)) {
					request->Arg1 = (PVOID)Buffer->CreationTime.LowPart;
					request->Arg2 = (PVOID)Buffer->CreationTime.HighPart;
					request->Arg3 = (PVOID)Buffer->LastAccessTime.LowPart;
					request->Arg4 = (PVOID)Buffer->LastAccessTime.HighPart;
					request->Arg5 = (PVOID)Buffer->LastWriteTime.LowPart;
					request->Arg6 = (PVOID)Buffer->LastWriteTime.HighPart;
					request->Arg7 = (PVOID)Buffer->FileAttributes;
					/* TODO: Add more members */
				}

				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoQueryOpenInfo(PIRP Irp, PFILE_NETWORK_OPEN_INFORMATION Buffer, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject)) {
			PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
			request = _CreateFastIoRequest(FastIoQueryOpen, DeviceObject->DriverObject, DeviceObject, irpStack->FileObject, Irp, Buffer, NULL, NULL, NULL, NULL, NULL);
		}

		ret = driverRecord->OldFastIoDisptach.FastIoQueryOpen(Irp, Buffer, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret) {
				request->Arg1 = (PVOID)Buffer->CreationTime.LowPart;
				request->Arg2 = (PVOID)Buffer->CreationTime.HighPart;
				request->Arg3 = (PVOID)Buffer->LastAccessTime.LowPart;
				request->Arg4 = (PVOID)Buffer->LastAccessTime.HighPart;
				request->Arg5 = (PVOID)Buffer->LastWriteTime.LowPart;
				request->Arg6 = (PVOID)Buffer->LastWriteTime.HighPart;
				request->Arg7 = (PVOID)Buffer->FileAttributes;
				/* TODO: Add more members */
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoQueryStandardInfo(PFILE_OBJECT FileObject, BOOLEAN Wait, PFILE_STANDARD_INFORMATION Buffer, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoQueryStandardInfo, DeviceObject->DriverObject, DeviceObject, FileObject, Buffer, (PVOID)Wait, NULL, NULL, NULL, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoQueryStandardInfo(FileObject, Wait, Buffer, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				if (NT_SUCCESS(IoStatusBlock->Status)) {
					request->Arg1 = (PVOID)Buffer->AllocationSize.LowPart;
					request->Arg2 = (PVOID)Buffer->AllocationSize.HighPart;
					request->Arg3 = (PVOID)Buffer->EndOfFile.LowPart;
					request->Arg4 = (PVOID)Buffer->EndOfFile.HighPart;
					request->Arg5 = (PVOID)Buffer->NumberOfLinks;
					request->Arg6 = (PVOID)Buffer->Directory;
					request->Arg7 = (PVOID)Buffer->DeletePending;
					/* TODO: Add more members (Buffer,Wait) */
				}

				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoRead(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, ULONG LockKey, PVOID Buffer, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoRead, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, (PVOID)Length, (PVOID)LockKey, (PVOID)Wait, Buffer, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoRead(FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoUnlockAll(PFILE_OBJECT FileObject, PEPROCESS ProcessId, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoUnlockAll, DeviceObject->DriverObject, DeviceObject, FileObject, ProcessId, NULL, NULL, NULL, NULL, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoUnlockAll(FileObject, ProcessId, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}
			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoUnlockByKey(PFILE_OBJECT FileObject, PVOID ProcessId, ULONG Key, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoUnlockAllByKey, DeviceObject->DriverObject, DeviceObject, FileObject, ProcessId, (PVOID)Key, NULL, NULL, NULL, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoUnlockAllByKey(FileObject, ProcessId, Key, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoUnlockSingle(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PLARGE_INTEGER Length, PEPROCESS ProcessId, ULONG Key, PIO_STATUS_BLOCK StatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoUnlockSingle, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, (PVOID)Length->LowPart, (PVOID)Length->HighPart, ProcessId, (PVOID)Key, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoUnlockSingle(FileObject, FileOffset, Length, ProcessId, Key, StatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && StatusBlock != NULL) {
				request->IOSBInformation = StatusBlock->Information;
				request->IOSBStatus = StatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoWrite(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, BOOLEAN Wait, ULONG LockKey, PVOID Buffer, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoWrite, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, (PVOID)Length, (PVOID)LockKey, (PVOID)Wait, Buffer, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoWrite(FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		ret = DeviceObject->DriverObject->FastIoDispatch->FastIoWrite(FileObject, FileOffset, Length, Wait, LockKey, Buffer, IoStatusBlock, DeviceObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoMdlRead(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG LockKey, PMDL *MdlChain, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(MdlRead, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, (PVOID)Length, (PVOID)LockKey, MdlChain, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.MdlRead(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		ret = DeviceObject->DriverObject->FastIoDispatch->MdlRead(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatusBlock, DeviceObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoMdlWrite(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG LockKey, PMDL *MdlChain, PIO_STATUS_BLOCK IoStatusBlock, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(PrepareMdlWrite, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, (PVOID)Length, (PVOID)LockKey, MdlChain, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.PrepareMdlWrite(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatusBlock, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		ret = DeviceObject->DriverObject->FastIoDispatch->PrepareMdlWrite(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatusBlock, DeviceObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoMdlReadComplete(PFILE_OBJECT FileObject, PMDL MdlChain, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(MdlReadComplete, DeviceObject->DriverObject, DeviceObject, FileObject, MdlChain, NULL, NULL, NULL, NULL, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.MdlReadComplete(FileObject, MdlChain, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		ret = DeviceObject->DriverObject->FastIoDispatch->MdlReadComplete(FileObject, MdlChain, DeviceObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoMdlWriteComplete(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PMDL MdlChain, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(MdlWriteComplete, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, MdlChain, NULL, NULL, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.MdlWriteComplete(FileObject, FileOffset, MdlChain, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		ret = DeviceObject->DriverObject->FastIoDispatch->MdlWriteComplete(FileObject, FileOffset, MdlChain, DeviceObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoReadCompressed(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG LockKey, PVOID Buffer, PMDL *MdlChain, PIO_STATUS_BLOCK IoStatusBlock, PCOMPRESSED_DATA_INFO CompressedInfo, ULONG CompressedInfoLength, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoReadCompressed, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, (PVOID)Length, (PVOID)LockKey, (PVOID)Buffer, (PVOID)CompressedInfoLength, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoReadCompressed(FileObject, FileOffset, Length, LockKey, Buffer, MdlChain, IoStatusBlock, CompressedInfo, CompressedInfoLength, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				if (NT_SUCCESS(IoStatusBlock->Status)) {
					if (MdlChain != NULL)
						request->Arg7 = *MdlChain;				
				}

				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		ret = DeviceObject->DriverObject->FastIoDispatch->FastIoReadCompressed(FileObject, FileOffset, Length, LockKey, Buffer, MdlChain, IoStatusBlock, CompressedInfo, CompressedInfoLength, DeviceObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoWriteCompressed(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, ULONG Length, ULONG LockKey, PVOID Buffer, PMDL *MdlChain, PIO_STATUS_BLOCK IoStatusBlock, PCOMPRESSED_DATA_INFO CompressedInfo, ULONG CompressedInfoLength, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(FastIoWriteCompressed, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, (PVOID)Length, (PVOID)LockKey, Buffer, (PVOID)CompressedInfoLength, NULL);

		ret = driverRecord->OldFastIoDisptach.FastIoWriteCompressed(FileObject, FileOffset, Length, LockKey, Buffer, MdlChain, IoStatusBlock, CompressedInfo, CompressedInfoLength, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			if (ret && IoStatusBlock != NULL) {
				if (NT_SUCCESS(IoStatusBlock->Status)) {
					if (MdlChain != NULL)
						request->Arg7 = *MdlChain;				
				}

				request->IOSBInformation = IoStatusBlock->Information;
				request->IOSBStatus = IoStatusBlock->Status;
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		ret = DeviceObject->DriverObject->FastIoDispatch->FastIoWriteCompressed(FileObject, FileOffset, Length, LockKey, Buffer, MdlChain, IoStatusBlock, CompressedInfo, CompressedInfoLength, DeviceObject);
	}

	return ret;
}


NTSTATUS HookHandlerFastIoAcquireForModWrite(PFILE_OBJECT FileObject, PLARGE_INTEGER EndingOffset, PERESOURCE *ResourceToRelease, PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;
	LARGE_INTEGER offset;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject)) {
			offset.QuadPart = -1;
			if (EndingOffset != NULL)
				offset = *EndingOffset;

			request = _CreateFastIoRequest(AcquireForModWrite, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)offset.LowPart, (PVOID)offset.HighPart, NULL, NULL, NULL, NULL, NULL);
		}

		status = driverRecord->OldFastIoDisptach.AcquireForModWrite(FileObject, EndingOffset, ResourceToRelease, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, NTSTATUS, status);
			if (NT_SUCCESS(status) && ResourceToRelease != NULL)
				request->Arg3 = *ResourceToRelease;

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		status = DeviceObject->DriverObject->FastIoDispatch->AcquireForModWrite(FileObject, EndingOffset, ResourceToRelease, DeviceObject);
	}

	return status;
}


NTSTATUS HookHandlerFastIoReleaseForModWrite(PFILE_OBJECT FileObject, PERESOURCE ResourceToRelease, PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(ReleaseForModWrite, DeviceObject->DriverObject, DeviceObject, FileObject, ResourceToRelease, NULL, NULL, NULL, NULL, NULL, NULL);

		status = driverRecord->OldFastIoDisptach.ReleaseForModWrite(FileObject, ResourceToRelease, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, NTSTATUS, status);
			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		status = DeviceObject->DriverObject->FastIoDispatch->ReleaseForModWrite(FileObject, ResourceToRelease, DeviceObject);
	}

	return status;
}


NTSTATUS HookHandlerFastIoAcquireForCcFlush(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(AcquireForCcFlush, DeviceObject->DriverObject, DeviceObject, FileObject, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

		status = driverRecord->OldFastIoDisptach.AcquireForCcFlush(FileObject, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, NTSTATUS, status);
			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		status = DeviceObject->DriverObject->FastIoDispatch->AcquireForCcFlush(FileObject, DeviceObject);
	}

	return status;
}


NTSTATUS HookHandlerFastIoReleaseForCcFlush(PFILE_OBJECT FileObject, PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(ReleaseForCcFlush, DeviceObject->DriverObject, DeviceObject, FileObject, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

		status = driverRecord->OldFastIoDisptach.ReleaseForCcFlush(FileObject, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, NTSTATUS, status);
			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		status = DeviceObject->DriverObject->FastIoDispatch->ReleaseForCcFlush(FileObject, DeviceObject);
	}

	return status;
}


BOOLEAN HookHandlerFastIoMdlReadCompleteCompressed(PFILE_OBJECT FileObject, PMDL MdlChain, PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(MdlReadCompleteCompressed, DeviceObject->DriverObject, DeviceObject, FileObject, MdlChain, NULL, NULL, NULL, NULL, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.MdlReadCompleteCompressed(FileObject, MdlChain, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		ret = DeviceObject->DriverObject->FastIoDispatch->MdlReadCompleteCompressed(FileObject, MdlChain, DeviceObject);
	}

	return ret;
}


BOOLEAN HookHandlerFastIoMdlWriteCompleteCompressed(PFILE_OBJECT FileObject, PLARGE_INTEGER FileOffset, PMDL MdlChain,  PDEVICE_OBJECT DeviceObject)
{
	BOOLEAN ret = FALSE;
	PREQUEST_FASTIO request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (_CatchRequest(driverRecord, deviceRecord, DeviceObject))
			request = _CreateFastIoRequest(MdlWriteCompleteCompressed, DeviceObject->DriverObject, DeviceObject, FileObject, (PVOID)FileOffset->LowPart, (PVOID)FileOffset->HighPart, MdlChain, NULL, NULL, NULL, NULL);

		ret = driverRecord->OldFastIoDisptach.MdlWriteCompleteCompressed(FileObject, FileOffset, MdlChain, DeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, BOOLEAN, ret);
			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
		ret = DeviceObject->DriverObject->FastIoDispatch->MdlWriteCompleteCompressed(FileObject, FileOffset, MdlChain, DeviceObject);
	}

	return ret;
}

/************************************************************************/
/*                  NON-FAST IO HOOKS                                   */
/************************************************************************/

VOID HookHandlerStartIoDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PREQUEST_STARTIO request = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
	PIO_STATUS_BLOCK iosb = Irp->UserIosb;
	DEBUG_ENTER_FUNCTION("DeviceObject=0x%p; Irp=0x%p", DeviceObject, Irp);

	driverRecord = DriverHookRecordGet(DeviceObject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
		if (driverRecord->MonitorStartIo && _CatchRequest(driverRecord, deviceRecord, DeviceObject)) {
			request = (PREQUEST_STARTIO)HeapMemoryAllocNonPaged(sizeof(REQUEST_STARTIO));
			if (request != NULL) {
				RequestHeaderInit(&request->Header, DeviceObject->DriverObject, DeviceObject, ertStartIo);
				request->IRPAddress = Irp;
				request->MajorFunction = IrpStack->MajorFunction;
				request->MinorFunction = IrpStack->MinorFunction;
				request->IrpFlags = Irp->Flags;
				request->FileObject = IrpStack->FileObject;
				request->Status = STATUS_UNSUCCESSFUL;
				request->Information = 0;
			}
		}

		driverRecord->OldStartIo(DeviceObject, Irp);
		if (request != NULL) {
			if (iosb != NULL) {
				request->Status = iosb->Status;
				request->Information = iosb->Information;
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL, "HOOK_INFO_DATA_INFO: HookHandlerStartIoDispatch: request->Information:%d", request->Information);
			}

			RequestQueueInsert(&request->Header);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DeviceObject->DriverObject);
	}

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}

typedef struct _IRP_COMPLETION_CONTEXT {
	volatile LONG ReferenceCount;
	PVOID OriginalContext;
	PIO_COMPLETION_ROUTINE OriginalRoutine;
	ULONG OriginalControl;
	PDRIVER_OBJECT DriverObject;
	PDEVICE_OBJECT DeviceObject;
	volatile PREQUEST_IRP_COMPLETION CompRequest;
} IRP_COMPLETION_CONTEXT, *PIRP_COMPLETION_CONTEXT;

#define IOCONTROL_DISPATCH 0
#define IOCONTROL_REQUEST 1
#define IOCONTROL_COMPLETE 2

static VOID DbgPrintBuffer (unsigned char *buf, int length)
{
	int lines;
	int lastline;
	int i;
	int offset = 0;

	if (buf == NULL)
	{
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nHOOK_DATA:DbgPrintBuffer called with NULL buffer");
		return;
	}

	if (length > 256)
		length = 256;

	lines = length / 16;
	lastline = length % 16;

	for (i = 0; i < lines; ++i) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x - %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
			offset,buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
		buf += 16;
		offset += 16;
	}
	switch (lastline) {
	case 1:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x",
			offset, buf[0]);
		break;
	case 2:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x",
			offset, buf[0], buf[1], buf[2]);
		break;
	case 3:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2]);
		break;
	case 4:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3]);
		break;
	case 5:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
		break;
	case 6:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
		break;
	case 7:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6]);
		break;
	case 8:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
		break;
	case 9:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x - %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8]);
		break;
	case 10:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x - %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]);
		break;
	case 11:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x - %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10]);
		break;
	case 12:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2X %.2x %.2x %.2x %.2x %.2x %.2x %.2x - %.2x %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
		break;
	case 13:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x - %.2x %.2x %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12]);
		break;
	case 14:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x - %.2x %.2x %.2x %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13]);
		break;
	case 15:
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"\nHOOK_DATA: 0x%.4x: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x - %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
			offset, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14]);
		break;

	}

}

static NTSTATUS _HookHandlerIRPCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	PIO_STACK_LOCATION nextStack = NULL;
	NTSTATUS status = STATUS_CONTINUE_COMPLETION;
	NTSTATUS irpStatus = Irp->IoStatus.Status;
	PREQUEST_IRP_COMPLETION completionRequest = NULL;
	PIRP_COMPLETION_CONTEXT cc = (PIRP_COMPLETION_CONTEXT)Context;
	PIO_STACK_LOCATION irpStack = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	int printed = 0;


	DEBUG_ENTER_FUNCTION("DeviceObject=0x%p; Irp=0x%p; Context=0x%p", DeviceObject, Irp, Context);

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	driverRecord = DriverHookRecordGet(cc->DriverObject);
	//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "\nHOOK_INFO_TRACE: _HookHandlerIRPCompletion: Enter, IRP:0x%p irpStack:0x%p driverRecord:0x%p",
	//	Irp, irpStack, driverRecord);

	completionRequest = (PREQUEST_IRP_COMPLETION)HeapMemoryAllocNonPaged(sizeof(REQUEST_IRP_COMPLETION));
	if (completionRequest != NULL) {
		RequestHeaderInit(&completionRequest->Header, cc->DriverObject, cc->DeviceObject, ertIRPCompletion);
		completionRequest->IRPAddress = Irp;
		completionRequest->CompletionInformation = Irp->IoStatus.Information;
		
		completionRequest->CompletionStatus = Irp->IoStatus.Status;
		cc->CompRequest = completionRequest;
		//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
		//	"\nHOOK_DATA: Complete: Irp = 0x%p, Length = %d, MdlAddress = 0x%p, flags = 0x%x", 
		//	Irp, completionRequest->CompletionInformation,Irp->MdlAddress,Irp->Flags);
		if (irpStack && driverRecord)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
					"\nHOOK_DATA: _HookHandlerIRPCompletion : Irp = 0x%p, Driver = %wZ",
					Irp, driverRecord->DriverName);
			//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			//		"\nHOOK_DATA: _HookHandlerIRPCompletion : surfaceAcpiNotifyObject = 0x%p, driverObject = 0x%p",
			//		surfaceAcpiNotifyObject, driverRecord->DriverObject);
			if (surfaceAcpiNotifyObject == driverRecord->DriverObject)
			{
				//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
				//	"\nHOOK_DATA: Complete: Irp = 0x%p, Length = %d, buffer = %p", 
				//	Irp, completionRequest->CompletionInformation, Irp->AssociatedIrp.SystemBuffer);
				DbgAcpiNotifyIoctl(Irp, irpStack, IOCONTROL_COMPLETE);
				printed = 1;
			}
		}

		if (!printed && Irp->AssociatedIrp.SystemBuffer != NULL)
		{
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
				"\nHOOK_DATA: Complete: Irp = 0x%p, Length = %d, buffer = %p", Irp, completionRequest->CompletionInformation, Irp->AssociatedIrp.SystemBuffer);
			DbgPrintBuffer(Irp->AssociatedIrp.SystemBuffer, (int)completionRequest->CompletionInformation);
		}
	}

	// Change the next (well, its the previous one in the completion path)
	// location Context and CompletionRoutine to the original data specified
	// by the higher driver.
	nextStack = IoGetNextIrpStackLocation(Irp);
	if (nextStack->Context == cc)
		nextStack->Context = cc->OriginalContext;
	
	if (nextStack->CompletionRoutine == _HookHandlerIRPCompletion)
		nextStack->CompletionRoutine = cc->OriginalRoutine;

	if (cc->OriginalRoutine != NULL &&
		// Inspired by IoCompleteRequestd
		((Irp->Cancel && (cc->OriginalControl & SL_INVOKE_ON_CANCEL)) ||
		(!NT_SUCCESS(irpStatus) && (cc->OriginalControl & SL_INVOKE_ON_ERROR)) ||
		(NT_SUCCESS(irpStatus) && (cc->OriginalControl & SL_INVOKE_ON_SUCCESS))))
		status = cc->OriginalRoutine(DeviceObject, Irp, cc->OriginalContext);
	else if (Irp->PendingReturned && Irp->CurrentLocation < Irp->StackCount) {
		// Inspired by IoCompleteRequest
		IoMarkIrpPending(Irp);
		status = STATUS_PENDING;
	}

	if (completionRequest != NULL)
		RequestHeaderSetResult(completionRequest->Header, NTSTATUS, status);

	if (InterlockedDecrement(&cc->ReferenceCount) == 0) {
		HeapMemoryFree(cc);
		if (completionRequest != NULL)
			RequestQueueInsert(&completionRequest->Header);
	}

	IoReleaseRemoveLock(&_rundownLock, Irp);

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


static PIRP_COMPLETION_CONTEXT _HookIRPCompletionRoutine(PIRP Irp, PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT DeviceObject)
{
	PIO_STACK_LOCATION irpStack = NULL;
	PIRP_COMPLETION_CONTEXT ret = NULL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	DEBUG_ENTER_FUNCTION("Irp=0x%p; DriverObject=0x%p; DeviceObject=0x%p", Irp, DriverObject, DeviceObject);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL, "HOOK_INFO_TRACE: _HookIRPCompletionRoutine: Enter, IRP = 0x%p", Irp);
	if (NT_SUCCESS(IoAcquireRemoveLock(&_rundownLock, Irp))) {
		irpStack = IoGetCurrentIrpStackLocation(Irp);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL, "HOOK_INFO_TRACE: _HookIRPCompletionRoutine: irpStack = 0x%p", irpStack);
		driverRecord = DriverHookRecordGet(DriverObject);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL, "HOOK_INFO_TRACE: _HookIRPCompletionRoutine: driverRecord = 0x%p", driverRecord);
		if (driverRecord != NULL) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL, "HOOK_INFO_DATA: Driver Name = %wZ, MajorFunction:0x%x", 
				driverRecord->DriverName, irpStack->MajorFunction);
			deviceRecord = DriverHookRecordGetDevice(driverRecord, DeviceObject);
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL, "HOOK_INFO_TRACE: _HookIRPCompletionRoutine: deviceRecord = %p", deviceRecord);
			if (_CatchRequest(driverRecord, deviceRecord, DeviceObject)) {
				if (deviceRecord == NULL || deviceRecord->IRPMonitorSettings[irpStack->MajorFunction]) {
					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL, "HOOK_INFO_TRACE: _HookIRPCompletionRoutine: In The Check");
					if (driverRecord->MonitorIRP) {
						DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL, "HOOK_INFO_TRACE: _HookIRPCompletionRoutine: Monitoring The IRP!!!!!!!!!!!");
						if (irpStack->MajorFunction == IRP_MJ_READ) {
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
								"HOOK_INFO_DATA: _HookIRPCompletionRoutine: Read: Irp:0x%p Flags:0x%x MdlAddress:0x%p UserBuffer:0x%p count:%d DO_flags:0x%x",
								Irp, Irp->Flags, Irp->MdlAddress, Irp->UserBuffer, Irp->IoStatus.Information,DeviceObject->Flags);
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
								"HOOK_INFO_DATA: _HookIRPCompletionRoutine: Read: Irp:0x%p SystemBuffer:0x%p Length:%d key:0x%x ByteOffset:0x%x",
								Irp, Irp->AssociatedIrp.SystemBuffer, irpStack->Parameters.Read.Length, irpStack->Parameters.Read.Key, irpStack->Parameters.Read.ByteOffset);
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
								"HOOK_INFO_DATA: _HookIRPCompletionRoutine: Read: irpStack: MajorFunction:0x%x MinorFunction:0x%x Flags:0x%x Control:0x%x",
								irpStack->MajorFunction, irpStack->MinorFunction, irpStack->Flags, irpStack->Control);
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
								"\nHOOK_DATA: Read Request: Irp = 0x%p, Length = %d, Driver = %wZ", 
								Irp, irpStack->Parameters.Read.Length, driverRecord->DriverName);
							//if (irpStack->Parameters.Read.Length)
							//  DbgPrintBuffer(Irp->AssociatedIrp.SystemBuffer, 48);
						}
						else if (irpStack->MajorFunction == IRP_MJ_WRITE) {
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
								"HOOK_INFO_DATA: _HookIRPCompletionRoutine: Write: Irp:0x%p Flags:0x%x MdlAddress:0x%p UserBuffer:0x%p, count:%d DO_Flags:0x%x",
								Irp, Irp->Flags, Irp->MdlAddress, Irp->UserBuffer, Irp->IoStatus.Information,DeviceObject->Flags);
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
								"HOOK_INFO_DATA: _HookIRPCompletionRoutine: Write: Irp:0x%p SystemBuffer:0x%p Length:%d key:0x%x ByteOffset:0x%x",
								Irp,Irp->AssociatedIrp.SystemBuffer, irpStack->Parameters.Write.Length, irpStack->Parameters.Write.Key, irpStack->Parameters.Write.ByteOffset);
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
								"HOOK_INFO_DATA: _HookIRPCompletionRoutine: Write: irpStack: MajorFunction:0x%x MinorFunction:0x%x Flags:0x%x Control:0x%x",
								irpStack->MajorFunction, irpStack->MinorFunction, irpStack->Flags, irpStack->Control);
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
								"\nHOOK_DATA: Write Request: Irp = 0x%p, Length = %d, Driver = %wZ", 
								Irp, irpStack->Parameters.Write.Length, driverRecord->DriverName);
							//if (irpStack->Parameters.Write.Length)
							//  DbgPrintBuffer(Irp->AssociatedIrp.SystemBuffer, irpStack->Parameters.Write.Length);
						}
						else if (irpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
							int printed = 0;
							ULONG controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
							if (irpStack->Parameters.DeviceIoControl.InputBufferLength && controlCode == IOCTL_BATTERY_QUERY_INFORMATION)
							{
								PBATTERY_QUERY_INFORMATION batt = (PBATTERY_QUERY_INFORMATION)(Irp->AssociatedIrp.SystemBuffer);
								DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
									"\nHOOK_DATA: DeviceIocontrol Request: Irp=0x%p,Length=%d,Driver=%wZ,Ioctl=0x%x,Tag=0x%x,InfoLevel=0x%x,AtRate=0x%x",
									Irp, irpStack->Parameters.DeviceIoControl.InputBufferLength, driverRecord->DriverName, controlCode,
									batt->BatteryTag,batt->InformationLevel,batt->AtRate);
								printed = 1;
							}
							if (!printed)
							{
								DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
									"\nHOOK_DATA: DeviceIocontrol Request: Irp = 0x%p, Length = %d, Driver = %wZ, Ioctl = 0x%x",
									Irp, irpStack->Parameters.DeviceIoControl.InputBufferLength, driverRecord->DriverName, irpStack->Parameters.DeviceIoControl.IoControlCode);
							}
							if (surfaceAcpiNotifyObject == driverRecord->DriverObject)
							{
								DbgAcpiNotifyIoctl(Irp, irpStack, IOCONTROL_REQUEST);
							}
						}
					}
				}
			}

		}

		ret = (PIRP_COMPLETION_CONTEXT)HeapMemoryAllocNonPaged(sizeof(IRP_COMPLETION_CONTEXT));
		if (ret != NULL) {
			RtlSecureZeroMemory(ret, sizeof(IRP_COMPLETION_CONTEXT));
			ret->ReferenceCount = 1;
			ret->DriverObject = DriverObject;
			ret->DeviceObject = DeviceObject;
			irpStack = IoGetCurrentIrpStackLocation(Irp);
			if (irpStack->CompletionRoutine != NULL) {
				ret->OriginalContext = irpStack->Context;
				ret->OriginalRoutine = irpStack->CompletionRoutine;
				ret->OriginalControl = irpStack->Control;
			}

			IoSkipCurrentIrpStackLocation(Irp);
			IoSetCompletionRoutine(Irp, _HookHandlerIRPCompletion, ret, TRUE, TRUE, TRUE);
			IoSetNextIrpStackLocation(Irp);
		}

		if (ret == NULL)
			IoReleaseRemoveLock(&_rundownLock, Irp);
	}

	DEBUG_EXIT_FUNCTION("0x%p", ret);
	return ret;
}

void DbgAcpiNotifyIoctl(PIRP Irp, PIO_STACK_LOCATION irpStack, int requestType)
{
	PVOID systemBuffer = NULL;

	systemBuffer = Irp->AssociatedIrp.SystemBuffer;

	if (systemBuffer)
	{
		PSPB_TRANSFER_LIST spbTransferList = systemBuffer;
		ULONG transferCount = spbTransferList->TransferCount;
		PSPB_TRANSFER_LIST_ENTRY spbTransferListEntry = spbTransferList->Transfers;
		//ULONG inputBufferLength = 0;
		//ULONG size = spbTransferList->Size;
		//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
		//	"\nHOOK_DATA: DbgAcpiNotifyIoctl: Irp=0x%p, Transfer List Size=0x%x, Transfer List Count=0x%x input buffer length=0x%x", 
		//	Irp, size, transferCount, inputBufferLength);
		for (ULONG i = 0; i < transferCount; ++i)
		{
			SPB_TRANSFER_DIRECTION spbTransferDirection = spbTransferListEntry->Direction;
			ULONG DelayInUs = spbTransferListEntry->DelayInUs;
			SPB_TRANSFER_BUFFER spbTransferBuffer = spbTransferListEntry->Buffer;
			SPB_TRANSFER_BUFFER_FORMAT spbTransferBufferFormat = spbTransferBuffer.Format;
			SPB_TRANSFER_BUFFER_LIST_ENTRY *simple = (SPB_TRANSFER_BUFFER_LIST_ENTRY *)&spbTransferBuffer.BufferList;
			PMDL pMdl = spbTransferBuffer.Mdl;
			PVOID buffer = simple->Buffer;
			ULONG bufferCb = simple->BufferCb;

			switch (requestType)  {
			  case IOCONTROL_COMPLETE:
				  if (spbTransferDirection == SpbTransferDirectionFromDevice)
				  {
					  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
						  "\nHOOK_DATA: DbgAcpiNotifyIoctl Read: Irp=0x%p, entry=%d, direction=0x%x, delay=0x%x, format=0x%x, mdl=0x%p, bufferCb=0x%x, buffer=0x%p",
						  Irp,i, spbTransferDirection, DelayInUs, spbTransferBufferFormat, pMdl, bufferCb, buffer);
					  DbgPrintBuffer(buffer, (int)bufferCb);
				  }
				  break;
			  case IOCONTROL_DISPATCH:
			  case IOCONTROL_REQUEST:
				  if (spbTransferDirection == SpbTransferDirectionToDevice)
				  {
					  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
						  "\nHOOK_DATA: DbgAcpiNotifyIoctl Write: Irp=0x%p, entry=%d, direction=0x%x, delay=0x%x, format=0x%x, mdl=0x%p, bufferCb=0x%x, buffer=0x%p",
						  Irp, i, spbTransferDirection, DelayInUs, spbTransferBufferFormat, pMdl, bufferCb, buffer);
					  DbgPrintBuffer(buffer, (int)bufferCb);
				  }
				  break;
			}
			++spbTransferListEntry;
		}
	}
}

NTSTATUS HookHandlerIRPDisptach(PDEVICE_OBJECT Deviceobject, PIRP Irp)
{
	PIRP_COMPLETION_CONTEXT compContext = NULL;
	PREQUEST_IRP request = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PDEVICE_HOOK_RECORD deviceRecord = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
	
	PVOID inputBuffer = NULL;
	PVOID outputBuffer = NULL;
	PVOID systemBuffer = NULL;
	ULONG controlCode = 0;
	ULONG inputBufferLength = 0;
	ULONG outputBufferLength = 0;		

	controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	inputBuffer = irpStack->Parameters.DeviceIoControl.Type3InputBuffer;
	outputBuffer = Irp->UserBuffer;
	systemBuffer = Irp->AssociatedIrp.SystemBuffer;



	DEBUG_ENTER_FUNCTION("DeviceObject=0x%p; Irp=0x%p", Deviceobject, Irp);

	driverRecord = DriverHookRecordGet(Deviceobject->DriverObject);
	if (driverRecord != NULL) {
		deviceRecord = DriverHookRecordGetDevice(driverRecord, Deviceobject);
		if (_CatchRequest(driverRecord, deviceRecord, Deviceobject)) {
			if (deviceRecord == NULL || deviceRecord->IRPMonitorSettings[irpStack->MajorFunction]) {
				if (driverRecord->MonitorIRP) {
					request = (PREQUEST_IRP)HeapMemoryAllocNonPaged(sizeof(REQUEST_IRP));
					if (request != NULL) {
						RequestHeaderInit(&request->Header, Deviceobject->DriverObject, Deviceobject, ertIRP);
						RequestHeaderSetResult(request->Header, NTSTATUS, STATUS_PENDING);
						request->IRPAddress = Irp;
						request->MajorFunction = irpStack->MajorFunction;
						request->MinorFunction = irpStack->MinorFunction;
						request->PreviousMode = ExGetPreviousMode();
						request->RequestorMode = Irp->RequestorMode;
						request->Arg1 = irpStack->Parameters.Others.Argument1;
						request->Arg2 = irpStack->Parameters.Others.Argument2;
						request->Arg3 = irpStack->Parameters.Others.Argument3;
						request->Arg4 = irpStack->Parameters.Others.Argument4;
						request->IrpFlags = Irp->Flags;
						request->FileObject = irpStack->FileObject;
						request->IOSBStatus = Irp->IoStatus.Status;
						request->IOSBInformation = Irp->IoStatus.Information;
						request->RequestorProcessId = IoGetRequestorProcessId(Irp);
						if (irpStack->MajorFunction == IRP_MJ_READ) {
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL, 
								"HOOK_INFO_DATA: HookHandlerIRPDisptach: Read: Irp = 0x%p Flags = 0x%x MdlAddress = 0x%p UserBuffer = 0x%p, count = %d",
								Irp, Irp->Flags, Irp->MdlAddress,Irp->UserBuffer, Irp->IoStatus.Information);
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
								"HOOK_INFO_DATA: HookHandlerIRPDisptach: Read: Irp:0x%p SystemBuffer:0x%p, Length:%d",
								Irp,Irp->AssociatedIrp.SystemBuffer, irpStack->Parameters.Read.Length);

						}
						else if (irpStack->MajorFunction == IRP_MJ_WRITE) {
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
								"HOOK_INFO_DATA: HookHandlerIRPDisptach: Write: Irp = 0x%p Flags = 0x%x MdlAddress = 0x%p UserBuffer = 0x%p, count = %d",
								Irp, Irp->Flags, Irp->MdlAddress, Irp->UserBuffer, Irp->IoStatus.Information);
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
								"HOOK_INFO_DATA: HookHandlerIRPDisptach: Write: Irp:0x%p SystemBuffer:0x%p Length:%d",
								Irp, Irp->AssociatedIrp.SystemBuffer, irpStack->Parameters.Write.Length);
							//if (irpStack->Parameters.Write.Length)
							//	DbgPrintBuffer(Irp->AssociatedIrp.SystemBuffer, irpStack->Parameters.Write.Length);
						}
						else if (irpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {


							controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
							inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
							outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
							inputBuffer = irpStack->Parameters.DeviceIoControl.Type3InputBuffer;
							outputBuffer = Irp->UserBuffer;
							systemBuffer = Irp->AssociatedIrp.SystemBuffer;
							DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
								"\nHOOK_DATA: DeviceIocontrol Dispatch: Irp = 0x%p, length = %d, Driver = %wZ, Ioctl = 0x%x",
								Irp, irpStack->Parameters.DeviceIoControl.InputBufferLength,
								driverRecord->DriverName, irpStack->Parameters.DeviceIoControl.IoControlCode);
							//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
							//	"\nHOOK_DATA: DeviceIocontrol Dispatch: driverObject:0x%p surfaceAcpiNotifyObject:0x%p cmBattObject:0x%p controlCode:0x%x IOCTL_SPB_EXECUTE_SEQUENCE:0x%x",
							//		driverRecord->DriverObject, surfaceAcpiNotifyObject, cmBattObject, controlCode, IOCTL_SPB_EXECUTE_SEQUENCE);

							if (controlCode == IOCTL_SPB_EXECUTE_SEQUENCE && !surfaceAcpiNotifyObject)
							{
								surfaceAcpiNotifyObject = driverRecord->DriverObject;
							}
							else if (controlCode == 0x294040 && !cmBattObject)
							{
								cmBattObject = driverRecord->DriverObject;
							}
							
							if (controlCode == IOCTL_SPB_EXECUTE_SEQUENCE)
							{
								//DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
								//	"\nHOOK_DATA: DeviceIocontrol Dispatch: inputBuffer:0x%p inputBufferLength:0x%d outputBuffer:0x%p outputBufferLength:0x%d systemBuffer:0x%p",
								//	inputBuffer, inputBufferLength, outputBuffer, outputBufferLength, systemBuffer);
								//DbgAcpiNotifyIoctl(Irp, irpStack, IOCONTROL_DISPATCH);
							}
							if (irpStack->Parameters.DeviceIoControl.InputBufferLength)
								DbgPrintBuffer(Irp->AssociatedIrp.SystemBuffer, irpStack->Parameters.DeviceIoControl.InputBufferLength);
						}
					}
				}

				if (driverRecord->MonitorIRPCompletion) {
					compContext = _HookIRPCompletionRoutine(Irp, Deviceobject->DriverObject, Deviceobject);
					if (compContext != NULL && request != NULL)
						InterlockedIncrement(&compContext->ReferenceCount);
				}
			}
		}

		status = driverRecord->OldMajorFunction[irpStack->MajorFunction](Deviceobject, Irp);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, NTSTATUS, status);
			RequestQueueInsert(&request->Header);
		}

		if (compContext != NULL && InterlockedDecrement(&compContext->ReferenceCount) == 0) {
			RequestQueueInsert(&compContext->CompRequest->Header);
			HeapMemoryFree(compContext);
		}

		if (deviceRecord != NULL)
			DeviceHookRecordDereference(deviceRecord);

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", Deviceobject->DriverObject);
	}

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


NTSTATUS HookHandlerAddDeviceDispatch(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject)
{
	PDEVICE_OBJECT detectedDevice = NULL;
	PREQUEST_ADDDEVICE request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p; PhysicalDeviceObject=0x%p", DriverObject, PhysicalDeviceObject);

	driverRecord = DriverHookRecordGet(DriverObject);
	if (driverRecord != NULL) {
		if (driverRecord->MonitoringEnabled && driverRecord->MonitorAddDevice) {
			request = (PREQUEST_ADDDEVICE)HeapMemoryAllocNonPaged(sizeof(REQUEST_ADDDEVICE));
			if (request != NULL)
				RequestHeaderInit(&request->Header, DriverObject, PhysicalDeviceObject, ertAddDevice);
		}

		status = driverRecord->OldAddDevice(DriverObject, PhysicalDeviceObject);
		if (request != NULL) {
			RequestHeaderSetResult(request->Header, NTSTATUS, status);
			RequestQueueInsert(&request->Header);
		}

		detectedDevice = PhysicalDeviceObject;
		while (detectedDevice != NULL) {
			PREQUEST_HEADER rq = NULL;

			if (NT_SUCCESS(RequestXXXDetectedCreate(ertDriverDetected, detectedDevice->DriverObject, NULL, &rq)))
				RequestQueueInsert(rq);

			if (NT_SUCCESS(RequestXXXDetectedCreate(ertDeviceDetected, detectedDevice->DriverObject, detectedDevice, &rq)))
				RequestQueueInsert(rq);

			detectedDevice = detectedDevice->AttachedDevice;
		}

		DriverHookRecordDereference(driverRecord);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DriverObject);
	}

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


VOID HookHandlerDriverUnloadDisptach(PDRIVER_OBJECT DriverObject)
{
	PREQUEST_UNLOAD request = NULL;
	PDRIVER_HOOK_RECORD driverRecord = NULL;
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p", DriverObject);

	driverRecord = DriverHookRecordGet(DriverObject);
	if (driverRecord != NULL) {
		if (driverRecord->MonitoringEnabled && driverRecord->MonitorDriverUnload) {
			request = (PREQUEST_UNLOAD)HeapMemoryAllocNonPaged(sizeof(REQUEST_UNLOAD));
			if (request != NULL)
				RequestHeaderInit(&request->Header, DriverObject, NULL, ertDriverUnload);
		}

		ObReferenceObject(DriverObject);
		driverRecord->OldDriverUnload(DriverObject);
		UnhookDriverObject(driverRecord);
		DriverHookRecordDereference(driverRecord);
		ObDereferenceObject(DriverObject);
		if (request != NULL)
			RequestQueueInsert(&request->Header);
	} else {
		DEBUG_ERROR("Hook is installed for non-hooked driver object 0x%p", DriverObject);
	}

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}


/************************************************************************/
/*              INITIALIZATION AND FINALIZATION                         */
/************************************************************************/

NTSTATUS HookHandlerModuleInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath, PVOID Context)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p; RegistryPath=\"%wZ\"; Context=0x%p", DriverObject, RegistryPath, Context);

	IoInitializeRemoveLock(&_rundownLock, 'LRHH', 0x7FFFFFFF, 0x7FFFFFFF);
	status = IoAcquireRemoveLock(&_rundownLock, DriverObject);

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


void HookHandlerModuleFinit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath, PVOID Context)
{
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p; RegistryPath=\"%wZ\"; Context=0x%p", DriverObject, RegistryPath, Context);

	IoReleaseRemoveLockAndWait(&_rundownLock, DriverObject);

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}
