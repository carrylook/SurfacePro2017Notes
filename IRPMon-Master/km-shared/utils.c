
#include <ntifs.h>
#include <ntddvol.h>
#include "preprocessor.h"
#include "allocator.h"
#include "kernel-shared.h"
#include "utils-dym-array.h"
#include "utils.h"

#undef DEBUG_TRACE_ENABLED
#define DEBUG_TRACE_ENABLED 0

typedef NTSTATUS (NTAPI ZWQUERYDIRECTORYOBJECT)(
   HANDLE DirectoryHandle,
   PVOID Buffer,
   ULONG Length,
   BOOLEAN ReturnSingleEntry,
   BOOLEAN RestartScan,
   PULONG Context,
   PULONG ReturnLength);

typedef NTSTATUS (NTAPI OBREFERENCEOBJECTBYNAME) (
   PUNICODE_STRING ObjectPath,
   ULONG Attributes,
   PACCESS_STATE PassedAccessState OPTIONAL,
   ACCESS_MASK DesiredAccess OPTIONAL,
   POBJECT_TYPE ObjectType,
   KPROCESSOR_MODE AccessMode,
   PVOID ParseContext OPTIONAL,
   PVOID *ObjectPtr); 



typedef struct _OBJECT_DIRECTORY_INFORMATION {
   UNICODE_STRING Name;
   UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

__declspec(dllimport) ZWQUERYDIRECTORYOBJECT ZwQueryDirectoryObject;
__declspec(dllimport) OBREFERENCEOBJECTBYNAME ObReferenceObjectByName;
__declspec(dllimport) POBJECT_TYPE *IoDriverObjectType;


/************************************************************************/
/*                             GLOBAL VARIABLES                         */
/************************************************************************/


/************************************************************************/
/* HELPER ROUTINES                                                      */
/************************************************************************/






VOID _ReleaseDriverArray(PDRIVER_OBJECT *DriverArray, SIZE_T DriverCount)
{
	DEBUG_ENTER_FUNCTION("DriverArray=0x%p; DriverCount=%u", DriverArray, DriverCount);

	if (DriverCount > 0) {
		for (ULONG i = 0; i < DriverCount; ++i)
			ObDereferenceObject(DriverArray[i]);

		HeapMemoryFree(DriverArray);
	}

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}


VOID _ReleaseDeviceArray(PDEVICE_OBJECT *DeviceArray, SIZE_T ArrayLength)
{
	DEBUG_ENTER_FUNCTION("DeviceArray=0x%p; ArrayLength=%u", DeviceArray, ArrayLength);

	if (ArrayLength > 0) {
		for (ULONG i = 0; i < ArrayLength; ++i)
			ObDereferenceObject(DeviceArray[i]);

		HeapMemoryFree(DeviceArray);
	}

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}


NTSTATUS _GetObjectName(PVOID Object, PUNICODE_STRING Name)
{
	ULONG oniLen = 0;
	POBJECT_NAME_INFORMATION oni = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("Object=0x%p; Name=0x%p", Object, Name);
	DEBUG_IRQL_LESS_OR_EQUAL(APC_LEVEL);

	status = ObQueryNameString(Object, NULL, 0, &oniLen);
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		oniLen += sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR);
		oni = (POBJECT_NAME_INFORMATION)HeapMemoryAllocNonPaged(oniLen);
		if (oni != NULL) {
			status = ObQueryNameString(Object, oni, oniLen, &oniLen);
			if (NT_SUCCESS(status)) {
				Name->Length = oni->Name.Length;
				Name->MaximumLength = Name->Length + sizeof(WCHAR);
				Name->Buffer = (PWCH)HeapMemoryAllocNonPaged(oni->Name.Length + sizeof(WCHAR));
				if (Name->Buffer != NULL) {
					memcpy(Name->Buffer, oni->Name.Buffer, oni->Name.Length);
					Name->Buffer[oni->Name.Length / sizeof(WCHAR)] = L'\0';
				} else status = STATUS_INSUFFICIENT_RESOURCES;
			}

			HeapMemoryFree(oni);
		} else status = STATUS_INSUFFICIENT_RESOURCES;
	} else if (NT_SUCCESS(status)) {
		Name->Length = 0;
		Name->MaximumLength = sizeof(WCHAR);
		Name->Buffer = (PWCH)HeapMemoryAllocNonPaged(sizeof(WCHAR));
		if (Name->Buffer != NULL) {
			Name->Buffer[0] = L'\0';
			status = STATUS_SUCCESS;
		} else status = STATUS_INSUFFICIENT_RESOURCES;
	}

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


static NTSTATUS _AppendDriverNameToDirectory(PUNICODE_STRING Dest, PUNICODE_STRING Src1, PUNICODE_STRING Src2)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("Dest=0x%p; Src1=%S; Src2=%S", Dest, Src1->Buffer, Src2->Buffer);

	Dest->Length = Src1->Length + sizeof(WCHAR) + Src2->Length;
	Dest->MaximumLength = Dest->Length;
	Dest->Buffer = (PWSTR)HeapMemoryAlloc(PagedPool, Dest->Length + sizeof(WCHAR));
	if (Dest->Buffer != NULL) {
		RtlZeroMemory(Dest->Buffer, Dest->Length + sizeof(WCHAR));
		RtlCopyMemory(Dest->Buffer, Src1->Buffer, Src1->Length);
		Dest->Buffer[Src1->Length / sizeof(WCHAR)] = L'\\';
		RtlCopyMemory(&Dest->Buffer[(Src1->Length / sizeof(WCHAR)) + 1], Src2->Buffer, Src2->Length);
		Status = STATUS_SUCCESS;
	} else Status = STATUS_INSUFFICIENT_RESOURCES;

	DEBUG_EXIT_FUNCTION("0x%x, *Dest=%S", Status, Dest->Buffer);
	return Status;
}


NTSTATUS _GetDriversInDirectory(PUNICODE_STRING Directory, PDRIVER_OBJECT **DriverArray, PSIZE_T DriverCount)
{
	SIZE_T tmpDriverCount = 0;
	PDRIVER_OBJECT *tmpDriverArray = NULL;
	HANDLE hDirectory = NULL;
	PUTILS_DYM_ARRAY driverArray = NULL;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING uDriverTypeString;
	DEBUG_ENTER_FUNCTION("Directory=%S; DriverArray=0x%p; DriverCount=0x%p", Directory->Buffer, DriverArray, DriverCount);

	*DriverCount = 0;
	*DriverArray = NULL;
	status = DymArrayCreate(PagedPool, &driverArray);
	if (NT_SUCCESS(status)) {
		RtlInitUnicodeString(&uDriverTypeString, L"Driver");
		InitializeObjectAttributes(&oa, Directory, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = ZwOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &oa);
		if (NT_SUCCESS(status)) {
			ULONG QueryContext = 0;
			UCHAR Buffer[1024];
			POBJECT_DIRECTORY_INFORMATION DirInfo = (POBJECT_DIRECTORY_INFORMATION)&Buffer;

			do {
				RtlZeroMemory(&Buffer, sizeof(Buffer));
				status = ZwQueryDirectoryObject(hDirectory, DirInfo, sizeof(Buffer), TRUE, FALSE, &QueryContext, NULL);
				if (NT_SUCCESS(status)) {
					if (RtlEqualUnicodeString(&DirInfo->TypeName, &uDriverTypeString, TRUE)) {
						UNICODE_STRING FullDriverName;

						status = _AppendDriverNameToDirectory(&FullDriverName, Directory, &DirInfo->Name);
						if (NT_SUCCESS(status)) {
							PDRIVER_OBJECT DriverPtr = NULL;

							status = ObReferenceObjectByName(&FullDriverName, OBJ_CASE_INSENSITIVE, NULL, GENERIC_READ, *IoDriverObjectType, KernelMode, NULL, (PVOID *)&DriverPtr);
							if (NT_SUCCESS(status)) {
								status = DymArrayPushBack(driverArray, DriverPtr);
								if (!NT_SUCCESS(status))
									ObDereferenceObject(DriverPtr);
							}

							HeapMemoryFree(FullDriverName.Buffer);
						}
					}
				}
			} while (NT_SUCCESS(status));

			if (status == STATUS_NO_MORE_ENTRIES) {
				tmpDriverCount = DymArrayLength(driverArray);
				tmpDriverArray = HeapMemoryAllocPaged(tmpDriverCount*sizeof(PDRIVER_OBJECT));
				if (tmpDriverArray != NULL) {
					for (SIZE_T i = 0; i < DymArrayLength(driverArray); ++i)
						tmpDriverArray[i] = (PDRIVER_OBJECT)DymArrayItem(driverArray, i);

					*DriverCount = tmpDriverCount;
					*DriverArray = tmpDriverArray;
					status = STATUS_SUCCESS;
				} else status = STATUS_INSUFFICIENT_RESOURCES;
			}

			ZwClose(hDirectory);
		}

		if (!NT_SUCCESS(status)) {
			for (SIZE_T i = 0; i < DymArrayLength(driverArray); ++i)
				ObDereferenceObject(DymArrayItem(driverArray, i));
		}

		DymArrayDestroy(driverArray);
	}

	DEBUG_EXIT_FUNCTION("0x%x, *DriverArray=0x%p, *DriverCount=%zu", status, *DriverArray, *DriverCount);
	return status;
}


NTSTATUS _EnumDriverDevices(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT **DeviceArray, PULONG DeviceArrayLength)
{
	ULONG TmpArrayLength = 0;
	PDEVICE_OBJECT *TmpDeviceArray = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p; DeviceArray=0x%p; DeviceArrayLength=0x%p", DriverObject, DeviceArray, DeviceArrayLength);

	do {
		Status = IoEnumerateDeviceObjectList(DriverObject, TmpDeviceArray, TmpArrayLength * sizeof(PDEVICE_OBJECT), &TmpArrayLength);
		if (Status == STATUS_BUFFER_TOO_SMALL) {
			if (TmpDeviceArray != NULL)
				HeapMemoryFree(TmpDeviceArray);

			TmpDeviceArray = (PDEVICE_OBJECT *)HeapMemoryAlloc(NonPagedPool, TmpArrayLength * sizeof(PDEVICE_OBJECT));
			if (TmpDeviceArray == NULL)
				Status = STATUS_INSUFFICIENT_RESOURCES;
		}
	} while (Status == STATUS_BUFFER_TOO_SMALL);

	if (NT_SUCCESS(Status)) {
		*DeviceArrayLength = TmpArrayLength;
		*DeviceArray = TmpDeviceArray;
	}

	DEBUG_EXIT_FUNCTION("0x%x, *DeviceArray=0x%p, *DeviceArrayLength=%u", Status, *DeviceArray, *DeviceArrayLength);
	return Status;
}


NTSTATUS _GetDeviceAddressByCondition(DEVICE_CONDITION_CALLBACK *Callback, BOOLEAN SearchDrivers, BOOLEAN SearchFileSystems, PVOID Context, PDEVICE_OBJECT *DeviceAddress, PVOID ReturnBuffer, ULONG ReturnBufferLength)
{
   PDRIVER_OBJECT *DriverArray = NULL;
   SIZE_T DriverArrayLength = 0;
   NTSTATUS Status = STATUS_UNSUCCESSFUL;
   DEBUG_ENTER_FUNCTION("Callback=0x%p; SearchDrivers=%d; SearchFileSystems=%d; Context=0x%p; DeviceAddress=0x%p; ReturnBuffer=0x%p; ReturnBufferLength=%d", Callback, SearchDrivers, SearchFileSystems, Context, DeviceAddress, ReturnBuffer, ReturnBufferLength);

   Status = STATUS_NOT_FOUND;
   *DeviceAddress = NULL;
   if (SearchDrivers) {
      UNICODE_STRING Directory;

      RtlInitUnicodeString(&Directory, L"\\Driver");
      Status = _GetDriversInDirectory(&Directory, &DriverArray, &DriverArrayLength);
   } else {
      Status = STATUS_SUCCESS;
   }

   if (NT_SUCCESS(Status)) {
      PDRIVER_OBJECT *FileSystemArray = NULL;
      SIZE_T FileSystemArrayLength = 0;

      if (SearchFileSystems) {
         UNICODE_STRING Directory;

         RtlInitUnicodeString(&Directory, L"\\FileSystem");
         Status = _GetDriversInDirectory(&Directory, &FileSystemArray, &FileSystemArrayLength);
      }

      if (NT_SUCCESS(Status)) {
         PDRIVER_OBJECT *TotalArray = NULL;
         SIZE_T TotalArrayLength = 0;

         TotalArrayLength = DriverArrayLength + FileSystemArrayLength;
         TotalArray = (PDRIVER_OBJECT *)HeapMemoryAlloc(NonPagedPool, TotalArrayLength * sizeof(PDRIVER_OBJECT));
         if (TotalArray != NULL) {
            ULONG i = 0;

            RtlCopyMemory(TotalArray, DriverArray, DriverArrayLength * sizeof(PDRIVER_OBJECT));
            RtlCopyMemory(&TotalArray[DriverArrayLength], FileSystemArray, FileSystemArrayLength * sizeof(PDRIVER_OBJECT));
            for (i = 0; i < TotalArrayLength; ++i) {
               BOOLEAN Finish = FALSE;
               PDEVICE_OBJECT *DeviceArray = NULL;
               ULONG DeviceArrayLength = 0;

               Status = _EnumDriverDevices(TotalArray[i], &DeviceArray, &DeviceArrayLength);
               if (NT_SUCCESS(Status)) {
                  ULONG j = 0;

                  for (j = 0; j < DeviceArrayLength; ++j) {
                     Status = Callback(DeviceArray[j], Context, ReturnBuffer, ReturnBufferLength);
                     if (NT_SUCCESS(Status)) {
                        Finish = TRUE;
                        *DeviceAddress = DeviceArray[j];
                        ObReferenceObject(*DeviceAddress);
                     } else {
                        Finish = Status != STATUS_NOT_FOUND;
                     }
                     
                     if (Finish) {
                        break;
                     }
                  }

                  _ReleaseDeviceArray(DeviceArray, DeviceArrayLength);
               } else {
                  Finish = TRUE;
               }

               if (Finish)
                  break;
            }

            if (*DeviceAddress == NULL)
               Status = STATUS_NOT_FOUND;

            HeapMemoryFree(TotalArray);
         }

         _ReleaseDriverArray(FileSystemArray, FileSystemArrayLength);
      }

      _ReleaseDriverArray(DriverArray, DriverArrayLength);
   }

   DEBUG_EXIT_FUNCTION("0x%x, *DeviceAddress=0x%p", Status, *DeviceAddress);
   return Status;
}

static NTSTATUS _DeviceByNameCondition(PDEVICE_OBJECT DeviceObject, PVOID Context, PVOID ReturnBuffer, ULONG ReturnBufferLength)
{                     
   UNICODE_STRING DeviceName;
   PUNICODE_STRING TargetDeviceName = (PUNICODE_STRING)Context;
   NTSTATUS Status = STATUS_UNSUCCESSFUL;

   UNREFERENCED_PARAMETER(ReturnBufferLength);
   UNREFERENCED_PARAMETER(ReturnBuffer);

   Status = _GetObjectName(DeviceObject, &DeviceName);
   if (NT_SUCCESS(Status)) {
      if (RtlCompareUnicodeString(&DeviceName, TargetDeviceName, TRUE) == 0) {
         Status = STATUS_SUCCESS;
      } else {
         Status = STATUS_NOT_FOUND;
      }

      HeapMemoryFree(DeviceName.Buffer);
   }

   return Status;
}


static NTSTATUS _DeviceByAddressCondition(PDEVICE_OBJECT DeviceObject, PVOID Context, PVOID ReturnBuffer, ULONG ReturnBufferLength)
{                     
	PDEVICE_OBJECT targetDeviceAddress = (PDEVICE_OBJECT)Context;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	UNREFERENCED_PARAMETER(ReturnBufferLength);
	UNREFERENCED_PARAMETER(ReturnBuffer);
	Status = STATUS_NOT_FOUND;
	if (targetDeviceAddress == DeviceObject)
		Status = STATUS_SUCCESS;

	return Status;
}


NTSTATUS _GetDeviceAddress(PUNICODE_STRING DeviceName, BOOLEAN SearchDrivers, BOOLEAN SearchFileSystems, PDEVICE_OBJECT *Object)
{
   NTSTATUS Status = STATUS_UNSUCCESSFUL;
   DEBUG_ENTER_FUNCTION("DeviceName=%S; SearchDrivers=%d; SearchFileSystems=%d; Object=0x%p", DeviceName->Buffer, SearchDrivers, SearchFileSystems, Object);

   if (DeviceName->Length > 0) {
	   Status = STATUS_NOT_FOUND;
      Status = _GetDeviceAddressByCondition(_DeviceByNameCondition, SearchDrivers, SearchFileSystems, DeviceName, Object, NULL, 0);
   } else Status = STATUS_NOT_FOUND;

   DEBUG_EXIT_FUNCTION("0x%x, *Object=0x%p", Status, *Object);
   return Status;
}


NTSTATUS VerifyDeviceByAddress(PVOID Address, BOOLEAN SearchDrivers, BOOLEAN SearchFileSystems, PDEVICE_OBJECT *Object)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("Address=0x%p; SearchDrivers=%d; SearchFileSystems=%d; Object=0x%p", Address, SearchDrivers, SearchFileSystems, Object);

	Status = _GetDeviceAddressByCondition(_DeviceByAddressCondition, SearchDrivers, SearchFileSystems, Address, Object, NULL, 0);

	DEBUG_EXIT_FUNCTION("0x%x, *Object=0x%p", Status, *Object);
	return Status;
}


NTSTATUS GetDriverObjectByName(PUNICODE_STRING Name, PDRIVER_OBJECT *DriverObject)
{
	PDRIVER_OBJECT tmpDriverObject = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("Name=0x%p; DriverObject=0x%p", Name, DriverObject);

	status = ObReferenceObjectByName(Name, 0, NULL, 0, *IoDriverObjectType, KernelMode, NULL, &tmpDriverObject);
	if (NT_SUCCESS(status))
		*DriverObject = tmpDriverObject;

	DEBUG_EXIT_FUNCTION("0x%x, *DriverObject=0x%p", status, *DriverObject);
	return status;
}
