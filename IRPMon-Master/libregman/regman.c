
#include <ntifs.h>
#include "allocator.h"
#include "preprocessor.h"
#include "value-record.h"
#include "key-record.h"
#include "registry-callback.h"
#include "regman.h"



/************************************************************************/
/*                PUBLIC FUNCTIONS                                      */
/************************************************************************/


NTSTATUS RegManKeyRegister(_In_ PUNICODE_STRING KeyName, _Out_ PHANDLE KeyHandle)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("KeyName=\"%wZ\"; KeyHandle=0x%p", KeyName, KeyHandle);

	status = RegCallbackKeyRegister(KeyName, (PREGMAN_KEY_RECORD *)KeyHandle);

	DEBUG_EXIT_FUNCTION("0x%x, *KeyHandle=0x%p", status, *KeyHandle);
	return status;
}


VOID RegManKeyUnregister(_In_ HANDLE KeyHandle)
{
	PREGMAN_KEY_RECORD keyRecord = (PREGMAN_KEY_RECORD)KeyHandle;
	DEBUG_ENTER_FUNCTION("KeyHandle=0x%p", KeyHandle);

	RegCallbackKeyUnregister(keyRecord);
	KeyRecordDereference(keyRecord);

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}


NTSTATUS RegManKeyValueAdd(_In_ HANDLE KeyHandle, _In_opt_ PUNICODE_STRING ValueName, _In_opt_ PVOID Data, _In_opt_ ULONG Length, _In_opt_ ULONG ValueType, _Out_ PHANDLE ValueHandle)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("KeyHandle=0x%p; ValueName=\"%wZ\"; Data=0x%p; Length=%u; ValueType=%u; ValueHandle=0x%p", KeyHandle, ValueName, Data, Length, ValueType, ValueHandle);

	status = KeyRecordValueAdd((PREGMAN_KEY_RECORD)KeyHandle, ValueName, Data, Length, ValueType, (PREGMAN_VALUE_RECORD *)ValueHandle);

	DEBUG_EXIT_FUNCTION("0x%x, *ValueHandle=0x%p", status, *ValueHandle);
	return status;
}


VOID RegManKeyValueDelete(_In_ HANDLE ValueHandle)
{
	PREGMAN_VALUE_RECORD valueRecord = (PREGMAN_VALUE_RECORD)ValueHandle;
	DEBUG_ENTER_FUNCTION("ValueHandle=0x%p", ValueHandle);

	KeyRecordValueDelete(valueRecord->KeyRecord, &valueRecord->Item.Key.String);
	ValueRecordDereference(valueRecord);

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}


NTSTATUS RegManValueCallbacksRegister(_In_ HANDLE ValueHandle, _In_ REGMAN_VALUE_QUERY_CALLBACK *QueryCallback, _In_ REGMAN_VALUE_SET_CALLBACK *SetCallback, _In_opt_ PVOID Context, _Out_ PHANDLE CallbackHandle)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("ValueHandle=0x%p; QueryCallback=0x%p; SetCallback=0x%p; Context=0x%p; CallbackHandle=0x%p", ValueHandle, QueryCallback, SetCallback, Context, CallbackHandle);

	status = ValueRecordCallbackRegister((PREGMAN_VALUE_RECORD)ValueHandle, QueryCallback, SetCallback, Context, CallbackHandle);

	DEBUG_EXIT_FUNCTION("0x%x, *CallbackHandle=0x%p", status, *CallbackHandle);
	return status;
}



VOID RegManValueCallbackUnregiser(_In_ HANDLE CallbackHandle)
{
	DEBUG_ENTER_FUNCTION("CallbackHandle=0x%p", CallbackHandle);

	ValueRecordCallbackUnregister(CallbackHandle);

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}


NTSTATUS RegManInit(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath, PVOID Context)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p; RegistryPath=\"%wZ\"; Context=0x%p", DriverObject, RegistryPath, Context);

	status = ValueRecordModuleInit(DriverObject, RegistryPath, Context);
	if (NT_SUCCESS(status)) {
		status = RegCallbackModuleInit(DriverObject, RegistryPath, Context);
		if (!NT_SUCCESS(status))
			ValueRecordModuleFinit(DriverObject, RegistryPath, Context);
	}

	DEBUG_EXIT_FUNCTION("0x%x", status);
	return status;
}


VOID RegManFinit(_In_ PDRIVER_OBJECT DriverObject, _In_opt_ PUNICODE_STRING RegistryPath, PVOID Context)
{
	DEBUG_ENTER_FUNCTION("DriverObject=0x%p; RegistryPath=\"%wZ\"; Context=0x%p", DriverObject, RegistryPath, Context);

	RegCallbackModuleFinit(DriverObject, RegistryPath, Context);
	ValueRecordModuleFinit(DriverObject, RegistryPath, Context);

	DEBUG_EXIT_FUNCTION_VOID();
	return;
}
