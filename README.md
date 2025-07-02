## Registering an Object Callback Without a Backing Module

When attempting to register an object callback from an unsigned or manually mapped driver (e.g., via `kdmapper`), the system returns `0xC0000022 (STATUS_ACCESS_DENIED)`.

```cpp
NTSTATUS __stdcall ObRegisterCallbacks(
    POB_CALLBACK_REGISTRATION CallbackRegistration,
    PVOID*                    RegistrationHandle)
{
    ...
    if (!MmVerifyCallbackFunctionCheckFlags(PreOperation, 0x20u))
        goto LABEL_21;

LABEL_21:
    return 0xC0000022; // STATUS_ACCESS_DENIED
}
```

The root cause lies in `MmVerifyCallbackFunctionCheckFlags`, which enforces that the callback function must reside within a properly loaded module **and** that the module’s `LDR_DATA_TABLE_ENTRY->Flags` has the `0x20` bit set

```cpp
BOOL __fastcall MmVerifyCallbackFunctionCheckFlags(void* notifyRoutine, DWORD flags)
{
    struct _KTHREAD*          CurrentThread;
    BOOL                      isValid = FALSE;
    PLDR_DATA_TABLE_ENTRY     entry;

    if (MiGetSystemRegionType((UINT64)notifyRoutine) == 1)
        return FALSE;

    CurrentThread = KeGetCurrentThread();
    --CurrentThread->KernelApcDisable;
    ExAcquireResourceSharedLite(&PsLoadedModuleResource, TRUE);

    entry = (PLDR_DATA_TABLE_ENTRY)MiLookupDataTableEntry(notifyRoutine, 0);
    if (entry && (!flags || (entry->Flags & flags) != 0))
        isValid = TRUE;

    ExReleaseResourceLite(&PsLoadedModuleResource);
    KeLeaveCriticalRegionThread(CurrentThread);
    return isValid;
}
```

The callback pointer must come from a loaded module with bit `0x20` set in its `Flags`.


```cpp
typedef OB_PREOP_CALLBACK_STATUS
(*POB_PRE_OPERATION_CALLBACK)(
    _In_     PVOID                       RegistrationContext,
    _Inout_  POB_PRE_OPERATION_INFORMATION OperationInformation
    );
```
`RegistrationContext` is always passed in `RCX`, and when registering the callback we usually set it to `NULL`.  
This means you can use a `jmp rcx` gadget in a valid module as the callback address and put your real callback’s address into `RegistrationContext`, so that the system jumps into your code.


MiLookupDataTableEntry : https://doxygen.reactos.org/d4/d67/sysldr_8c.html#af88787f6aa47e5cd93b686656feb6c7a
