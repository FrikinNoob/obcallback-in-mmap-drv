#include "global.h"

#define DbgPrintf(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, __VA_ARGS__)

UNICODE_STRING Altitude = RTL_CONSTANT_STRING(L"300000");

PVOID obCallbackRegHandle;

void* GetProcAddress(const wchar_t* szRoutine) {
	UNICODE_STRING unRoutine;
	RtlInitUnicodeString(&unRoutine, szRoutine);
	return MmGetSystemRoutineAddress(&unRoutine);
}

void DriverUnload(PDRIVER_OBJECT pDrvObj)
{
    UnRef(pDrvObj);

    if (obCallbackRegHandle) {
        ObUnRegisterCallbacks(obCallbackRegHandle);
        DbgPrintf("[-] ObUnRegisterCallbacks\n");
    }

    DbgPrintf("[-] DriverUnload\n");
    return;
}

OB_PREOP_CALLBACK_STATUS ObCallback(PVOID arg1, POB_PRE_OPERATION_INFORMATION OpInfo)
{
    UnRef(arg1);

    ULONG desiredAccess = 0;
    ULONG originalAccess = 0;

    if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = OpInfo->Parameters->CreateHandleInformation.DesiredAccess;
        originalAccess = OpInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    }
    else if (OpInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
        originalAccess = OpInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    }

    DbgPrintf("ObPreCallback, Op=%u, Obj=0x%p, Flags=0x%x, DesiredAccess=0x%x, ProcId=%u\n",
        OpInfo->Operation,
        OpInfo->Object,
        OpInfo->Flags,
        desiredAccess,
        HandleToULong(PsGetCurrentProcessId()));

    return OB_PREOP_SUCCESS;
}

void* FindValidJmpRcxGadget()
{
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PLIST_ENTRY NextEntry;    
    PAGED_CODE();

    /* Loop entries */
    NextEntry = PsLoadedModuleList.Flink;
    do
    {
        /* Get the loader entry */
        LdrEntry = CONTAINING_RECORD(NextEntry,
            LDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks);

        if (LdrEntry->Flags & 0x20)
        {
            DbgPrintf("[+] Found valid module: %wZ, Flags: 0x%x\n",
                &LdrEntry->BaseDllName, LdrEntry->Flags);

            void* base = LdrEntry->DllBase;
            PUCHAR pat = FindPattern(base, ".text", "FF E1");
            if (pat) {
                DbgPrintf("[+] Gotcha!\n");
                return pat;
            }
        }
        
        /* Move on */
        NextEntry = NextEntry->Flink;
    } while (NextEntry != &PsLoadedModuleList);

    return NULL;
}

void EnumObCallbackEntry(bool bProcessType) {
    /* https://www.vergiliusproject.com/kernels/x64/windows-10/21h2/_OBJECT_TYPE */
    //0xd8 bytes (sizeof)
    struct _OBJECT_TYPE
    {
        struct _LIST_ENTRY TypeList;                                            //0x0
        struct _UNICODE_STRING Name;                                            //0x10
        VOID* DefaultObject;                                                    //0x20
        UCHAR Index;                                                            //0x28
        ULONG TotalNumberOfObjects;                                             //0x2c
        ULONG TotalNumberOfHandles;                                             //0x30
        ULONG HighWaterNumberOfObjects;                                         //0x34
        ULONG HighWaterNumberOfHandles;                                         //0x38
        struct _OBJECT_TYPE_INITIALIZER TypeInfo;                               //0x40
        struct _EX_PUSH_LOCK TypeLock;                                          //0xb8
        ULONG Key;                                                              //0xc0
        struct _LIST_ENTRY CallbackList;                                        //0xc8
    }  *Type = bProcessType ? *(_OBJECT_TYPE**)PsProcessType : *(_OBJECT_TYPE**)PsThreadType;

    struct OB_CALLBACK;
    typedef struct _OB_CALLBACK_ENTRY {
        LIST_ENTRY                   CallbackList;   
        OB_OPERATION                 Operations;     
        BOOLEAN                      Enabled;     
        OB_CALLBACK*                 Entry;
        POBJECT_TYPE                 ObjectType;   
        POB_PRE_OPERATION_CALLBACK   PreOperation;  
        POB_POST_OPERATION_CALLBACK  PostOperation; 
        KSPIN_LOCK                   Lock;       
    } OB_CALLBACK_ENTRY, * POB_CALLBACK_ENTRY;

    PLIST_ENTRY callbackListHead = &Type->CallbackList;
    for (PLIST_ENTRY link = callbackListHead->Blink; link != callbackListHead; link = link->Blink) {
        POB_CALLBACK_ENTRY entry = (POB_CALLBACK_ENTRY)link;

        void* PreOp = entry->PreOperation;
        void* PostOp = entry->PostOperation;
        if (PreOp) {            
            auto Ldr = MiLookupDataTableEntry(PreOp);
            if (Ldr) {
                DWORD offset = (uintptr_t)PreOp - (uintptr_t)Ldr->DllBase;
                DbgPrintf("[+] PreOp: %wZ+0x%x\n", &Ldr->BaseDllName, offset);
            }
            else {
                DbgPrintf("[!] PreOp(0x%p) don't have backing module?\n", PreOp);
            }
        }

        if (PostOp) {
            auto Ldr = MiLookupDataTableEntry(PostOp);
            if (Ldr) {
                DWORD offset = (uintptr_t)PostOp - (uintptr_t)Ldr->DllBase;
                DbgPrintf("[+] PostOp: %wZ+0x%x\n", &Ldr->BaseDllName, offset);
            }
            else {
                DbgPrintf("[!] PostOp(0x%p) don't have backing module?\n", PostOp);
            }
        }
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
    UnRef(pRegPath);
    
    obCallbackRegHandle = 0;

    OB_OPERATION_REGISTRATION OpReg;
    OB_CALLBACK_REGISTRATION CbReg;
    MemZero(&OpReg, sizeof(OpReg));
    MemZero(&CbReg, sizeof(CbReg));

    DbgPrintf("[+] driver loaded at 0x%p, size=0x%x\n", pDrvObj->DriverStart, pDrvObj->DriverSize);
    pDrvObj->DriverUnload = DriverUnload;

    do {
        ULONG dwNtos = 0;
        PVOID ntos = GetKernelAddress("ntoskrnl.exe", &dwNtos);
        if (!ntos) {
            DbgPrintf("[!] failed to GetKernelAddress\n");
            break;
        }

        DbgPrintf("[+] ntos: 0x%p, size: 0x%x\n", ntos, dwNtos);

        void* pat = FindValidJmpRcxGadget();

        DbgPrintf("[+] jmp rcx at 0x%p\n", pat);
        if (!pat)
            break;

        OpReg.ObjectType = PsProcessType;
        OpReg.Operations = OB_OPERATION_HANDLE_CREATE;
        OpReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)pat;
        OpReg.PostOperation = NULL;

        CbReg.Version = OB_FLT_REGISTRATION_VERSION;
        CbReg.Altitude = Altitude;
        CbReg.RegistrationContext = &ObCallback;
        CbReg.OperationRegistrationCount = 1;
        CbReg.OperationRegistration = &OpReg;

        NTSTATUS status = ObRegisterCallbacks(&CbReg, &obCallbackRegHandle);
        DbgPrintf("[+] ObRegisterCallbacks result: 0x%x\n", status);

         EnumObCallbackEntry(true);

    } while (0);

    return STATUS_SUCCESS;
}