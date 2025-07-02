#include "global.h"
#include "util.h"

PVOID FindSection(PVOID ModBase, const char* Name, PULONG SectSize)
{
	PIMAGE_NT_HEADERS NT_Header = NT_HEADER(ModBase);
	PIMAGE_SECTION_HEADER Sect = IMAGE_FIRST_SECTION(NT_Header);
	for (PIMAGE_SECTION_HEADER pSect = Sect; pSect < Sect + NT_Header->FileHeader.NumberOfSections; pSect++)
	{
		char SectName[9]; SectName[8] = 0;
		MemCpy(SectName, pSect->Name, 8);
		if (StrICmp(pSect->Name, Name, true))
		{
			if (SectSize) {
				ULONG SSize = SizeAlign(max(pSect->Misc.VirtualSize, pSect->SizeOfRawData));
				*SectSize = SSize;
			}
			return (PVOID)((ULONG64)ModBase + pSect->VirtualAddress);
		}
	}
	return nullptr;
}
PUCHAR FindPattern(PVOID ModBase, const char* SectName, const char* Pattern, ULONG AddressOffset)
{
	ULONG SectSize = 0; ULONG Offset = 0;
	PUCHAR SectStart = (PUCHAR)FindSection(ModBase, SectName, &SectSize);

	PUCHAR ModBuff = (PUCHAR)KAlloc(SectSize); MemCpy(ModBuff, SectStart, SectSize);
	PUCHAR ModuleStart = ModBuff; PUCHAR ModuleEnd = ModBuff + SectSize;

	PUCHAR FirstMatch = nullptr;
	const char* CurPatt = Pattern;
	for (; ModuleStart < ModuleEnd; ++ModuleStart)
	{
		bool SkipByte = (*CurPatt == '\?');
		if (SkipByte || *ModuleStart == GetByte(CurPatt)) {
			if (!FirstMatch) FirstMatch = ModuleStart;
			SkipByte ? CurPatt += 2 : CurPatt += 3;

			if (CurPatt[-1] == 0 && Offset++ == AddressOffset)
				break;
		}
		else if (FirstMatch) {
			ModuleStart = FirstMatch;
			FirstMatch = nullptr;
			CurPatt = Pattern;
		}
	}

	KFree(ModBuff, SectSize);

	return FirstMatch ? (PUCHAR)(((ULONG64)FirstMatch - (ULONG64)ModBuff) + (ULONG64)SectStart) : nullptr;
}

PVOID NQSI(SYSTEM_INFORMATION_CLASS Class, ULONG* Size)
{
NewTry: ULONG ReqSize = 0;
	ZwQuerySystemInformation(Class, nullptr, ReqSize, &ReqSize);
	if (!ReqSize) goto NewTry;

	PVOID pInfo = KAlloc(ReqSize);
	if (!NT_SUCCESS(ZwQuerySystemInformation(Class, pInfo, ReqSize, &ReqSize))) {
		KFree(pInfo, ReqSize); goto NewTry;
	}

	if (Size) *Size = ReqSize;

	return pInfo;
}

PVOID GetKernelAddress(const char* ModName, ULONG* Size)
{
	ULONG ReqSize;
	PSYSTEM_MODULE_INFORMATION ModuleList = (PSYSTEM_MODULE_INFORMATION)NQSI(SystemModuleInformation, &ReqSize);

	PVOID ModuleBase = 0;
	for (ULONG64 i = 0; i < ModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE Module = ModuleList->Modules[i];
		if (StrICmp(&Module.ImageName[Module.ModuleNameOffset], ModName, true)) {
			ModuleBase = Module.Base;

			if (Size) *Size = Module.Size;

			break;
		}
	}

	KFree(ModuleList, ReqSize);
	return ModuleBase;
}

PLDR_DATA_TABLE_ENTRY NTAPI MiLookupDataTableEntry(IN PVOID Address)
{
	PLDR_DATA_TABLE_ENTRY LdrEntry, FoundEntry = NULL;
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

		/* Check if the address matches */
		if ((Address >= LdrEntry->DllBase) &&
			(Address < (PVOID)((ULONG_PTR)LdrEntry->DllBase +
				LdrEntry->SizeOfImage)))
		{
			/* Found a match */
			FoundEntry = LdrEntry;
			break;
		}

		/* Move on */
		NextEntry = NextEntry->Flink;
	} while (NextEntry != &PsLoadedModuleList);

	/* Return the entry */
	return FoundEntry;
}