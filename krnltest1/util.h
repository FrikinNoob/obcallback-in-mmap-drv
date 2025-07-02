#pragma once 
__forceinline void MemCpy(PVOID Dst, PVOID Src, ULONG Size) {
	memcpy(Dst, Src, Size);
}
__forceinline void MemZero(PVOID Ptr, SIZE_T Size, UCHAR Filling = 0) {
	memset(Ptr, Filling, Size);
}

__forceinline PVOID KAlloc(ULONG Size, POOL_TYPE PoolType = NonPagedPoolNx) {
	PVOID Buff = ExAllocatePoolWithTag(PoolType, Size, 'KgxD');
	if (Buff) MemZero(Buff, Size); return Buff;
}
__forceinline void KFree(PVOID Ptr, ULONG Size = 0) {
	if (Size) MemZero(Ptr, Size);
	ExFreePoolWithTag(Ptr, 'KgxD');
}

#define InRange(x, a, b) (x >= a && x <= b) 
#define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
#define GetByte(x) ((UCHAR)(GetBits(x[0]) << 4 | GetBits(x[1])))

PVOID FindSection(PVOID ModBase, const char* Name, PULONG SectSize);
PUCHAR FindPattern(PVOID ModBase, const char* SectName, const char* Pattern, ULONG AddressOffset = 0);
PVOID NQSI(SYSTEM_INFORMATION_CLASS Class, ULONG* Size = nullptr);
PVOID GetKernelAddress(const char* ModName, ULONG* Size = nullptr);
PLDR_DATA_TABLE_ENTRY NTAPI MiLookupDataTableEntry(IN PVOID Address);