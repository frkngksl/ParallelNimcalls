import Structs
import winim/lean
import cstrutils

const MAX_SYSCALL_STUB_SIZE = 64
const MAX_NUMBER_OF_SYSCALLS = 1024

type
    NtCreateThreadExType = proc(hThread: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: PVOID, ProcessHandle: HANDLE, lpStartAddress: PVOID, lpParameter: PVOID,Flags:ULONG,StackZeroBits:SIZE_T,SizeOfStackCommit:SIZE_T,SizeOfStackReserve:SIZE_T,lpBytesBuffer: PVOID):NTSTATUS {.stdcall.}
    NtOpenFileType = proc(FileHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, IoStatusBlock: PIO_STATUS_BLOCK, ShareAccess: ULONG, OpenOptions: ULONG):NTSTATUS {.stdcall.}
    NtCreateSectionType = proc(SectionHandle: PHANDLE, DesiredAccess:ACCESS_MASK,ObjectAttributes:POBJECT_ATTRIBUTES,MaximumSize:PLARGE_INTEGER,SectionPageProtection:ULONG,AllocationAttributes:ULONG,FileHandle:HANDLE):NTSTATUS{.stdcall.}
    NtMapViewOfSectionType = proc(SectionHandle: HANDLE, ProcessHandle:HANDLE,BaseAddress:ptr LPVOID,ZeroBits:ULONG_PTR,CommitSize:SIZE_T,SectionOffset:PLARGE_INTEGER,ViewSize:PSIZE_T,InheritDisposition:DWORD,AllocationType:ULONG,Win32Protect:ULONG):NTSTATUS{.stdcall.}

var ntOpenFileClean:NtOpenFileType= nil
var ntCreateSectionClean:NtCreateSectionType = nil
var ntMapViewOfSectionClean:NtMapViewOfSectionType = nil
var syscallNames:array[MAX_NUMBER_OF_SYSCALLS,string]
var syscallStubs:array[MAX_NUMBER_OF_SYSCALLS,uint64]

proc GetSyscall(syscallName:string,uiCount:UINT):uint64 =
    for i in countup(0, cast[int] (uiCount-1)):
        if(syscallName == syscallNames[i]):
            return syscallStubs[i]
    return 0


proc FindBytes(sourceAddr:uint64,sourceLength:DWORD):uint64 =
    var sourceAddrMut = sourceAddr
    var sourceLengthMut = sourceLength
    while(3<=sourceLengthMut):
        var test:ptr array[3,byte] = cast[ptr array[3,byte]](sourceAddrMut)
        if(test[0] == 0xf and test[1] == 0x5 and test[2] == 0xc3):
            return sourceAddrMut
        sourceAddrMut+=uint64(1)
        sourceLengthMut-=DWORD(1)
    return 0


proc RVAToFileOffsetPointer(pModule:ULONG_PTR,dwRVA:DWORD):uint64 =
    var dosHeader: PIMAGE_DOS_HEADER = cast[PIMAGE_DOS_HEADER](pModule)
    var imageNtHeaders: PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](pModule+dosHeader.e_lfanew)
    var sectionHeader: PIMAGE_SECTION_HEADER = cast[PIMAGE_SECTION_HEADER](cast[uint64](addr imageNtHeaders.OptionalHeader) + imageNtHeaders.FileHeader.SizeOfOptionalHeader)
    var i:int = 0
    var uintRva: uint64 = cast[uint64](dwRVA)
    while i < cast[int] (imageNtHeaders.FileHeader.NumberOfSections):
        if(cast[uint64](sectionHeader.VirtualAddress) <= uintRva and cast[uint64](sectionHeader.VirtualAddress) + cast[uint64](sectionHeader.Misc.VirtualSize) > uintRva):
            uintRva-=cast[uint64](sectionHeader.VirtualAddress)
            uintRva+=cast[uint64](sectionHeader.PointerToRawData)
            return cast[uint64](pModule) + uintRva
        sectionHeader = cast[PIMAGE_SECTION_HEADER](cast[uint64] (sectionHeader) + cast[uint64] (sizeof(IMAGE_SECTION_HEADER)))
        i=i+1
    return 0
    

proc extractSyscalls(ntdllBase:uint64): UINT =
    var dosHeader: PIMAGE_DOS_HEADER = cast[PIMAGE_DOS_HEADER](ntdllBase)
    var imageNtHeaders: PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](ntdllBase+cast[uint64](dosHeader.e_lfanew))
    #var sectionHeader: PIMAGE_SECTION_HEADER = cast[PIMAGE_SECTION_HEADER](cast[uint64](addr imageNtHeaders.OptionalHeader) + imageNtHeaders.FileHeader.SizeOfOptionalHeader)
    var dataDirectory: array[IMAGE_NUMBEROF_DIRECTORY_ENTRIES, IMAGE_DATA_DIRECTORY]=imageNtHeaders.OptionalHeader.DataDirectory
    var virtualAddress:DWORD = dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    var exportDirectory: PIMAGE_EXPORT_DIRECTORY = cast[PIMAGE_EXPORT_DIRECTORY](RVAToFileOffsetPointer(cast[ULONG_PTR](ntdllBase),virtualAddress))  
    var numberOfNames: DWORD = exportDirectory.NumberOfNames
    var functions:uint64 = RVAToFileOffsetPointer(cast[ULONG_PTR](ntdllBase),exportDirectory.AddressOfFunctions)
    var names:uint64 =  RVAToFileOffsetPointer(cast[ULONG_PTR](ntdllBase),exportDirectory.AddressOfNames)
    var ordinals:uint64 = RVAToFileOffsetPointer(cast[ULONG_PTR](ntdllBase),exportDirectory.AddressOfNameOrdinals)
    var uiCount:UINT = 0
    var i:DWORD = 0
    var pStubs:uint64 = cast[uint64](VirtualAlloc(NULL, MAX_NUMBER_OF_SYSCALLS * MAX_SYSCALL_STUB_SIZE, MEM_RESERVE or MEM_COMMIT, PAGE_EXECUTE_READWRITE))
    if(pStubs == 0):
        return uiCount
    while i < numberOfNames and uiCount < MAX_NUMBER_OF_SYSCALLS:
        var functionNameAddr:PDWORD = cast[PDWORD](names+cast[uint64](i*sizeof(DWORD)))
        var offset = functionNameAddr[]
        var szName: cstring = cast[cstring](RVAToFileOffsetPointer(cast[ULONG_PTR](ntdllBase),offset))
        if(startsWith(szName,cstring"Zw")):
            var functionOrdinalPtr:PWORD = cast[PWORD](ordinals+cast[uint64](i*sizeof(WORD)))
            var functionOrdinal:WORD = functionOrdinalPtr[]
            var functionAddressPtr:PDWORD = cast[PDWORD](functions+cast[uint64](functionOrdinal*WORD(sizeof(DWORD))))
            var functionAddress:DWORD = functionAddressPtr[]
            var functionPtr:uint64 = RVAToFileOffsetPointer(cast[ULONG_PTR](ntdllBase),functionAddress)
            var functionEnd:uint64 = FindBytes(functionPtr,MAX_SYSCALL_STUB_SIZE)+3
            #echo functionPtr
            #echo functionEnd
            if(functionEnd > 3):
                syscallNames[uiCount] = $szName
                syscallNames[uiCount][0] = 'N'
                syscallNames[uiCount][1] = 't'
                copyMem(cast[pointer](pStubs + cast[uint64](uiCount * MAX_SYSCALL_STUB_SIZE)),cast[pointer](functionPtr),functionEnd-functionPtr)
                syscallStubs[uiCount]=pStubs + cast[uint64](uiCount * MAX_SYSCALL_STUB_SIZE)
                uiCount+=1
        i+=1
    return uiCount


proc loadNtdllIntoSection(): uint64 =
    var resultOfSyscall:NTSTATUS = 0
    var hFile:HANDLE = 0
    var objectAttributes:OBJECT_ATTRIBUTES 
    var objectPath:UNICODE_STRING 
    var ioStatusBlock:IO_STATUS_BLOCK
    var hSection:HANDLE = 0
    var lpvSection:LPVOID = nil
    var viewSize:SIZE_T = 0

    RtlInitUnicodeString(addr(objectPath), "\\??\\C:\\Windows\\System32\\ntdll.dll");
    InitializeObjectAttributes(addr(objectAttributes),addr(objectPath),OBJ_CASE_INSENSITIVE,0,nil)
    resultOfSyscall = ntOpenFileClean(addr(hFile),FILE_READ_DATA,addr(objectAttributes),addr(ioStatusBlock),FILE_SHARE_READ,0)
    if (not NT_SUCCESS(resultOfSyscall)):
        echo "[!] Error on NtOpenFile System Call"
        return 0
    resultOfSyscall = ntCreateSectionClean(addr(hSection),SECTION_ALL_ACCESS,nil,nil,PAGE_READONLY,SEC_COMMIT,hFile)
    if (not NT_SUCCESS(resultOfSyscall)):
        echo "[!] Error on NtCreateSection System Call"
        return 0
    resultOfSyscall = ntMapViewOfSectionClean(hSection, GetCurrentProcess(), addr(lpvSection), cast[ULONG_PTR](nil), cast[SIZE_T](nil), cast[PLARGE_INTEGER](nil), addr(viewSize), 1, 0, PAGE_READONLY)
    if (not NT_SUCCESS(resultOfSyscall)):
        echo "[!] Error on NtCreateSection System Call"
        return 0
    CloseHandle(hFile)
    CloseHandle(hSection)
    return cast[uint64](lpvSection)

proc buildSyscallStub(stubRegion:uint64,syscallNo:uint32): uint64 =
    var syscallStub:array[11,byte] = [byte 0x4c, 0x8b, 0xd1,0xb8, 0x00, 0x00, 0x00, 0x00,0x0f, 0x05,0xc3]
    copyMem(cast[pointer] (stubRegion) ,addr syscallStub,syscallStub.len)
    var ptrToStub:uint64 = stubRegion + 4
    var ptrToMemory:ptr uint32 = cast[ptr uint32 ](ptrToStub)
    ptrToMemory[] = syscallNo
    return stubRegion


proc initSyscallsFromLdrpThunkSignature(): bool =
    var pebPointer: Structs.PPEB = GetPEB()
    if(pebPointer == nil):
        return false
    var head: PLIST_ENTRY = (addr pebPointer.Ldr.InLoadOrderModuleList)
    var cursor: PLIST_ENTRY = (pebPointer.Ldr.InLoadOrderModuleList.Flink)
    var ntdllBase: ByteAddress = 0
    while head != cursor:
        var ldrData = cast[Structs.PLDR_DATA_TABLE_ENTRY](cursor)
        var name = cast[ptr array[32, uint16]](ldrData.BaseDllName.Buffer)
        var charName: string
        var index: int = 0
        while name[index] != 0x0:
            charName.add(cast[char](name[index]))
            index=index+1
        #echo charName
        if(charName == "ntdll.dll"):
            ntdllBase = cast[ByteAddress](ldrData.DllBase)
            break
        cursor = cursor.Flink
    var imageNtHeaders:PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](ntdllBase+(cast[PIMAGE_DOS_HEADER] (ntdllBase).e_lfanew))
    var sectionHeader:PIMAGE_SECTION_HEADER = cast[PIMAGE_SECTION_HEADER]( cast[uint64](addr imageNtHeaders.OptionalHeader) + imageNtHeaders.FileHeader.SizeOfOptionalHeader)
    var i:int = 0
    var dataSectionAddress:uint64 = 0 
    var dataSectionSize:uint64 = 0
    while i < cast[int] (imageNtHeaders.FileHeader.NumberOfSections):
        var nameOfSection:array[IMAGE_SIZEOF_SHORT_NAME, BYTE] = sectionHeader.Name
        var sectionName: string
        var index: int = 0
        while nameOfSection[index] != 0x0:
            sectionName.add(cast[char](nameOfSection[index]))
            index=index+1
        i=i+1
        if sectionName == ".data":
            dataSectionAddress = cast[uint64] (ntdllBase + sectionHeader.VirtualAddress)
            dataSectionSize = cast[uint64] (sectionHeader.Misc.VirtualSize)
        sectionHeader = cast[PIMAGE_SECTION_HEADER](cast[uint64] (sectionHeader) + cast[uint64] (sizeof(IMAGE_SECTION_HEADER)))
    var ntOpenFileNum:uint32 = 0
    var ntCreateSectionNum:uint32 = 0
    var ntMapViewOfSectionNum:uint32 = 0
    if(dataSectionSize < 16*5 or dataSectionAddress == 0):
        return false
    for offset in countup(0, cast[int] (dataSectionSize - (16 * 5)-1)):
        var element1 = cast[ptr uint32](dataSectionAddress + cast[uint64] (offset) )[]
        var element2 = cast[ptr uint32](dataSectionAddress + cast[uint64] (offset) + 16)[]
        var element3 = cast[ptr uint32](dataSectionAddress + cast[uint64] (offset) + 32)[]
        var element4 = cast[ptr uint32](dataSectionAddress + cast[uint64] (offset) + 48)[]
        var element5 = cast[ptr uint32](dataSectionAddress + cast[uint64] (offset) + 64)[]
        var signature:uint32 = cast[uint32] (0xb8d18b4c)
        
        if (element1 == signature and element2 == signature and element3 == signature and element4 == signature and element5 == signature):
            ntOpenFileNum = cast[ptr uint32](dataSectionAddress + cast[uint64] (offset) + 4)[]
            ntCreateSectionNum = cast[ptr uint32](dataSectionAddress + cast[uint64] (offset) + 16 + 4)[]
            ntMapViewOfSectionNum = cast[ptr uint32](dataSectionAddress + cast[uint64] (offset) + 64 + 4)[]
            echo "[+] Found NtOpenFile Syscall Number: ",ntOpenFileNum
            echo "[+] Found NtCreateSection Syscall Number: ",ntCreateSectionNum
            echo "[+] Found NtMapViewOfSection Syscall Number: ",ntMapViewOfSectionNum
            break
    if(ntOpenFileNum == 0 or ntCreateSectionNum == 0 or ntMapViewOfSectionNum == 0):
        return false
    var memPointer = cast[uint64] (VirtualAlloc(nil,3 * MAX_SYSCALL_STUB_SIZE, MEM_RESERVE or MEM_COMMIT, PAGE_EXECUTE_READWRITE))
    ntOpenFileClean = cast[NtOpenFileType] (buildSyscallStub(memPointer,ntOpenFileNum))
    ntCreateSectionClean = cast[NtCreateSectionType](buildSyscallStub(memPointer+MAX_SYSCALL_STUB_SIZE,ntCreateSectionNum))
    ntMapViewOfSectionClean = cast[NtMapViewOfSectionType] (buildSyscallStub(memPointer+(2*MAX_SYSCALL_STUB_SIZE),ntMapViewOfSectionNum))
    return true

when isMainModule:
    var result = initSyscallsFromLdrpThunkSignature()
    if(not result):
        echo "[!] LdrpThunk Error"
        quit(0)
    var pNtdll = loadNtdllIntoSection()
    if(pNtdll == 0):
        echo "[!] Load Ntdll Error"
        quit(0)
    var uiCount:UINT = extractSyscalls(pNtdll)
    if( uiCount == 0):
        echo "[!] Extract Syscall Error"
        quit(0)
    echo "[+] Number of extracted syscalls:",uiCount
    var ntCreateThreadExReturn = (GetSyscall("NtCreateThreadEx",uiCount))
    if(ntCreateThreadExReturn == 0):
        echo "[!] Syscall not found"
        quit(0)
    var ntCreateThreadExAddr = cast[NtCreateThreadExType] (ntCreateThreadExReturn)
    var hThread:HANDLE
    var ntStatus:NTSTATUS = ntCreateThreadExAddr(addr(hThread), GENERIC_ALL, nil, GetCurrentProcess(), cast[PVOID] (0x41414141), nil, 0, 0, 0, 0, nil)