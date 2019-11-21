#pragma once
#include "../hide_str.hpp"
#include "../t1ha/t1ha.h"

#include <string>
#include <TlHelp32.h>
#include <Windows.h>
#include <winnt.h>
#include <winternl.h>

#define STRONG_SEED 10376313370251892926
#define RAND_DWORD1	0x03EC7B5E
#define ROR(x,n) (((x) >> (n)) | ((x) << (32-(n))))

// -----------------
#pragma region Export Work
struct LDR_MODULE
{
  LIST_ENTRY e[3];
  HMODULE base;
  void *entry;
  UINT size;
  UNICODE_STRING dllPath;
  UNICODE_STRING dllname;
};

typedef struct _PEB_LDR_DATA_
{
  BYTE Reserved1[8];
  PVOID Reserved2[3];
  LIST_ENTRY *InMemoryOrderModuleList;
} PEB_LDR_DATA_, * PPEB_LDR_DATA_;

#ifdef _WIN64

typedef struct _PEB_c
{
  BYTE Reserved1[2];
  BYTE BeingDebugged;
  BYTE Reserved2[21];
  PPEB_LDR_DATA_ Ldr;
} PEB_c;

#else

typedef struct _PEB_c
{
  /*0x000*/     UINT8        InheritedAddressSpace;
  /*0x001*/     UINT8        ReadImageFileExecOptions;
  /*0x002*/     UINT8        BeingDebugged;
  /*0x003*/     UINT8        SpareBool;
  /*0x004*/     VOID *Mutant;
  /*0x008*/     VOID *ImageBaseAddress;
  /*0x00C*/     struct _PEB_LDR_DATA *Ldr;
  /*.....*/
} PEB_c;

#endif

#pragma warning (disable : 4996)
__forceinline const wchar_t *char_to_wchar(const char *c)
{
  const size_t cSize = strlen(c) + 1;
  wchar_t *wc = new wchar_t[cSize];
  mbstowcs(wc, c, cSize);
  return wc;
}

static HMODULE(WINAPI *temp_LoadLibraryA)(__in LPCSTR file_name) = nullptr;

static int (*temp_lstrcmpiW)(LPCWSTR lpString1, LPCWSTR lpString2) = nullptr;

static __forceinline HMODULE hash_LoadLibraryA(__in LPCSTR file_name)
{
  return temp_LoadLibraryA(file_name);
}

static __forceinline int hash_lstrcmpiW(LPCWSTR lpString1,
                                        LPCWSTR lpString2)
{
  return temp_lstrcmpiW(lpString1,
                        lpString2);
}

__forceinline HMODULE kernel32Handle(void)
{
  HMODULE dwResult = NULL;
  PEB_c *lpPEB = NULL;
  SIZE_T *lpFirstModule = NULL;
#if defined _WIN64
  lpPEB = *(PEB_c **)(__readgsqword(0x30) + 0x60); //get a pointer to the PEB
#else
  lpPEB = *(PEB_c **)(__readfsdword(0x18) + 0x30); //get a pointer to the PEB
#endif
  // PEB->Ldr->LdrInMemoryOrderModuleList
  // PEB->Ldr = 0x0C
  // Ldr->LdrInMemoryOrderModuleList = 0x14
  lpFirstModule = (SIZE_T *)lpPEB->Ldr->InMemoryOrderModuleList;
  SIZE_T *lpCurrModule = lpFirstModule;
  do
  {
    PWCHAR szwModuleName = (PWCHAR)lpCurrModule[10]; // 0x28 - module name in unicode
    DWORD i = 0;
    DWORD dwHash = 0;
    while (szwModuleName[i])
    {
      BYTE zByte = (BYTE)szwModuleName[i];
      if (zByte >= 'a' && zByte <= 'z')
        zByte -= 0x20; // Uppercase
      dwHash = ROR(dwHash, 13) + zByte;
      i++;
    }
    if ((dwHash ^ RAND_DWORD1) == (0x6E2BCA17 ^ RAND_DWORD1)) // KERNEL32.DLL hash
    {
      dwResult = (HMODULE)lpCurrModule[4];
      return dwResult;
    }
    lpCurrModule = (SIZE_T *)lpCurrModule[0]; // next module in linked list
  } while (lpFirstModule != (SIZE_T *)lpCurrModule[0]);
  return dwResult;
}

__forceinline LPVOID parse_export_table(HMODULE module, uint64_t api_hash, uint64_t len, const uint64_t seed)
{
  PIMAGE_DOS_HEADER img_dos_header;
  PIMAGE_NT_HEADERS img_nt_header;
  PIMAGE_EXPORT_DIRECTORY in_export;
  img_dos_header = (PIMAGE_DOS_HEADER)module;
  img_nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)img_dos_header + img_dos_header->e_lfanew);
  in_export = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)img_dos_header + img_nt_header->OptionalHeader.DataDirectory[
                                         IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  PDWORD rva_name;
  PWORD rva_ordinal;
  rva_name = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNames);
  rva_ordinal = (PWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfNameOrdinals);
  UINT ord = -1;
  char *api_name;
  unsigned int i;
  for (i = 0; i < in_export->NumberOfNames - 1; i++)
  {
    api_name = (PCHAR)((DWORD_PTR)img_dos_header + rva_name[i]);
    const uint64_t get_hash = t1ha0(api_name, len, seed);
    if (api_hash == get_hash)
    {
      ord = static_cast<UINT>(rva_ordinal[i]);
      break;
    }
  }
  const auto func_addr = (PDWORD)((DWORD_PTR)img_dos_header + in_export->AddressOfFunctions);
  const auto func_find = (LPVOID)((DWORD_PTR)img_dos_header + func_addr[ord]);
  return func_find;
}

__forceinline LPVOID get_api(uint64_t api_hash, LPCSTR module, uint64_t len, const uint64_t seed)
{
  HMODULE krnl32, hDll;
  LPVOID api_func;
#ifdef _WIN64
  const auto ModuleList = 0x18;
  const auto ModuleListFlink = 0x18;
  const auto KernelBaseAddr = 0x10;
  const INT_PTR peb = __readgsqword(0x60);
#else
  int ModuleList = 0x0C;
  int ModuleListFlink = 0x10;
  int KernelBaseAddr = 0x10;
  INT_PTR peb = __readfsdword(0x30);
#endif
  const auto mdllist = *(INT_PTR *)(peb + ModuleList);
  const auto mlink = *(INT_PTR *)(mdllist + ModuleListFlink);
  auto krnbase = *(INT_PTR *)(mlink + KernelBaseAddr);
  auto mdl = (LDR_MODULE *)mlink;
  HMODULE hKernel32 = NULL;
  hKernel32 = kernel32Handle();
  const char *lstrcmpiW_ = (LPCSTR)PRINT_HIDE_STR("lstrcmpiW");
  const uint64_t api_hash_lstrcmpiW = t1ha0(lstrcmpiW_, strlen(lstrcmpiW_), STRONG_SEED);
  temp_lstrcmpiW = static_cast<int(*)(LPCWSTR, LPCWSTR)>(parse_export_table(
                     hKernel32, api_hash_lstrcmpiW, strlen(lstrcmpiW_), STRONG_SEED));
  do
  {
    mdl = (LDR_MODULE *)mdl->e[0].Flink;
    if (mdl->base != nullptr)
    {
      if (!hash_lstrcmpiW(mdl->dllname.Buffer, char_to_wchar((LPCSTR)PRINT_HIDE_STR("kernel32.dll"))))
      {
        break;
      }
    }
  } while (mlink != (INT_PTR)mdl);
  krnl32 = static_cast<HMODULE>(mdl->base);
  const char *LoadLibraryA_ = (LPCSTR)PRINT_HIDE_STR("LoadLibraryA");
  const uint64_t api_hash_LoadLibraryA = t1ha0(LoadLibraryA_, strlen(LoadLibraryA_), STRONG_SEED);
  temp_LoadLibraryA = static_cast<HMODULE(WINAPI *)(LPCSTR)>(parse_export_table(
                        krnl32, api_hash_LoadLibraryA, strlen(LoadLibraryA_), STRONG_SEED));
  hDll = hash_LoadLibraryA(module);
  api_func = static_cast<LPVOID>(parse_export_table(hDll, api_hash, len, seed));
  return api_func;
}

#pragma endregion Export Work

// -----------------
#pragma region Pointer Hash Functions
HANDLE(WINAPI *temp_CreateFile)(__in LPCSTR file_name,
                                __in DWORD access,
                                __in DWORD share,
                                __in LPSECURITY_ATTRIBUTES security,
                                __in DWORD creation_disposition,
                                __in DWORD flags,
                                __in HANDLE template_file) = nullptr;

BOOL(WINAPI *temp_VirtualProtect)(LPVOID lpAddress,
                                  SIZE_T dwSize,
                                  DWORD flNewProtect,
                                  PDWORD lpflOldProtect) = nullptr;

LPVOID(WINAPI *temp_VirtualAlloc)(LPVOID lpAddress,
                                  SIZE_T dwSize,
                                  DWORD flAllocationType,
                                  DWORD flProtect) = nullptr;

BOOL(WINAPI *temp_VirtualFree)(LPVOID lpAddress,
                               SIZE_T dwSize,
                               DWORD dwFreeType) = nullptr;

LPVOID(WINAPI *temp_VirtualAllocEx)(HANDLE hProcess,
                                    LPVOID lpAddress,
                                    SIZE_T dwSize,
                                    DWORD flAllocationType,
                                    DWORD flProtect) = nullptr;

BOOL(WINAPI *temp_VirtualFreeEx)(HANDLE hProcess,
                                 LPVOID lpAddress,
                                 SIZE_T dwSize,
                                 DWORD dwFreeType) = nullptr;


DWORD(WINAPI *temp_QueryDosDeviceW)(LPCWSTR lpDeviceName,
                                    LPWSTR lpTargetPath,
                                    DWORD ucchMax) = nullptr;

BOOL(WINAPI *temp_GetDiskFreeSpaceExW)(LPCWSTR lpDirectoryName,
                                       PULARGE_INTEGER lpFreeBytesAvailableToCaller,
                                       PULARGE_INTEGER lpTotalNumberOfBytes,
                                       PULARGE_INTEGER lpTotalNumberOfFreeBytes) = nullptr;

HMODULE(WINAPI *temp_LoadLibraryW)(LPCWSTR lpLibFileName) = nullptr;

BOOL(WINAPI *temp_GetModuleHandleExW)(DWORD dwFlags,
                                      LPCWSTR lpModuleName,
                                      HMODULE *phModule) = nullptr;

DWORD(WINAPI *temp_GetModuleFileNameW)(HMODULE hModule,
                                       LPWSTR lpFilename,
                                       DWORD nSize) = nullptr;

HMODULE(WINAPI *temp_GetModuleHandleA)(LPCSTR lpModuleName) = nullptr;

FARPROC(WINAPI *temp_GetProcAddress)(HMODULE hModule,
                                     LPCSTR lpProcName) = nullptr;

HMODULE(WINAPI *temp_GetModuleHandleW)(LPCWSTR lpModuleName) = nullptr;

HANDLE(WINAPI *temp_GetCurrentThread)() = nullptr;

HANDLE(WINAPI *temp_GetStdHandle)(_In_ DWORD nStdHandle) = nullptr;

BOOL(WINAPI *temp_GetConsoleScreenBufferInfo)(_In_ HANDLE hConsoleOutput,
    _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo) = nullptr;

BOOL(WINAPI *temp_SetConsoleTextAttribute)(_In_ HANDLE hConsoleOutput,
    _In_ WORD wAttributes) = nullptr;

DWORD(WINAPI *temp_GetTickCount)() = nullptr;

BOOL(WINAPI *temp_VerifyVersionInfoW)(LPOSVERSIONINFOEXA lpVersionInformation,
                                      DWORD dwTypeMask,
                                      DWORDLONG dwlConditionMask) = nullptr;

UINT(WINAPI *temp_GetSystemWindowsDirectoryW)(LPWSTR lpBuffer,
    UINT uSize) = nullptr;

UINT(WINAPI *temp_GetWindowsDirectoryW)(LPWSTR lpBuffer,
                                        UINT uSize) = nullptr;

UINT(WINAPI *temp_GetSystemDirectoryW)(LPWSTR lpBuffer,
                                       UINT uSize) = nullptr;

UINT(WINAPI *temp_GetSystemDirectoryA)(LPSTR lpBuffer,
                                       UINT uSize) = nullptr;

void (WINAPI *temp_GetSystemInfo)(LPSYSTEM_INFO lpSystemInfo) = nullptr;

DWORD(WINAPI *temp_ExpandEnvironmentStringsW)(LPCWSTR lpSrc,
    LPWSTR lpDst,
    DWORD nSize) = nullptr;

BOOL(WINAPI *temp_QueryPerformanceCounter)(LARGE_INTEGER *lpPerformanceCount) = nullptr;

BOOL(WINAPI *temp_IsProcessorFeaturePresent)(DWORD ProcessorFeature) = nullptr;

PVOID(WINAPI *temp_AddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) = nullptr;

void (WINAPI *temp_SetLastError)(DWORD dwErrCode) = nullptr;

_Post_equals_last_error_ DWORD(WINAPI *temp_GetLastError)() = nullptr;

void (WINAPI *temp_OutputDebugStringW)(LPCWSTR lpOutputString) = nullptr;

DWORD(WINAPI *temp_FormatMessageW)(DWORD dwFlags,
                                   LPCVOID lpSource,
                                   DWORD dwMessageId,
                                   DWORD dwLanguageId,
                                   LPWSTR lpBuffer,
                                   DWORD nSize,
                                   va_list *Arguments) = nullptr;

HANDLE(WINAPI *temp_CreateMutexW)(LPSECURITY_ATTRIBUTES lpMutexAttributes,
                                  BOOL bInitialOwner,
                                  LPCWSTR lpName) = nullptr;

HANDLE(WINAPI *temp_CreateEventW)(LPSECURITY_ATTRIBUTES lpEventAttributes,
                                  BOOL bManualReset,
                                  BOOL bInitialState,
                                  LPCWSTR lpName) = nullptr;

BOOL(WINAPI *temp_SetEvent)(HANDLE hEvent) = nullptr;

DWORD(WINAPI *temp_WaitForSingleObject)(HANDLE hHandle,
                                        DWORD dwMilliseconds) = nullptr;

DWORD(WINAPI *temp_QueueUserAPC)(PAPCFUNC pfnAPC,
                                 HANDLE hThread,
                                 ULONG_PTR dwData) = nullptr;

HANDLE(WINAPI *temp_CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                  SIZE_T dwStackSize,
                                  LPTHREAD_START_ROUTINE lpStartAddress,
                                  __drv_aliasesMem LPVOID lpParameter,
                                  DWORD dwCreationFlags,
                                  LPDWORD lpThreadId) = nullptr;

HANDLE(WINAPI *temp_CreateWaitableTimerW)(LPSECURITY_ATTRIBUTES lpTimerAttributes,
    BOOL bManualReset,
    LPCWSTR lpTimerName) = nullptr;

BOOL(WINAPI *temp_SetWaitableTimer)(HANDLE hTimer,
                                    const LARGE_INTEGER *lpDueTime,
                                    LONG lPeriod,
                                    PTIMERAPCROUTINE pfnCompletionRoutine,
                                    LPVOID lpArgToCompletionRoutine,
                                    BOOL fResume) = nullptr;

BOOL(WINAPI *temp_CancelWaitableTimer)(HANDLE hTimer) = nullptr;

BOOL(WINAPI *temp_CreateTimerQueueTimer)(PHANDLE phNewTimer,
    HANDLE TimerQueue,
    WAITORTIMERCALLBACK Callback,
    PVOID DueTime,
    DWORD Period,
    DWORD Flags,
    ULONG Parameter) = nullptr;

DWORD(WINAPI *temp_SetFilePointer)(HANDLE hFile,
                                   LONG lDistanceToMove,
                                   PLONG lpDistanceToMoveHigh,
                                   DWORD dwMoveMethod) = nullptr;

BOOL(WINAPI *temp_ReadFile)(HANDLE hFile,
                            LPVOID lpBuffer,
                            DWORD nNumberOfBytesToRead,
                            LPDWORD lpNumberOfBytesRead,
                            LPOVERLAPPED lpOverlapped) = nullptr;

HANDLE(WINAPI *temp_CreateFileW)(LPCWSTR lpFileName,
                                 DWORD dwDesiredAccess,
                                 DWORD dwShareMode,
                                 LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                 DWORD dwCreationDisposition,
                                 DWORD dwFlagsAndAttributes,
                                 HANDLE hTemplateFile) = nullptr;

DWORD(WINAPI *temp_GetFullPathNameW)(LPCWSTR lpFileName,
                                     DWORD nBufferLength,
                                     LPWSTR lpBuffer,
                                     LPWSTR *lpFilePart) = nullptr;

DWORD(WINAPI *temp_GetFileAttributesW)(LPCWSTR lpFileName) = nullptr;

void (WINAPI *temp_GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime) = nullptr;

SIZE_T(WINAPI *temp_VirtualQuery)(LPCVOID lpAddress,
                                  PMEMORY_BASIC_INFORMATION lpBuffer,
                                  SIZE_T dwLength) = nullptr;

BOOL(WINAPI *temp_ReadProcessMemory)(HANDLE hProcess,
                                     LPCVOID lpBaseAddress,
                                     LPVOID lpBuffer,
                                     SIZE_T nSize,
                                     SIZE_T *lpNumberOfBytesRead) = nullptr;

/*DECLSPEC_ALLOCATOR*/
HLOCAL(WINAPI *temp_LocalAlloc)(UINT uFlags,
                                SIZE_T uBytes) = nullptr;

HLOCAL(WINAPI *temp_LocalFree)(_Frees_ptr_opt_ HLOCAL hMem) = nullptr;

BOOL(WINAPI *temp_GlobalMemoryStatusEx)(LPMEMORYSTATUSEX lpBuffer) = nullptr;

BOOL(WINAPI *temp_WriteProcessMemory)(HANDLE hProcess,
                                      LPVOID lpBaseAddress,
                                      LPCVOID lpBuffer,
                                      SIZE_T nSize,
                                      SIZE_T *lpNumberOfBytesWritten) = nullptr;

SIZE_T(WINAPI *temp_LocalSize)(HLOCAL hMem) = nullptr;

LPVOID(WINAPI *temp_HeapAlloc)(HANDLE hHeap,
                               DWORD dwFlags,
                               SIZE_T dwBytes) = nullptr;

HANDLE(WINAPI *temp_GetProcessHeap)() = nullptr;
BOOL(WINAPI *temp_HeapFree)(HANDLE hHeap,
                            DWORD dwFlags,
                            _Frees_ptr_opt_ LPVOID lpMem) = nullptr;

BOOL(WINAPI *temp_IsBadReadPtr)(const VOID *lp,
                                UINT_PTR ucb) = nullptr;
HANDLE(WINAPI *temp_GetCurrentProcess)() = nullptr;

BOOL(WINAPI *temp_GetThreadContext)(HANDLE hThread,
                                    LPCONTEXT lpContext) = nullptr;

void (WINAPI *temp_Sleep)(DWORD dwMilliseconds) = nullptr;

DWORD(WINAPI *temp_GetCurrentProcessId)() = nullptr;

HANDLE(WINAPI *temp_OpenProcess)(DWORD dwDesiredAccess,
                                 BOOL bInheritHandle,
                                 DWORD dwProcessId) = nullptr;

DWORD(WINAPI *temp_GetEnvironmentVariableW)(LPCWSTR lpName,
    LPWSTR lpBuffer,
    DWORD nSize) = nullptr;

HANDLE(WINAPI *temp_CreateToolhelp32Snapshot)(DWORD dwFlags,
    DWORD th32ProcessID) = nullptr;

BOOL(WINAPI *temp_Module32FirstW)(HANDLE hSnapshot,
                                  LPMODULEENTRY32W lpme) = nullptr;

BOOL(WINAPI *temp_Module32NextW)(HANDLE hSnapshot,
                                 LPMODULEENTRY32W lpme) = nullptr;

BOOL(WINAPI *temp_SwitchToThread)() = nullptr;

BOOL(WINAPI *temp_IsWow64Process)(HANDLE hProcess,
                                  PBOOL Wow64Process) = nullptr;

HANDLE(WINAPI *temp_CreateRemoteThread)(HANDLE hProcess,
                                        LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                        SIZE_T dwStackSize,
                                        LPTHREAD_START_ROUTINE lpStartAddress,
                                        LPVOID lpParameter,
                                        DWORD dwCreationFlags,
                                        LPDWORD lpThreadId) = nullptr;

BOOL(WINAPI *temp_Thread32First)(HANDLE hSnapshot,
                                 LPTHREADENTRY32 lpte) = nullptr;

HANDLE(WINAPI *temp_OpenThread)(DWORD dwDesiredAccess,
                                BOOL bInheritHandle,
                                DWORD dwThreadId) = nullptr;

BOOL(WINAPI *temp_Thread32Next)(HANDLE hSnapshot,
                                LPTHREADENTRY32 lpte) = nullptr;

BOOL(WINAPI *temp_Process32FirstW)(HANDLE hSnapshot,
                                   LPTHREADENTRY32 lpte) = nullptr;

BOOL(WINAPI *temp_Process32NextW)(HANDLE hSnapshot,
                                  LPTHREADENTRY32 lpte) = nullptr;

DWORD(WINAPI *temp_GetCurrentThreadId)() = nullptr;


BOOL(WINAPI *temp_TerminateProcess)(HANDLE hProcess,
                                    UINT uExitCode) = nullptr;


BOOL(WINAPI *temp_CloseHandle)(HANDLE hObject) = nullptr;

BOOL(WINAPI *temp_DuplicateHandle)(HANDLE hSourceProcessHandle,
                                   HANDLE hSourceHandle,
                                   HANDLE hTargetProcessHandle,
                                   LPHANDLE lpTargetHandle,
                                   DWORD dwDesiredAccess,
                                   BOOL bInheritHandle,
                                   DWORD dwOptions) = nullptr;


BOOL(WINAPI *temp_SetHandleInformation)(HANDLE hObject,
                                        DWORD dwMask,
                                        DWORD dwFlags) = nullptr;

BOOL(WINAPI *temp_DeviceIoControl)(HANDLE hDevice,
                                   DWORD dwIoControlCode,
                                   LPVOID lpInBuffer,
                                   DWORD nInBufferSize,
                                   LPVOID lpOutBuffer,
                                   DWORD nOutBufferSize,
                                   LPDWORD lpBytesReturned,
                                   LPOVERLAPPED lpOverlapped) = nullptr;

int (WINAPI *temp_lstrlenW)(LPCWSTR lpString) = nullptr;

int (WINAPI *temp_MultiByteToWideChar)(UINT CodePage,
                                       DWORD dwFlags,
                                       _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
                                       int cbMultiByte,
                                       LPWSTR lpWideCharStr,
                                       int cchWideChar) = nullptr;

HANDLE(WINAPI *temp_CreateTimerQueue)() = nullptr;

BOOL(WINAPI *temp_DeleteTimerQueueEx)(HANDLE TimerQueue,
                                      HANDLE CompletionEvent) = nullptr;

BOOL(WINAPI *temp_CheckRemoteDebuggerPresent)(HANDLE hProcess,
    PBOOL pbDebuggerPresent) = nullptr;

LONG(WINAPI *temp_UnhandledExceptionFilter)(_EXCEPTION_POINTERS *ExceptionInfo) = nullptr;

LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI *temp_SetUnhandledExceptionFilter)(
  LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) = nullptr;

ULONG(WINAPI *temp_RemoveVectoredExceptionHandler)(PVOID Handle) = nullptr;

int (*temp_WSAStartup)(WORD wVersionRequired,
                       LPWSADATA lpWSAData) = nullptr;

int (*temp_WSACleanup)() = nullptr;

int (*temp_closesocket)(IN SOCKET s) = nullptr;

int (*temp_recv)(SOCKET s,
                 char *buf,
                 int len,
                 int flags) = nullptr;

int (*temp_send)(SOCKET s,
                 const char *buf,
                 int len,
                 int flags) = nullptr;


SOCKET(*temp_socket)(int af, int type, int protocol) = nullptr;

int (*temp_connect)(SOCKET s,
                    const sockaddr *name,
                    int namelen) = nullptr;

ULONG(*temp_inet_addr)(_In_z_ const char FAR *cp) = nullptr;

u_short(*temp_htons)(u_short hostshort) = nullptr;

int (*temp_WSAGetLastError)() = nullptr;

void (*temp_RtlInitUnicodeString)(PUNICODE_STRING DestinationString,
                                  PCWSTR SourceString) = nullptr;
NTSTATUS(*temp_NtClose)(IN HANDLE Handle) = nullptr;
BOOL(*temp_FreeLibrary)(HMODULE hLibModule
                       ) = nullptr;

HMODULE(*temp_LoadLibraryAA)(LPCSTR lpLibFileName) = nullptr;

BOOL(*temp_QueryInformationJobObject)(HANDLE             hJob,
                                      JOBOBJECTINFOCLASS JobObjectInformationClass,
                                      LPVOID             lpJobObjectInformation,
                                      DWORD              cbJobObjectInformationLength,
                                      LPDWORD            lpReturnLength) = nullptr;

DWORD(*temp_K32GetProcessImageFileNameW)(HANDLE hProcess,
    LPWSTR  lpImageFileName,
    DWORD  nSize) = nullptr;
#pragma endregion Pointer Hash Functions

// -----------------
#pragma region Custom Functions
HANDLE hash_CreateFileA(
  __in LPCSTR file_name,
  __in DWORD access,
  __in DWORD share_mode,
  __in LPSECURITY_ATTRIBUTES security,
  __in DWORD creation_disposition,
  __in DWORD flags,
  __in HANDLE template_file)
{
  const auto _hash = t1ha0("CreateFileA", strlen("CreateFileA"), STRONG_SEED);
  temp_CreateFile = static_cast<HANDLE(WINAPI *)(LPCSTR,
                    DWORD,
                    DWORD,
                    LPSECURITY_ATTRIBUTES,
                    DWORD,
                    DWORD,
                    HANDLE)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                     strlen("CreateFileA"),
                                     STRONG_SEED));
  return temp_CreateFile(file_name, access, share_mode, security, creation_disposition, flags, template_file);
}

BOOL hash_VirtualProtect(LPVOID lpAddress,
                         SIZE_T dwSize,
                         DWORD flNewProtect,
                         PDWORD lpflOldProtect)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("VirtualProtect");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_VirtualProtect = static_cast<BOOL(WINAPI *)(LPVOID,
                        SIZE_T,
                        DWORD,
                        PDWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                         strlen(func),
                                         STRONG_SEED));
  return temp_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

LPVOID hash_VirtualAlloc(LPVOID lpAddress,
                         SIZE_T dwSize,
                         DWORD flAllocationType,
                         DWORD flProtect)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("VirtualAlloc");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_VirtualAlloc = static_cast<LPVOID(WINAPI *)(LPVOID,
                      SIZE_T,
                      DWORD,
                      DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                      strlen(func),
                                      STRONG_SEED));
  return temp_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL hash_VirtualFree(LPVOID lpAddress,
                      SIZE_T dwSize,
                      DWORD dwFreeType)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("VirtualFree");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_VirtualFree = static_cast<BOOL(WINAPI *)(LPVOID,
                     SIZE_T,
                     DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                     strlen(func),
                                     STRONG_SEED));
  return temp_VirtualFree(lpAddress, dwSize, dwFreeType);
}

LPVOID hash_VirtualAllocEx(HANDLE hProcess,
                           LPVOID lpAddress,
                           SIZE_T dwSize,
                           DWORD flAllocationType,
                           DWORD flProtect)
{
  const auto _hash = t1ha0("VirtualAllocEx", strlen("VirtualAllocEx"), STRONG_SEED);
  temp_VirtualAllocEx = static_cast<LPVOID(WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD)>(get_api(
                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("VirtualAllocEx"), STRONG_SEED));
  return temp_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL hash_VirtualFreeEx(HANDLE hProcess,
                        LPVOID lpAddress,
                        SIZE_T dwSize,
                        DWORD dwFreeType)
{
  const auto _hash = t1ha0("VirtualFreeEx", strlen("VirtualFreeEx"), STRONG_SEED);
  temp_VirtualFreeEx = static_cast<BOOL(WINAPI *)(HANDLE,
                       LPVOID,
                       SIZE_T,
                       DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                       strlen("VirtualFreeEx"),
                                       STRONG_SEED));
  return temp_VirtualFreeEx(hProcess,
                            lpAddress,
                            dwSize,
                            dwFreeType);
}

DWORD hash_QueryDosDeviceW(LPCWSTR lpDeviceName,
                           LPWSTR lpTargetPath,
                           DWORD ucchMax)
{
  const auto _hash = t1ha0("QueryDosDeviceW", strlen("QueryDosDeviceW"), STRONG_SEED);
  temp_QueryDosDeviceW = static_cast<DWORD(WINAPI *)(LPCWSTR,
                         LPWSTR,
                         DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                         strlen("QueryDosDeviceW"),
                                         STRONG_SEED));
  return temp_QueryDosDeviceW(lpDeviceName,
                              lpTargetPath,
                              ucchMax);
}

BOOL hash_GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName,
                              PULARGE_INTEGER lpFreeBytesAvailableToCaller,
                              PULARGE_INTEGER lpTotalNumberOfBytes,
                              PULARGE_INTEGER lpTotalNumberOfFreeBytes)
{
  const auto _hash = t1ha0("GetDiskFreeSpaceExW", strlen("GetDiskFreeSpaceExW"), STRONG_SEED);
  temp_GetDiskFreeSpaceExW = static_cast<BOOL(WINAPI *)(LPCWSTR,
                             PULARGE_INTEGER,
                             PULARGE_INTEGER,
                             PULARGE_INTEGER)>(get_api(
                                   _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetDiskFreeSpaceExW"), STRONG_SEED));
  return temp_GetDiskFreeSpaceExW(lpDirectoryName,
                                  lpFreeBytesAvailableToCaller,
                                  lpTotalNumberOfBytes,
                                  lpTotalNumberOfFreeBytes);
}

HMODULE hash_LoadLibraryW(LPCWSTR lpLibFileName)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("LoadLibraryW");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_LoadLibraryW = static_cast<HMODULE(WINAPI *)(LPCWSTR)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                      strlen(func),
                      STRONG_SEED));
  return temp_LoadLibraryW(lpLibFileName);
}

BOOL hash_GetModuleHandleExW(DWORD dwFlags,
                             LPCWSTR lpModuleName,
                             HMODULE *phModule)
{
  const auto _hash = t1ha0("GetModuleHandleExW", strlen("GetModuleHandleExW"), STRONG_SEED);
  temp_GetModuleHandleExW = static_cast<BOOL(WINAPI *)(DWORD,
                            LPCWSTR,
                            HMODULE *)>(get_api(
                                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetModuleHandleExW"), STRONG_SEED));
  return temp_GetModuleHandleExW(dwFlags,
                                 lpModuleName,
                                 phModule);
}

DWORD hash_GetModuleFileNameW(HMODULE hModule,
                              LPWSTR lpFilename,
                              DWORD nSize)
{
  const auto _hash = t1ha0("GetModuleFileNameW", strlen("GetModuleFileNameW"), STRONG_SEED);
  temp_GetModuleFileNameW = static_cast<DWORD(WINAPI *)(HMODULE,
                            LPWSTR,
                            DWORD)>(get_api(
                                      _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetModuleFileNameW"), STRONG_SEED));
  return temp_GetModuleFileNameW(hModule,
                                 lpFilename,
                                 nSize);
}

HMODULE hash_GetModuleHandleA(LPCSTR lpModuleName)
{
  const auto _hash = t1ha0("GetModuleHandleA", strlen("GetModuleHandleA"), STRONG_SEED);
  temp_GetModuleHandleA = static_cast<HMODULE(WINAPI *)(LPCSTR)>(get_api(
                            _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetModuleHandleA"), STRONG_SEED));
  return temp_GetModuleHandleA(lpModuleName);
}

HMODULE hash_GetModuleHandleW(LPCWSTR lpModuleName)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("GetModuleHandleW");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_GetModuleHandleW = static_cast<HMODULE(WINAPI *)(LPCWSTR)>(get_api(
                            _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen(func), STRONG_SEED));
  return temp_GetModuleHandleW(lpModuleName);
}

FARPROC hash_GetProcAddress(HMODULE hModule,
                            LPCSTR lpProcName)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("GetProcAddress");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_GetProcAddress = static_cast<FARPROC(WINAPI *)(HMODULE,
                        LPCSTR)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                         strlen(func),
                                         STRONG_SEED));
  return temp_GetProcAddress(hModule,
                             lpProcName);
}

HANDLE hash_GetStdHandle(_In_ DWORD nStdHandle)
{
  const auto _hash = t1ha0("GetStdHandle", strlen("GetStdHandle"), STRONG_SEED);
  temp_GetStdHandle = static_cast<HANDLE(WINAPI *)(_In_ DWORD)>(get_api(
                        _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetStdHandle"), STRONG_SEED));
  return temp_GetStdHandle(nStdHandle);
}

BOOL hash_GetConsoleScreenBufferInfo(_In_ HANDLE hConsoleOutput,
                                     _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo)
{
  const auto _hash = t1ha0("GetConsoleScreenBufferInfo", strlen("GetConsoleScreenBufferInfo"), STRONG_SEED);
  temp_GetConsoleScreenBufferInfo = static_cast<BOOL(WINAPI *)(_In_ HANDLE,
                                    _Out_ PCONSOLE_SCREEN_BUFFER_INFO)>(get_api(
                                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetConsoleScreenBufferInfo"), STRONG_SEED));
  return temp_GetConsoleScreenBufferInfo(hConsoleOutput,
                                         lpConsoleScreenBufferInfo);
}

BOOL hash_SetConsoleTextAttribute(_In_ HANDLE hConsoleOutput,
                                  _In_ WORD wAttributes)
{
  const auto _hash = t1ha0("SetConsoleTextAttribute", strlen("SetConsoleTextAttribute"), STRONG_SEED);
  temp_SetConsoleTextAttribute = static_cast<BOOL(WINAPI *)(_In_ HANDLE,
                                 _In_ WORD)>(get_api(
                                       _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("SetConsoleTextAttribute"), STRONG_SEED));
  return temp_SetConsoleTextAttribute(hConsoleOutput,
                                      wAttributes);
}

DWORD hash_GetTickCount()
{
  const auto _hash = t1ha0("GetTickCount", strlen("GetTickCount"), STRONG_SEED);
  temp_GetTickCount = static_cast<DWORD(WINAPI *)()>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                      strlen("GetTickCount"),
                      STRONG_SEED));
  return temp_GetTickCount();
}

BOOL hash_VerifyVersionInfoW(LPOSVERSIONINFOEXA lpVersionInformation,
                             DWORD dwTypeMask,
                             DWORDLONG dwlConditionMask)
{
  const auto _hash = t1ha0("VerifyVersionInfoW", strlen("VerifyVersionInfoW"), STRONG_SEED);
  temp_VerifyVersionInfoW = static_cast<BOOL(WINAPI *)(LPOSVERSIONINFOEXA,
                            DWORD,
                            DWORDLONG)>(get_api(
                                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("VerifyVersionInfoW"), STRONG_SEED));
  return temp_VerifyVersionInfoW(lpVersionInformation,
                                 dwTypeMask,
                                 dwlConditionMask);
}

UINT hash_GetSystemWindowsDirectoryW(LPWSTR lpBuffer,
                                     UINT uSize)
{
  const auto _hash = t1ha0("GetSystemWindowsDirectoryW", strlen("GetSystemWindowsDirectoryW"), STRONG_SEED);
  temp_GetSystemWindowsDirectoryW = static_cast<UINT(WINAPI *)(LPWSTR,
                                    UINT)>(get_api(
                                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetSystemWindowsDirectoryW"), STRONG_SEED));
  return temp_GetSystemWindowsDirectoryW(lpBuffer,
                                         uSize);
}

UINT hash_GetWindowsDirectoryW(LPWSTR lpBuffer,
                               UINT uSize)
{
  const auto _hash = t1ha0("GetWindowsDirectoryW", strlen("GetWindowsDirectoryW"), STRONG_SEED);
  temp_GetWindowsDirectoryW = static_cast<UINT(WINAPI *)(LPWSTR,
                              UINT)>(get_api(
                                       _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetWindowsDirectoryW"), STRONG_SEED));
  return temp_GetWindowsDirectoryW(lpBuffer,
                                   uSize);
}

UINT hash_GetSystemDirectoryW(LPWSTR lpBuffer,
                              UINT uSize)
{
  const auto _hash = t1ha0("GetSystemDirectoryW", strlen("GetSystemDirectoryW"), STRONG_SEED);
  temp_GetSystemDirectoryW = static_cast<UINT(WINAPI *)(LPWSTR,
                             UINT)>(get_api(
                                      _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetSystemDirectoryW"), STRONG_SEED));
  return temp_GetSystemDirectoryW(lpBuffer,
                                  uSize);
}

UINT hash_GetSystemDirectoryA(LPSTR lpBuffer,
                              UINT uSize)
{
  const auto _hash = t1ha0("GetSystemDirectoryA", strlen("GetSystemDirectoryA"), STRONG_SEED);
  temp_GetSystemDirectoryA = static_cast<UINT(WINAPI *)(LPSTR,
                             UINT)>(get_api(
                                      _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetSystemDirectoryA"), STRONG_SEED));
  return temp_GetSystemDirectoryA(lpBuffer,
                                  uSize);
}

void hash_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
{
  const auto _hash = t1ha0("GetSystemInfo", strlen("GetSystemInfo"), STRONG_SEED);
  temp_GetSystemInfo = static_cast<void(WINAPI *)(LPSYSTEM_INFO)>(get_api(
                         _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetSystemInfo"), STRONG_SEED));
  return temp_GetSystemInfo(lpSystemInfo);
}

DWORD hash_ExpandEnvironmentStringsW(LPCWSTR lpSrc,
                                     LPWSTR lpDst,
                                     DWORD nSize)
{
  const auto _hash = t1ha0("ExpandEnvironmentStringsW", strlen("ExpandEnvironmentStringsW"), STRONG_SEED);
  temp_ExpandEnvironmentStringsW = static_cast<DWORD(WINAPI *)(LPCWSTR,
                                   LPWSTR,
                                   DWORD)>(get_api(
                                         _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("ExpandEnvironmentStringsW"), STRONG_SEED));
  return temp_ExpandEnvironmentStringsW(lpSrc,
                                        lpDst,
                                        nSize);
}

BOOL hash_QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
{
  const auto _hash = t1ha0("QueryPerformanceCounter", strlen("QueryPerformanceCounter"), STRONG_SEED);
  temp_QueryPerformanceCounter = static_cast<BOOL(WINAPI *)(LARGE_INTEGER *)>(get_api(
                                   _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("QueryPerformanceCounter"), STRONG_SEED));
  return temp_QueryPerformanceCounter(lpPerformanceCount);
}

BOOL hash_IsProcessorFeaturePresent(DWORD ProcessorFeature)
{
  const auto _hash = t1ha0("IsProcessorFeaturePresent", strlen("IsProcessorFeaturePresent"), STRONG_SEED);
  temp_IsProcessorFeaturePresent = static_cast<BOOL(WINAPI *)(DWORD)>(get_api(
                                     _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("IsProcessorFeaturePresent"), STRONG_SEED)
                                                                     );
  return temp_IsProcessorFeaturePresent(ProcessorFeature);
}

//TODO: needed fix
PVOID hash_AddVectoredExceptionHandler(ULONG First,
                                       PVECTORED_EXCEPTION_HANDLER Handler)
{
  const auto _hash = t1ha0("AddVectoredExceptionHandler", strlen("AddVectoredExceptionHandler"), STRONG_SEED);
  temp_AddVectoredExceptionHandler = static_cast<PVOID(WINAPI *)(ULONG, PVECTORED_EXCEPTION_HANDLER)>(get_api(
                                       _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("AddVectoredExceptionHandler"), STRONG_SEED));
  return temp_AddVectoredExceptionHandler(First, Handler);
}

void hash_SetLastError(DWORD dwErrCode)
{
  const auto _hash = t1ha0("SetLastError", strlen("SetLastError"), STRONG_SEED);
  temp_SetLastError = static_cast<void(WINAPI *)(DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                      strlen("SetLastError"),
                      STRONG_SEED));
  return temp_SetLastError(dwErrCode);
}

_Post_equals_last_error_ DWORD hash_GetLastError()
{
  const auto _hash = t1ha0("GetLastError", strlen("GetLastError"), STRONG_SEED);
  temp_GetLastError = static_cast<DWORD(WINAPI *)()>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                      strlen("GetLastError"),
                      STRONG_SEED));
  return temp_GetLastError();
}

void hash_OutputDebugStringW(LPCWSTR lpOutputString)
{
  const auto _hash = t1ha0("OutputDebugStringW", strlen("OutputDebugStringW"), STRONG_SEED);
  temp_OutputDebugStringW = static_cast<void(WINAPI *)(LPCWSTR)>(get_api(
                              _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("OutputDebugStringW"), STRONG_SEED));
  return temp_OutputDebugStringW(lpOutputString);
}

DWORD hash_FormatMessageW(DWORD dwFlags,
                          LPCVOID lpSource,
                          DWORD dwMessageId,
                          DWORD dwLanguageId,
                          LPWSTR lpBuffer,
                          DWORD nSize,
                          va_list *Arguments)
{
  const auto _hash = t1ha0("FormatMessageW", strlen("FormatMessageW"), STRONG_SEED);
  temp_FormatMessageW = static_cast<DWORD(WINAPI *)(DWORD,
                        LPCVOID,
                        DWORD,
                        DWORD,
                        LPWSTR,
                        DWORD,
                        va_list *)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                    strlen("FormatMessageW"),
                                    STRONG_SEED));
  return temp_FormatMessageW(dwFlags,
                             lpSource,
                             dwMessageId,
                             dwLanguageId,
                             lpBuffer,
                             nSize,
                             Arguments);
}

HANDLE hash_CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes,
                         BOOL bInitialOwner,
                         LPCWSTR lpName)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("CreateMutexW");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_CreateMutexW = static_cast<HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES,
                      BOOL,
                      LPCWSTR)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                        strlen(func),
                                        STRONG_SEED));
  return temp_CreateMutexW(lpMutexAttributes,
                           bInitialOwner,
                           lpName);
}

HANDLE hash_CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes,
                         BOOL bManualReset,
                         BOOL bInitialState,
                         LPCWSTR lpName)
{
  const auto _hash = t1ha0("CreateEventW", strlen("CreateEventW"), STRONG_SEED);
  temp_CreateEventW = static_cast<HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES,
                      BOOL,
                      BOOL,
                      LPCWSTR)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                        strlen("CreateEventW"),
                                        STRONG_SEED));
  return temp_CreateEventW(lpEventAttributes,
                           bManualReset,
                           bInitialState,
                           lpName);
}

BOOL hash_SetEvent(HANDLE hEvent)
{
  const auto _hash = t1ha0("SetEvent", strlen("SetEvent"), STRONG_SEED);
  temp_SetEvent = static_cast<BOOL(WINAPI *)(HANDLE)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                  strlen("SetEvent"), STRONG_SEED));
  return temp_SetEvent(hEvent);
}

DWORD hash_WaitForSingleObject(HANDLE hHandle,
                               DWORD dwMilliseconds)
{
  const auto _hash = t1ha0("WaitForSingleObject", strlen("WaitForSingleObject"), STRONG_SEED);
  temp_WaitForSingleObject = static_cast<DWORD(WINAPI *)(HANDLE,
                             DWORD)>(get_api(
                                       _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("WaitForSingleObject"), STRONG_SEED));
  return temp_WaitForSingleObject(hHandle,
                                  dwMilliseconds);
}

DWORD hash_QueueUserAPC(PAPCFUNC pfnAPC,
                        HANDLE hThread,
                        ULONG_PTR dwData)
{
  const auto _hash = t1ha0("QueueUserAPC", strlen("QueueUserAPC"), STRONG_SEED);
  temp_QueueUserAPC = static_cast<DWORD(WINAPI *)(PAPCFUNC,
                      HANDLE,
                      ULONG_PTR)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                          strlen("QueueUserAPC"),
                                          STRONG_SEED));
  return temp_QueueUserAPC(pfnAPC,
                           hThread,
                           dwData);
}

HANDLE hash_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                         SIZE_T dwStackSize,
                         LPTHREAD_START_ROUTINE lpStartAddress,
                         __drv_aliasesMem LPVOID lpParameter,
                         DWORD dwCreationFlags,
                         LPDWORD lpThreadId)
{
  const auto _hash = t1ha0("CreateEventW", strlen("CreateEventW"), STRONG_SEED);
  temp_CreateThread = static_cast<HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES,
                      SIZE_T,
                      LPTHREAD_START_ROUTINE,
                      __drv_aliasesMem LPVOID,
                      DWORD,
                      LPDWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                        strlen("CreateEventW"),
                                        STRONG_SEED));
  return temp_CreateThread(lpThreadAttributes,
                           dwStackSize,
                           lpStartAddress,
                           lpParameter,
                           dwCreationFlags,
                           lpThreadId);
}

HANDLE hash_CreateWaitableTimerW(LPSECURITY_ATTRIBUTES lpTimerAttributes,
                                 BOOL bManualReset,
                                 LPCWSTR lpTimerName)
{
  const auto _hash = t1ha0("CreateWaitableTimerW", strlen("CreateWaitableTimerW"), STRONG_SEED);
  temp_CreateWaitableTimerW = static_cast<HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES,
                              BOOL,
                              LPCWSTR)>(get_api(
                                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("CreateWaitableTimerW"), STRONG_SEED));
  return temp_CreateWaitableTimerW(lpTimerAttributes,
                                   bManualReset,
                                   lpTimerName);
}

BOOL hash_SetWaitableTimer(HANDLE hTimer,
                           const LARGE_INTEGER *lpDueTime,
                           LONG lPeriod,
                           PTIMERAPCROUTINE pfnCompletionRoutine,
                           LPVOID lpArgToCompletionRoutine,
                           BOOL fResume)
{
  const auto _hash = t1ha0("SetWaitableTimer", strlen("SetWaitableTimer"), STRONG_SEED);
  temp_SetWaitableTimer = static_cast<BOOL(WINAPI *)(HANDLE,
                          const LARGE_INTEGER *,
                          LONG,
                          PTIMERAPCROUTINE,
                          LPVOID,
                          BOOL)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                         strlen("SetWaitableTimer"),
                                         STRONG_SEED));
  return temp_SetWaitableTimer(hTimer,
                               lpDueTime,
                               lPeriod,
                               pfnCompletionRoutine,
                               lpArgToCompletionRoutine,
                               fResume);
}

BOOL hash_CancelWaitableTimer(HANDLE hTimer)
{
  const auto _hash = t1ha0("CancelWaitableTimer", strlen("CancelWaitableTimer"), STRONG_SEED);
  temp_CancelWaitableTimer = static_cast<BOOL(WINAPI *)(HANDLE)>(get_api(
                               _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("CancelWaitableTimer"), STRONG_SEED));
  return temp_CancelWaitableTimer(hTimer);
}

BOOL hash_CreateTimerQueueTimer(PHANDLE phNewTimer,
                                HANDLE TimerQueue,
                                WAITORTIMERCALLBACK Callback,
                                PVOID DueTime,
                                DWORD Period,
                                DWORD Flags,
                                ULONG Parameter)
{
  const auto _hash = t1ha0("CreateTimerQueueTimer", strlen("CreateTimerQueueTimer"), STRONG_SEED);
  temp_CreateTimerQueueTimer = static_cast<BOOL(WINAPI *)(PHANDLE,
                               HANDLE,
                               WAITORTIMERCALLBACK,
                               PVOID,
                               DWORD,
                               DWORD,
                               ULONG)>(get_api(
                                         _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("CreateTimerQueueTimer"), STRONG_SEED));
  return temp_CreateTimerQueueTimer(phNewTimer,
                                    TimerQueue,
                                    Callback,
                                    DueTime,
                                    Period,
                                    Flags,
                                    Parameter);
}

DWORD hash_SetFilePointer(HANDLE hFile,
                          LONG lDistanceToMove,
                          PLONG lpDistanceToMoveHigh,
                          DWORD dwMoveMethod)
{
  const auto _hash = t1ha0("SetFilePointer", strlen("SetFilePointer"), STRONG_SEED);
  temp_SetFilePointer = static_cast<DWORD(WINAPI *)(HANDLE,
                        LONG,
                        PLONG,
                        DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                        strlen("SetFilePointer"),
                                        STRONG_SEED));
  return temp_SetFilePointer(hFile,
                             lDistanceToMove,
                             lpDistanceToMoveHigh,
                             dwMoveMethod);
}

BOOL hash_ReadFile(HANDLE hFile,
                   LPVOID lpBuffer,
                   DWORD nNumberOfBytesToRead,
                   LPDWORD lpNumberOfBytesRead,
                   LPOVERLAPPED lpOverlapped)
{
  const auto _hash = t1ha0("ReadFile", strlen("ReadFile"), STRONG_SEED);
  temp_ReadFile = static_cast<BOOL(WINAPI *)(HANDLE,
                  LPVOID,
                  DWORD,
                  LPDWORD,
                  LPOVERLAPPED)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                         strlen("ReadFile"),
                                         STRONG_SEED));
  return temp_ReadFile(hFile,
                       lpBuffer,
                       nNumberOfBytesToRead,
                       lpNumberOfBytesRead,
                       lpOverlapped);
}

HANDLE hash_CreateFileW(LPCWSTR lpFileName,
                        DWORD dwDesiredAccess,
                        DWORD dwShareMode,
                        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                        DWORD dwCreationDisposition,
                        DWORD dwFlagsAndAttributes,
                        HANDLE hTemplateFile)
{
  const auto _hash = t1ha0("CreateFileW", strlen("CreateFileW"), STRONG_SEED);
  temp_CreateFileW = static_cast<HANDLE(WINAPI *)(LPCWSTR,
                     DWORD,
                     DWORD,
                     LPSECURITY_ATTRIBUTES,
                     DWORD,
                     DWORD,
                     HANDLE)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                      strlen("CreateFileW"),
                                      STRONG_SEED));
  return temp_CreateFileW(lpFileName,
                          dwDesiredAccess,
                          dwShareMode,
                          lpSecurityAttributes,
                          dwCreationDisposition,
                          dwFlagsAndAttributes,
                          hTemplateFile);
}

DWORD hash_GetFullPathNameW(LPCWSTR lpFileName,
                            DWORD nBufferLength,
                            LPWSTR lpBuffer,
                            LPWSTR *lpFilePart)
{
  const auto _hash = t1ha0("GetFullPathNameW", strlen("GetFullPathNameW"), STRONG_SEED);
  temp_GetFullPathNameW = static_cast<DWORD(WINAPI *)(LPCWSTR,
                          DWORD,
                          LPWSTR,
                          LPWSTR *)>(get_api(
                                       _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetFullPathNameW"), STRONG_SEED));
  return temp_GetFullPathNameW(lpFileName,
                               nBufferLength,
                               lpBuffer,
                               lpFilePart);
}

DWORD hash_GetFileAttributesW(LPCWSTR lpFileName)
{
  const auto _hash = t1ha0("GetFileAttributesW", strlen("GetFileAttributesW"), STRONG_SEED);
  temp_GetFileAttributesW = static_cast<DWORD(WINAPI *)(LPCWSTR)>(get_api(
                              _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetFileAttributesW"), STRONG_SEED));
  return temp_GetFileAttributesW(lpFileName);
}


void hash_GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
  const auto _hash = t1ha0("GetSystemTimeAsFileTime", strlen("GetSystemTimeAsFileTime"), STRONG_SEED);
  temp_GetSystemTimeAsFileTime = static_cast<void(WINAPI *)(LPFILETIME)>(get_api(
                                   _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetSystemTimeAsFileTime"), STRONG_SEED));
  return temp_GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}

//SIZE_T hash_VirtualQuery(LPCVOID lpAddress,
//                         PMEMORY_BASIC_INFORMATION lpBuffer,
//                         SIZE_T dwLength)
//{
//  const auto _hash = t1ha0("VirtualQuery", strlen("VirtualQuery"), STRONG_SEED);
//  temp_VirtualQuery = static_cast<SIZE_T(WINAPI *)(LPCVOID,
//                      PMEMORY_BASIC_INFORMATION,
//                      SIZE_T)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("VirtualQuery"),
//                                       STRONG_SEED));
//  return temp_VirtualQuery(lpAddress,
//                           lpBuffer,
//                           dwLength);
//}

BOOL hash_ReadProcessQMemory(HANDLE hProcess,
                             LPCVOID lpBaseAddress,
                             LPVOID lpBuffer,
                             SIZE_T nSize,
                             SIZE_T *lpNumberOfBytesRead)
{
  const auto _hash = t1ha0("ReadProcessMemory", strlen("ReadProcessMemory"), STRONG_SEED);
  temp_ReadProcessMemory = static_cast<BOOL(WINAPI *)(HANDLE,
                           LPCVOID,
                           LPVOID,
                           SIZE_T,
                           SIZE_T *)>(get_api(
                                        _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("ReadProcessMemory"), STRONG_SEED));
  return temp_ReadProcessMemory(hProcess,
                                lpBaseAddress,
                                lpBuffer,
                                nSize,
                                lpNumberOfBytesRead);
}

/*DECLSPEC_ALLOCATOR*/
HLOCAL hash_LocalAlloc(UINT uFlags,
                       SIZE_T uBytes)
{
  const auto _hash = t1ha0("LocalAlloc", strlen("LocalAlloc"), STRONG_SEED);
  temp_LocalAlloc = static_cast<HLOCAL(WINAPI *)(UINT,
                    SIZE_T)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                     strlen("LocalAlloc"),
                                     STRONG_SEED));
  return temp_LocalAlloc(uFlags,
                         uBytes);
}

HLOCAL hash_LocalFree(_Frees_ptr_opt_ HLOCAL hMem)
{
  const auto _hash = t1ha0("LocalFree", strlen("LocalFree"), STRONG_SEED);
  temp_LocalFree = static_cast<HLOCAL(WINAPI *)(_Frees_ptr_opt_ HLOCAL)>(get_api(
                     _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("LocalFree"), STRONG_SEED));
  return temp_LocalFree(hMem);
}

BOOL hash_GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer)
{
  const auto _hash = t1ha0("GlobalMemoryStatusEx", strlen("GlobalMemoryStatusEx"), STRONG_SEED);
  temp_GlobalMemoryStatusEx = static_cast<BOOL(WINAPI *)(LPMEMORYSTATUSEX)>(get_api(
                                _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GlobalMemoryStatusEx"), STRONG_SEED));
  return temp_GlobalMemoryStatusEx(lpBuffer);
}

BOOL hash_WriteProcessMemory(HANDLE hProcess,
                             LPVOID lpBaseAddress,
                             LPCVOID lpBuffer,
                             SIZE_T nSize,
                             SIZE_T *lpNumberOfBytesWritten)
{
  const auto _hash = t1ha0("WriteProcessMemory", strlen("WriteProcessMemory"), STRONG_SEED);
  temp_WriteProcessMemory = static_cast<BOOL(WINAPI *)(HANDLE,
                            LPVOID,
                            LPCVOID,
                            SIZE_T,
                            SIZE_T *)>(get_api(
                                         _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("WriteProcessMemory"), STRONG_SEED));
  return temp_WriteProcessMemory(hProcess,
                                 lpBaseAddress,
                                 lpBuffer,
                                 nSize,
                                 lpNumberOfBytesWritten);
}

SIZE_T hash_LocalSize(HLOCAL hMem)
{
  const auto _hash = t1ha0("LocalSize", strlen("LocalSize"), STRONG_SEED);
  temp_LocalSize = static_cast<SIZE_T(WINAPI *)(HLOCAL)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                   strlen("LocalSize"),
                   STRONG_SEED));
  return temp_LocalSize(hMem);
}


LPVOID hash_HeapAlloc(HANDLE hHeap,
                      DWORD dwFlags,
                      SIZE_T dwBytes)
{
  const auto _hash = t1ha0("HeapAlloc", strlen("HeapAlloc"), STRONG_SEED);
  temp_HeapAlloc = static_cast<LPVOID(WINAPI *)(HANDLE,
                   DWORD,
                   SIZE_T)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                    strlen("HeapAlloc"),
                                    STRONG_SEED));
  return temp_HeapAlloc(hHeap,
                        dwFlags,
                        dwBytes);
}

HANDLE hash_GetProcessHeap()
{
  const auto _hash = t1ha0("GetProcessHeap", strlen("GetProcessHeap"), STRONG_SEED);
  temp_GetProcessHeap = static_cast<HANDLE(WINAPI *)()>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                        strlen("GetProcessHeap"),
                        STRONG_SEED));
  return temp_GetProcessHeap();
}

BOOL hash_HeapFree(HANDLE hHeap,
                   DWORD dwFlags,
                   _Frees_ptr_opt_ LPVOID lpMem)
{
  const auto _hash = t1ha0("HeapFree", strlen("HeapFree"), STRONG_SEED);
  temp_HeapFree = static_cast<BOOL(WINAPI *)(HANDLE,
                  DWORD,
                  _Frees_ptr_opt_ LPVOID)>(get_api(
                        _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("HeapFree"), STRONG_SEED)
                                          );
  return temp_HeapFree(hHeap,
                       dwFlags,
                       lpMem);
}

BOOL hash_IsBadReadPtr(const VOID *lp,
                       UINT_PTR ucb)
{
  const auto _hash = t1ha0("IsBadReadPtr", strlen("IsBadReadPtr"), STRONG_SEED);
  temp_IsBadReadPtr = static_cast<BOOL(WINAPI *)(const VOID *,
                      UINT_PTR)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                         strlen("IsBadReadPtr"),
                                         STRONG_SEED));
  return temp_IsBadReadPtr(lp,
                           ucb);
}

HANDLE hash_GetCurrentProcess()
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("GetCurrentProcess");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_GetCurrentProcess = static_cast<HANDLE(WINAPI *)()>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                           strlen(func),
                           STRONG_SEED));
  return temp_GetCurrentProcess();
}

BOOL hash_GetThreadContext(HANDLE hThread,
                           LPCONTEXT lpContext)
{
  const auto _hash = t1ha0("GetThreadContext", strlen("GetThreadContext"), STRONG_SEED);
  temp_GetThreadContext = static_cast<BOOL(WINAPI *)(HANDLE,
                          LPCONTEXT)>(get_api(
                                        _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetThreadContext"), STRONG_SEED));
  return temp_GetThreadContext(hThread,
                               lpContext);
}

void hash_Sleep(DWORD dwMilliseconds)
{
  const auto _hash = t1ha0("Sleep", strlen("Sleep"), STRONG_SEED);
  temp_Sleep = static_cast<void(WINAPI *)(DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
               strlen("Sleep"), STRONG_SEED));
  return temp_Sleep(dwMilliseconds);
}

DWORD hash_GetCurrentProcessId()
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("GetCurrentProcessId");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_GetCurrentProcessId = static_cast<DWORD(WINAPI *)()>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                             strlen(func), STRONG_SEED));
  return temp_GetCurrentProcessId();
}

HANDLE hash_OpenProcess(DWORD dwDesiredAccess,
                        BOOL bInheritHandle,
                        DWORD dwProcessId)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("OpenProcess");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_OpenProcess = static_cast<HANDLE(WINAPI *)(DWORD,
                     BOOL,
                     DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                     strlen(func),
                                     STRONG_SEED));
  return temp_OpenProcess(dwDesiredAccess,
                          bInheritHandle,
                          dwProcessId);
}

DWORD hash_GetEnvironmentVariableW(LPCWSTR lpName,
                                   LPWSTR lpBuffer,
                                   DWORD nSize)
{
  const auto _hash = t1ha0("GetEnvironmentVariableW", strlen("GetEnvironmentVariableW"), STRONG_SEED);
  temp_GetEnvironmentVariableW = static_cast<DWORD(WINAPI *)(LPCWSTR,
                                 LPWSTR,
                                 DWORD)>(get_api(
                                     _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("GetEnvironmentVariableW"), STRONG_SEED));
  return temp_GetEnvironmentVariableW(lpName,
                                      lpBuffer,
                                      nSize);
}

HANDLE hash_CreateToolhelp32Snapshot(DWORD dwFlags,
                                     DWORD th32ProcessID)
{
  const auto _hash = t1ha0("CreateToolhelp32Snapshot", strlen("CreateToolhelp32Snapshot"), STRONG_SEED);
  temp_CreateToolhelp32Snapshot = static_cast<HANDLE(WINAPI *)(DWORD,
                                  DWORD)>(get_api(
                                      _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("CreateToolhelp32Snapshot"), STRONG_SEED));
  return temp_CreateToolhelp32Snapshot(dwFlags,
                                       th32ProcessID);
}

BOOL hash_Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
{
  const auto _hash = t1ha0("Module32FirstW", strlen("Module32FirstW"), STRONG_SEED);
  temp_Module32FirstW = static_cast<BOOL(WINAPI *)(HANDLE, LPMODULEENTRY32W)>(get_api(
                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("Module32FirstW"), STRONG_SEED));
  return temp_Module32FirstW(hSnapshot, lpme);
}

BOOL hash_Module32NextW(HANDLE hSnapshot,
                        LPMODULEENTRY32W lpme)
{
  const auto _hash = t1ha0("Module32NextW", strlen("Module32NextW"), STRONG_SEED);
  temp_Module32NextW = static_cast<BOOL(WINAPI *)(HANDLE,
                       LPMODULEENTRY32W)>(get_api(
                           _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("Module32NextW"), STRONG_SEED));
  return temp_Module32NextW(hSnapshot,
                            lpme);
}

BOOL hash_SwitchToThread()
{
  const auto _hash = t1ha0("SwitchToThread", strlen("SwitchToThread"), STRONG_SEED);
  temp_SwitchToThread = static_cast<BOOL(WINAPI *)()>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                        strlen("SwitchToThread"),
                        STRONG_SEED));
  return temp_SwitchToThread();
}

BOOL hash_IsWow64Process(HANDLE hProcess,
                         PBOOL Wow64Process)
{
  const auto _hash = t1ha0("IsWow64Process", strlen("IsWow64Process"), STRONG_SEED);
  temp_IsWow64Process = static_cast<BOOL(WINAPI *)(HANDLE,
                        PBOOL)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                        strlen("IsWow64Process"),
                                        STRONG_SEED));
  return temp_IsWow64Process(hProcess,
                             Wow64Process);
}

HANDLE hash_CreateRemoteThread(HANDLE hProcess,
                               LPSECURITY_ATTRIBUTES lpThreadAttributes,
                               SIZE_T dwStackSize,
                               LPTHREAD_START_ROUTINE lpStartAddress,
                               LPVOID lpParameter,
                               DWORD dwCreationFlags,
                               LPDWORD lpThreadId)
{
  const auto _hash = t1ha0("CreateRemoteThread", strlen("CreateRemoteThread"), STRONG_SEED);
  temp_CreateRemoteThread = static_cast<HANDLE(WINAPI *)(HANDLE,
                            LPSECURITY_ATTRIBUTES,
                            SIZE_T,
                            LPTHREAD_START_ROUTINE,
                            LPVOID,
                            DWORD,
                            LPDWORD)>(get_api(
                                        _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("CreateRemoteThread"), STRONG_SEED));
  return temp_CreateRemoteThread(hProcess,
                                 lpThreadAttributes,
                                 dwStackSize,
                                 lpStartAddress,
                                 lpParameter,
                                 dwCreationFlags,
                                 lpThreadId);
}

BOOL hash_Thread32First(HANDLE hSnapshot,
                        LPTHREADENTRY32 lpte)
{
  const auto _hash = t1ha0("Thread32First", strlen("Thread32First"), STRONG_SEED);
  temp_Thread32First = static_cast<BOOL(WINAPI *)(HANDLE,
                       LPTHREADENTRY32)>(get_api(
                           _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("Thread32First"), STRONG_SEED));
  return temp_Thread32First(hSnapshot,
                            lpte);
}

HANDLE hash_OpenThread(DWORD dwDesiredAccess,
                       BOOL bInheritHandle,
                       DWORD dwThreadId)
{
  const auto _hash = t1ha0("OpenThread", strlen("OpenThread"), STRONG_SEED);
  temp_OpenThread = static_cast<HANDLE(WINAPI *)(DWORD,
                    BOOL,
                    DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                    strlen("OpenThread"),
                                    STRONG_SEED));
  return temp_OpenThread(dwDesiredAccess,
                         bInheritHandle,
                         dwThreadId);
}

BOOL hash_Thread32Next(HANDLE hSnapshot,
                       LPTHREADENTRY32 lpte)
{
  const auto _hash = t1ha0("Thread32Next", strlen("Thread32Next"), STRONG_SEED);
  temp_Thread32Next = static_cast<BOOL(WINAPI *)(HANDLE,
                      LPTHREADENTRY32)>(get_api(
                                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("Thread32Next"), STRONG_SEED));
  return temp_Thread32Next(hSnapshot,
                           lpte);
}

BOOL hash_Process32FirstW(HANDLE hSnapshot,
                          LPTHREADENTRY32 lpte)
{
  const auto _hash = t1ha0("Process32FirstW", strlen("Process32FirstW"), STRONG_SEED);
  temp_Process32FirstW = static_cast<BOOL(WINAPI *)(HANDLE,
                         LPTHREADENTRY32)>(get_api(
                               _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("Process32FirstW"), STRONG_SEED)
                                          );
  return temp_Process32FirstW(hSnapshot,
                              lpte);
}

BOOL hash_Process32NextW(HANDLE hSnapshot,
                         LPTHREADENTRY32 lpte)
{
  const auto _hash = t1ha0("Process32NextW", strlen("Process32NextW"), STRONG_SEED);
  temp_Process32NextW = static_cast<BOOL(WINAPI *)(HANDLE,
                        LPTHREADENTRY32)>(get_api(
                            _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("Process32NextW"), STRONG_SEED));
  return temp_Process32NextW(hSnapshot,
                             lpte);
}

DWORD hash_GetCurrentThreadId()
{
  const auto _hash = t1ha0("GetCurrentThreadId", strlen("GetCurrentThreadId"), STRONG_SEED);
  temp_GetCurrentThreadId = static_cast<DWORD(WINAPI *)()>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                            strlen("GetCurrentThreadId"),
                            STRONG_SEED));
  return temp_GetCurrentThreadId();
}

BOOL hash_TerminateProcess(HANDLE hProcess,
                           UINT uExitCode)
{
  const auto _hash = t1ha0("TerminateProcess", strlen("TerminateProcess"), STRONG_SEED);
  temp_TerminateProcess = static_cast<BOOL(WINAPI *)(HANDLE,
                          UINT)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                         strlen("TerminateProcess"),
                                         STRONG_SEED));
  return temp_TerminateProcess(hProcess,
                               uExitCode);
}

BOOL hash_CloseHandle(HANDLE hObject)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("CloseHandle");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_CloseHandle = static_cast<BOOL(WINAPI *)(HANDLE)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                     strlen(func),
                     STRONG_SEED));
  return temp_CloseHandle(hObject);
}

BOOL hash_DuplicateHandle(HANDLE hSourceProcessHandle,
                          HANDLE hSourceHandle,
                          HANDLE hTargetProcessHandle,
                          LPHANDLE lpTargetHandle,
                          DWORD dwDesiredAccess,
                          BOOL bInheritHandle,
                          DWORD dwOptions)
{
  const auto _hash = t1ha0("DuplicateHandle", strlen("DuplicateHandle"), STRONG_SEED);
  temp_DuplicateHandle = static_cast<BOOL(WINAPI *)(HANDLE,
                         HANDLE,
                         HANDLE,
                         LPHANDLE,
                         DWORD,
                         BOOL,
                         DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                         strlen("DuplicateHandle"),
                                         STRONG_SEED));
  return temp_DuplicateHandle(hSourceProcessHandle,
                              hSourceHandle,
                              hTargetProcessHandle,
                              lpTargetHandle,
                              dwDesiredAccess,
                              bInheritHandle,
                              dwOptions);
}

BOOL hash_SetHandleInformation(HANDLE hObject,
                               DWORD dwMask,
                               DWORD dwFlags)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("SetHandleInformation");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_SetHandleInformation = static_cast<BOOL(WINAPI *)(HANDLE,
                              DWORD,
                              DWORD)>(get_api(
                                        _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen(func), STRONG_SEED));
  return temp_SetHandleInformation(hObject,
                                   dwMask,
                                   dwFlags);
}

BOOL hash_DeviceIoControl(HANDLE hDevice,
                          DWORD dwIoControlCode,
                          LPVOID lpInBuffer,
                          DWORD nInBufferSize,
                          LPVOID lpOutBuffer,
                          DWORD nOutBufferSize,
                          LPDWORD lpBytesReturned,
                          LPOVERLAPPED lpOverlapped)
{
  const auto _hash = t1ha0("DeviceIoControl", strlen("DeviceIoControl"), STRONG_SEED);
  temp_DeviceIoControl = static_cast<BOOL(WINAPI *)(HANDLE,
                         DWORD,
                         LPVOID,
                         DWORD,
                         LPVOID,
                         DWORD,
                         LPDWORD,
                         LPOVERLAPPED)>(get_api(
                                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("DeviceIoControl"), STRONG_SEED));
  return temp_DeviceIoControl(hDevice,
                              dwIoControlCode,
                              lpInBuffer,
                              nInBufferSize,
                              lpOutBuffer,
                              nOutBufferSize,
                              lpBytesReturned,
                              lpOverlapped);
}

int hash_lstrlenW(LPCWSTR lpString)
{
  const auto _hash = t1ha0("lstrlenW", strlen("lstrlenW"), STRONG_SEED);
  temp_lstrlenW = static_cast<int(WINAPI *)(LPCWSTR)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                  strlen("lstrlenW"), STRONG_SEED));
  return temp_lstrlenW(lpString);
}


int hash_MultiByteToWideChar(UINT CodePage,
                             DWORD dwFlags,
                             _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
                             int cbMultiByte,
                             LPWSTR lpWideCharStr,
                             int cchWideChar)
{
  const auto _hash = t1ha0("MultiByteToWideChar", strlen("MultiByteToWideChar"), STRONG_SEED);
  temp_MultiByteToWideChar = static_cast<int(WINAPI *)(UINT,
                             DWORD,
                             _In_NLS_string_(cbMultiByte)LPCCH,
                             int,
                             LPWSTR,
                             int)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                   strlen("MultiByteToWideChar"), STRONG_SEED));
  return temp_MultiByteToWideChar(CodePage,
                                  dwFlags,
                                  lpMultiByteStr,
                                  cbMultiByte,
                                  lpWideCharStr,
                                  cchWideChar);
}

HANDLE hash_CreateTimerQueue()
{
  const auto _hash = t1ha0("CreateTimerQueue", strlen("CreateTimerQueue"), STRONG_SEED);
  temp_CreateTimerQueue = static_cast<HANDLE(WINAPI *)()>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                          strlen("CreateTimerQueue"),
                          STRONG_SEED));
  return temp_CreateTimerQueue();
}

BOOL hash_DeleteTimerQueueEx(HANDLE TimerQueue,
                             HANDLE CompletionEvent)
{
  const auto _hash = t1ha0("DeleteTimerQueueEx", strlen("DeleteTimerQueueEx"), STRONG_SEED);
  temp_DeleteTimerQueueEx = static_cast<BOOL(WINAPI *)(HANDLE,
                            HANDLE)>(get_api(
                                       _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("DeleteTimerQueueEx"), STRONG_SEED));
  return temp_DeleteTimerQueueEx(TimerQueue, CompletionEvent);
}

BOOL hash_CheckRemoteDebuggerPresent(HANDLE hProcess,
                                     PBOOL pbDebuggerPresent)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("CheckRemoteDebuggerPresent");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_CheckRemoteDebuggerPresent = static_cast<BOOL(WINAPI *)(HANDLE,
                                    PBOOL)>(get_api(
                                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen(func), STRONG_SEED));
  return temp_CheckRemoteDebuggerPresent(hProcess,
                                         pbDebuggerPresent);
}

LONG hash_UnhandledExceptionFilter(_EXCEPTION_POINTERS *ExceptionInfo)
{
  const auto _hash = t1ha0("UnhandledExceptionFilter", strlen("UnhandledExceptionFilter"), STRONG_SEED);
  temp_UnhandledExceptionFilter = static_cast<LONG(WINAPI *)(_EXCEPTION_POINTERS *)>(get_api(
                                    _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("UnhandledExceptionFilter"), STRONG_SEED));
  return temp_UnhandledExceptionFilter(ExceptionInfo);
}

LPTOP_LEVEL_EXCEPTION_FILTER hash_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
  const auto _hash = t1ha0("SetUnhandledExceptionFilter", strlen("SetUnhandledExceptionFilter"), STRONG_SEED);
  temp_SetUnhandledExceptionFilter = static_cast<LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI *)(LPTOP_LEVEL_EXCEPTION_FILTER)>(
                                       get_api(
                                         _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("SetUnhandledExceptionFilter"), STRONG_SEED));
  return temp_SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
}

ULONG hash_RemoveVectoredExceptionHandler(PVOID Handle)
{
  const auto _hash = t1ha0("RemoveVectoredExceptionHandler", strlen("RemoveVectoredExceptionHandler"), STRONG_SEED);
  temp_RemoveVectoredExceptionHandler = static_cast<ULONG(WINAPI *)(PVOID)>(get_api(
                                          _hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen("RemoveVectoredExceptionHandler"), STRONG_SEED));
  return temp_RemoveVectoredExceptionHandler(Handle);
}

int hash_WSAStartup(WORD wVersionRequired,
                    LPWSADATA lpWSAData)
{
  const auto _hash = t1ha0("WSAStartup", strlen("WSAStartup"), STRONG_SEED);
  temp_WSAStartup = static_cast<int(*)(WORD,
                                       LPWSADATA)>(get_api(_hash, "ws2_32.dll", strlen("WSAStartup"), STRONG_SEED));
  return temp_WSAStartup(wVersionRequired,
                         lpWSAData);
}

int hash_WSACleanup()
{
  const auto _hash = t1ha0("WSACleanup", strlen("WSACleanup"), STRONG_SEED);
  temp_WSACleanup = static_cast<int(*)()>(get_api(_hash, "ws2_32.dll", strlen("WSACleanup"), STRONG_SEED));
  return temp_WSACleanup();
}

int hash_closesocket(IN SOCKET s)
{
  const auto _hash = t1ha0("closesocket", strlen("closesocket"), STRONG_SEED);
  temp_closesocket = static_cast<int(*)(IN SOCKET)>(get_api(_hash, "ws2_32.dll", strlen("closesocket"), STRONG_SEED));
  return temp_closesocket(s);
}

int hash_recv(SOCKET s,
              char *buf,
              int len,
              int flags)
{
  const auto _hash = t1ha0("recv", strlen("recv"), STRONG_SEED);
  temp_recv = static_cast<int(*)(SOCKET,
                                 char *,
                                 int,
                                 int)>(get_api(_hash, "ws2_32.dll", strlen("recv"), STRONG_SEED));
  return temp_recv(s,
                   buf,
                   len,
                   flags);
}

int hash_send(SOCKET s,
              const char *buf,
              int len,
              int flags)
{
  const auto _hash = t1ha0("send", strlen("send"), STRONG_SEED);
  temp_send = static_cast<int(*)(SOCKET,
                                 const char *,
                                 int,
                                 int)>(get_api(_hash, "ws2_32.dll", strlen("send"), STRONG_SEED));
  return temp_send(s,
                   buf,
                   len,
                   flags);
}

// TODO: need fix
SOCKET hash_socket(int af,
                   int type,
                   int protocol)
{
  const auto _hash = t1ha0("socket", strlen("socket"), STRONG_SEED);
  temp_socket = static_cast<SOCKET(*)(int, int, int)>(get_api(_hash, "ws2_32.dll", strlen("socket"), STRONG_SEED));
  return temp_socket(af, type, protocol);
}

int hash_connect(SOCKET s,
                 const sockaddr *name,
                 int namelen)
{
  const auto _hash = t1ha0("connect", strlen("connect"), STRONG_SEED);
  temp_connect = static_cast<int(*)(SOCKET,
                                    const sockaddr *,
                                    int)>(get_api(_hash, "ws2_32.dll", strlen("connect"), STRONG_SEED));
  return temp_connect(s,
                      name,
                      namelen);
}

u_short hash_htons(u_short hostshort)
{
  const auto _hash = t1ha0("htons", strlen("htons"), STRONG_SEED);
  temp_htons = static_cast<u_short(*)(u_short)>(get_api(_hash, "ws2_32.dll", strlen("htons"), STRONG_SEED));
  return temp_htons(hostshort);
}

int hash_WSAGetLastError()
{
  const auto _hash = t1ha0("WSAGetLastError", strlen("WSAGetLastError"), STRONG_SEED);
  temp_WSAGetLastError = static_cast<int(*)()>(get_api(_hash, "ws2_32.dll", strlen("WSAGetLastError"), STRONG_SEED));
  return temp_WSAGetLastError();
}

ULONG hash_inet_addr(_In_z_ const char FAR *cp)
{
  const auto _hash = t1ha0("inet_addr", strlen("inet_addr"), STRONG_SEED);
  temp_inet_addr = static_cast<ULONG(*)(_In_z_ const char FAR *)>(get_api(
                     _hash, "ws2_32.dll", strlen("inet_addr"), STRONG_SEED));
  return temp_inet_addr(cp);
}

void hash_RtlInitUnicodeString(PUNICODE_STRING DestinationString,
                               PCWSTR SourceString)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("RtlInitUnicodeString");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_RtlInitUnicodeString = static_cast<void(*)(PUNICODE_STRING, PCWSTR)>(get_api(
                                _hash, (LPCSTR)PRINT_HIDE_STR("ntdll.dll"), strlen(func), STRONG_SEED));
  return temp_RtlInitUnicodeString(DestinationString,
                                   SourceString);
}

NTSTATUS hash_NtClose(IN HANDLE Handle)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("NtClose");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_NtClose = static_cast<NTSTATUS(*)(IN HANDLE)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("ntdll.dll"), strlen(func),
                 STRONG_SEED));
  return temp_NtClose(Handle);
}

BOOL hash_FreeLibrary(HMODULE hLibModule)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("FreeLibrary");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_FreeLibrary = static_cast<BOOL(*)(HMODULE)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"), strlen(func),
                     STRONG_SEED));
  return temp_FreeLibrary(hLibModule);
}

HMODULE hash_LoadLibraryAA(LPCSTR lpLibFileName)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("LoadLibraryA");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_LoadLibraryAA = static_cast<HMODULE(*)(LPCSTR)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                       strlen(func), STRONG_SEED));
  return temp_LoadLibraryAA(lpLibFileName);
}

BOOL hash_QueryInformationJobObject(HANDLE             hJob,
                                    JOBOBJECTINFOCLASS JobObjectInformationClass,
                                    LPVOID             lpJobObjectInformation,
                                    DWORD              cbJobObjectInformationLength,
                                    LPDWORD            lpReturnLength)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("QueryInformationJobObject");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_QueryInformationJobObject = static_cast<BOOL(*)(HANDLE,
                                   JOBOBJECTINFOCLASS,
                                   LPVOID,
                                   DWORD,
                                   LPDWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                       strlen(func), STRONG_SEED));
  return temp_QueryInformationJobObject(hJob,
                                        JobObjectInformationClass,
                                        lpJobObjectInformation,
                                        cbJobObjectInformationLength,
                                        lpReturnLength);
}

DWORD hash_K32GetProcessImageFileNameW(HANDLE hProcess,
                                       LPWSTR  lpImageFileName,
                                       DWORD  nSize)
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("K32GetProcessImageFileNameW");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_K32GetProcessImageFileNameW = static_cast<DWORD(*)(HANDLE,
                                     LPWSTR,
                                     DWORD)>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                                         strlen(func), STRONG_SEED));
  return temp_K32GetProcessImageFileNameW(hProcess,
                                          lpImageFileName,
                                          nSize);
}
HANDLE hash_GetCurrentThread()
{
  const char *func = (LPCSTR)PRINT_HIDE_STR("GetCurrentThread");
  const auto _hash = t1ha0(func, strlen(func), STRONG_SEED);
  temp_GetCurrentThread = static_cast<HANDLE(*)()>(get_api(_hash, (LPCSTR)PRINT_HIDE_STR("kernel32.dll"),
                          strlen(func), STRONG_SEED));
  return temp_GetCurrentThread();
}
#pragma endregion Custom Functions