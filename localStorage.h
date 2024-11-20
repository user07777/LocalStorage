#pragma once
#include <Windows.h>
#include <sstream>
#include <string>
#include <vector>
#include <shlobj.h> 
#include <random>
#include <fstream>


class localStorage {
public:
    inline std::string genSalt(int length) {
#ifdef _M_IX86
        //Junk
        __asm {
            xor eax, eax
            mov eax, 0x400000 ^ 0xc20
            add eax, 0x400000 ^ 0xc30
            sub eax, 0x400000 ^ 0xc40
        }

#endif

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        std::ostringstream oss;

        for (int i = 0; i < length; ++i) {

#ifdef _M_IX86
            //Junk
            __asm {
                mov ecx, 0x400000 ^ 0xc40
                xor ecx, 0x400000 ^ 0xc350
                inc ecx
                dec ecx
            }
#endif      

            oss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
#ifdef _M_IX86
            //Junk
            __asm {
                push eax
                xor eax, eax
                pop eax
            }
#endif
        }
#ifdef _M_IX86
        __asm {
            //Junk
            mov eax, 0x4000 ^ 0xc350
            add eax, 0x4000 ^ 0xc340
            sub eax, 0x4000 ^ 0xc330
        }
#endif      

        return oss.str();
    }

    inline std::string enc(std::string str, std::string key) {
        std::ostringstream oss;
        int len = key.length();

        if (len == 0) {
            return "";
        }
        std::string salt = genSalt(30);

#ifdef _M_IX86
        __asm {
            xor eax, eax
            mov eax, 0x400000 ^ 0xc250
            add eax, 0x400000 ^ 0xc260
            sub eax, 0x400000 ^ 0xc280
            push eax
            pop eax
        }
#endif

        oss << salt;

        for (int i = 0; i < str.size(); ++i) {

#ifdef _M_IX86
            __asm {
                mov ebx, 0x400000 ^ 0xc450
                xor ebx, 0x400000 ^ 0xc455
                add ebx, 0x400000 ^ 0xc460
                push ebx
                pop ebx
            }
#endif

            unsigned char hex = str[i] ^ key[i % len];
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hex;

#ifdef _M_IX86
            __asm {
                mov ecx, 0x400000 ^ 0xc390
                xor ecx, 0x400000 ^ 0xc370
                inc ecx
                dec ecx
                push ecx
                pop ecx
            }
#endif
        }
#ifdef _M_IX86
        __asm {
            mov edx, 0x400000 ^ 0xc350
            xor edx, 0x400000 ^ 0xc450
            add edx, 0x400000 ^ 0xc550
            sub edx, 0x400000 ^ 0xc650
            push edx
            pop edx
        }
#endif
        return oss.str();
    }

    inline std::string dec(std::string str, std::string key) {
        if (key.empty() || str.empty() || str.size() % 2 != 0) {
            return "";
        }

        std::string result;
        int len = key.length();

#ifdef _M_IX86
        __asm {
            xor eax, eax
            mov eax, 0x4000 ^ 0xc350
            add eax, 0x4000 ^ 0xc250
            sub eax, 0x4000 ^ 0xc150
            push eax
            pop eax
        }
#endif

        for (int i = 60; i < str.size(); i += 2) {
#ifdef _M_IX86
            __asm {
                mov ebx, 0x4000 ^ 0xc50
                xor ebx, 0x4000 ^ 0xc150
                add ebx, 0x4000 ^ 0xc250
                push ebx
                pop ebx
            }
#endif

            std::string hex = str.substr(i, 2);
            unsigned char txt = static_cast<unsigned char>(std::stoi(hex, nullptr, 16));

            result += static_cast<char>(txt ^ key[((i - 60) / 2) % len]);

#ifdef _M_IX86
            __asm {
                mov ecx, 0x4000 ^ 0xc705
                xor ecx, 0x4000 ^ 0xc710
                inc ecx
                dec ecx
                push ecx
                pop ecx
            }
#endif
        }

#ifdef _M_IX86
        __asm {
            mov edx, 0x4000 ^ 0xc3150
            xor edx, 0x4000 ^ 0xc3250
            add edx, 0x4000 ^ 0xc3350
            sub edx, 0x4000 ^ 0xc3450
            push edx
            pop edx
        }
#endif

        return result;
    }


    inline void save(std::string key, std::string str) {
        strs.push_back(std::make_pair(key+":", str));
    }
    virtual bool saveExe() {
        char path[MAX_PATH];

        if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
            return false;
        }
        std::string path2 = appData_();

        if (!CopyFileA(path, path2.c_str(), FALSE)) {
            return false;
        }

        HANDLE f = CreateFileA(path2.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (f == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD sz = GetFileSize(f, NULL);
        if (sz == INVALID_FILE_SIZE) {
            CloseHandle(f);
            return false;
        }

        LPVOID data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (data == NULL) {
            CloseHandle(f);
            return false;
        }

        DWORD bytesRead;
        if (!ReadFile(f, data, sz, &bytesRead, NULL) || bytesRead != sz) {
            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(f);
            return false;
        }

        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(data);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(f);
            return false;
        }

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(data) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(f);
            return false;
        }

        PIMAGE_SECTION_HEADER localsect = IMAGE_FIRST_SECTION(ntHeaders) + (ntHeaders->FileHeader.NumberOfSections - 1);

        DWORD end = localsect->PointerToRawData + localsect->SizeOfRawData;

        std::string item =  "localStorage=" + toStr() + ";";

        SetFilePointer(f, end, NULL, FILE_BEGIN);

        DWORD bytes;
        if (!WriteFile(f, item.c_str(), static_cast<DWORD>(item.size()), &bytes, NULL) || bytes != item.size()) {
            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(f);
            return false;
        }

        HeapFree(GetProcessHeap(), 0, data);
        CloseHandle(f);
        return true;
    }

    virtual std::string get(std::string key="") {
        char path[MAX_PATH];

        if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
            return "";
        }

        HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (f == INVALID_HANDLE_VALUE) {
            return "";
        }

        DWORD sz = GetFileSize(f, NULL);
        if (sz == INVALID_FILE_SIZE) {
            CloseHandle(f);
            return "";
        }

        LPVOID data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (data == NULL) {
            CloseHandle(f);
            return "";
        }

        DWORD bytesRead;
        if (!ReadFile(f, data, sz, &bytesRead, NULL) || bytesRead != sz) {
            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(f);
            return "";
        }

        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(data);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(f);
            return "";
        }

        PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(data) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(f);
            return "";
        }

        PIMAGE_SECTION_HEADER localsect = IMAGE_FIRST_SECTION(ntHeaders) + (ntHeaders->FileHeader.NumberOfSections - 1);
        DWORD end = localsect->PointerToRawData + localsect->SizeOfRawData;

        char* localstorage = reinterpret_cast<char*>(data) + end;
        int localsz = sz - end;

        std::string name = "localStorage";
        std::string var(localstorage, localsz);
        int pos = var.find(name + "=");
        if (pos == std::string::npos) {
            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(f);
            return "";
        }

        int start = pos + name.size() + 1;
        int endP = var.find(';', start);
        if (endP == std::string::npos) {
            HeapFree(GetProcessHeap(), 0, data);
            CloseHandle(f);
            return "";
        }

        std::string value = var.substr(start, endP - start);

        HeapFree(GetProcessHeap(), 0, data);
        CloseHandle(f);
        if (key != "")
            return parse(key, value);
        else
            return value;
    }

    virtual bool swap() {
        std::string path2 = appData_();
        char path[MAX_PATH];
        if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
            std::cerr << "GetModuleFileNameA: " << GetLastError() << "\n";
        }

        std::string psPath = "swap.ps1";

        std::ofstream ps1(psPath);

        if (!ps1.is_open()) {
            return false;
        }

        ps1 << R"(
        param (
            [int]$p_id,
            [string]$og,
            [string]$copy
        )

try {
    Write-Host "proc: $p_id"
    while (Get-Process -Id $p_id -ErrorAction SilentlyContinue) {
        Start-Sleep -Milliseconds 100
    }

    Write-Host "swapping $copy and $og"
    Move-Item -Force -Path $copy -Destination $og

    Write-Host "restart $og"
}
catch {
    Write-Host "Err: $_"
}
Read-Host "..."
)";

        ps1.close();

        std::string cmd = "powershell -ExecutionPolicy Bypass -NoProfile -File \"" + psPath +
            "\" -p_id " + std::to_string(GetCurrentProcessId()) +
            " -og \"" + path +
            "\" -copy \"" + path2 + "\"";

        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
        PROCESS_INFORMATION pi;

        if (!CreateProcessA(NULL, const_cast<char*>(cmd.c_str()), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            std::cerr << "CreateProcessA: " << GetLastError() << "\n";
            return false;
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return true;
    }


private:
    //helpers
    inline std::string toStr() const {
        std::string vecStr;
        for (auto& i : strs)
            vecStr+= i.first+i.second+",";

        if (!vecStr.empty())
            vecStr.pop_back(); 

        return vecStr;
    }

    inline void fromStr(std::string str) {
        strs.clear(); 
        std::istringstream ss(str);
        std::string s;

        while (std::getline(ss, s, ',')) { 
            int pos = s.find(':');
            if (pos != std::string::npos) {
                std::string first = s.substr(0, pos);
                std::string second = s.substr(pos + 1);
                strs.emplace_back(first, second);
            }
        }
    }

    inline  std::string parse(std::string key,std::string val) {
        std::string str = key + ":";
        int pos = val.find(key);
        if (pos == std::string::npos) {
            return "";
        }

        int start = pos + str.size();
        int endP = val.find(',', start);
        if (endP == std::string::npos) {
            endP = val.size();
        }

        return val.substr(start, endP - start);
    }

    inline std::string appData_() const {
        char path[MAX_PATH];

        if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
            std::cerr << "GetModuleFileNameA: " << GetLastError() << "\n";
            return "";
        }

        char sh[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, sh) != S_OK) {
            std::cerr << "SHGetFolderPathA: " << GetLastError() << "\n";
            return "";
        }

        std::string appData = std::string(sh) + "\\localStorage";
        if (!CreateDirectoryA(appData.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            std::cerr << "CreateDirectoryA: " << GetLastError() << "\n";
            return "";
        }

        return appData + "\\" + std::string(strrchr(path, '\\') + 1);

    }



    std::vector<std::pair<std::string, std::string>> strs;
};
