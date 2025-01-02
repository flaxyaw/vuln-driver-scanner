#include "driver_scanner.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <locale>
#include <winhttp.h>
#include <wincrypt.h>
#include <fstream>
#include <softpub.h>
#include <wintrust.h>
#include <mscat.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")

// Define MD5 length constant
#define MD5_HASH_LENGTH 16

// Helper function to convert LPSTR to wstring
std::wstring string_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

// Helper function to convert FILETIME to time_point
std::chrono::system_clock::time_point FileTimeToTimePoint(const FILETIME& ft) {
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    // Convert to Unix epoch
    auto fileTime_systemTime = ull.QuadPart;
    auto unixTime = (fileTime_systemTime - 116444736000000000ULL) / 10000000ULL;

    return std::chrono::system_clock::from_time_t(static_cast<time_t>(unixTime));
}

DriverScanner::DriverScanner()
    : deepScanEnabled(false)
    , signatureVerificationEnabled(false)
{
    fetchMsdbxList();
}

DriverScanner::~DriverScanner() {
}

void DriverScanner::enableDeepScan(bool enable) {
    deepScanEnabled = enable;
}

void DriverScanner::setSignatureVerification(bool enable) {
    signatureVerificationEnabled = enable;
}

void DriverScanner::setCustomScanPath(const std::wstring& path) {
    customScanPath = path;
}

void DriverScanner::checkDriverCapabilities(DriverInfo& driver) {
    std::ifstream file(driver.path, std::ios::binary);
    if (!file) return;

    // Read the entire file content
    std::vector<BYTE> content(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    file.close();

    driver.hasReadWriteCapability = checkForReadWriteCapability(content);
    driver.hasKillProcessCapability = checkForKillProcessCapability(content);

    if (deepScanEnabled) {
        driver.hasRegistryCapability = checkForRegistryCapability(content);
        driver.hasFileSystemCapability = checkForFileSystemCapability(content);
        driver.hasNetworkCapability = checkForNetworkCapability(content);
        analyzeDriverStrings(driver, content);
        checkVulnerabilities(driver, content);
    }

    if (signatureVerificationEnabled) {
        verifyDigitalSignature(driver.path, driver);
    }

    getFileMetadata(driver.path, driver);
}

bool DriverScanner::checkForRegistryCapability(const std::vector<BYTE>& driverContent) {
    const std::vector<std::string> registryPatterns = {
        "ZwCreateKey",
        "ZwOpenKey",
        "ZwDeleteKey",
        "ZwQueryKey",
        "ZwSetValueKey",
        "ZwQueryValueKey"
    };

    std::string content(driverContent.begin(), driverContent.end());
    for (const auto& pattern : registryPatterns) {
        if (content.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool DriverScanner::checkForFileSystemCapability(const std::vector<BYTE>& driverContent) {
    const std::vector<std::string> fsPatterns = {
        "ZwCreateFile",
        "ZwOpenFile",
        "ZwDeleteFile",
        "ZwReadFile",
        "ZwWriteFile",
        "FltRegisterFilter"
    };

    std::string content(driverContent.begin(), driverContent.end());
    for (const auto& pattern : fsPatterns) {
        if (content.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool DriverScanner::checkForNetworkCapability(const std::vector<BYTE>& driverContent) {
    const std::vector<std::string> networkPatterns = {
        "TdiOpen",
        "TdiClose",
        "TdiSend",
        "TdiReceive",
        "WSKStartup",
        "FwpsCalloutRegister"
    };

    std::string content(driverContent.begin(), driverContent.end());
    for (const auto& pattern : networkPatterns) {
        if (content.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void DriverScanner::analyzeDriverStrings(DriverInfo& driver, const std::vector<BYTE>& content) {
    // Convert content to string for analysis
    std::string str(content.begin(), content.end());

    // Look for suspicious strings
    const std::vector<std::string> suspiciousPatterns = {
        "hack", "cheat", "inject", "hook", "patch",
        "bypass", "escalate", "privilege", "rootkit",
        "debug", "anti", "detect"
    };

    for (const auto& pattern : suspiciousPatterns) {
        if (str.find(pattern) != std::string::npos) {
            driver.suspiciousStrings.push_back(pattern);
        }
    }
}

void DriverScanner::checkVulnerabilities(DriverInfo& driver, const std::vector<BYTE>& content) {
    std::string str(content.begin(), content.end());

    for (const auto& pattern : knownVulnPatterns) {
        if (str.find(pattern) != std::string::npos) {
            driver.detectedVulnerabilities.push_back(
                "Potentially unsafe function: " + pattern);
        }
    }

    for (const auto& api : dangerousAPIs) {
        if (str.find(api) != std::string::npos) {
            driver.detectedVulnerabilities.push_back(
                "Dangerous API usage: " + api);
        }
    }
}

bool DriverScanner::verifyDigitalSignature(const std::wstring& filePath, DriverInfo& driver) {
    LONG lStatus = ERROR_SUCCESS;

    // Set up WINTRUST_FILE_INFO structure
    WINTRUST_FILE_INFO FileInfo = {};
    FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileInfo.pcwszFilePath = filePath.c_str();
    FileInfo.hFile = NULL;
    FileInfo.pgKnownSubject = NULL;

    // Set up WinTrust data structure
    WINTRUST_DATA WinTrustData = {};
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileInfo;

    // Set up action ID
    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // Call WinVerifyTrust
    lStatus = ::WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &guidAction,
        &WinTrustData);

    // Cleanup
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &guidAction,
        &WinTrustData);

    driver.isSignedByCertificate = (lStatus == ERROR_SUCCESS);

    // Check if Microsoft signed
    if (driver.isSignedByCertificate) {
        driver.isMicrosoftSigned = (filePath.find(L"\\Windows\\") != std::wstring::npos);
    }

    return driver.isSignedByCertificate;
}

void DriverScanner::getFileMetadata(const std::wstring& filePath, DriverInfo& driver) {
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
        ULARGE_INTEGER fileSize;
        fileSize.LowPart = fileInfo.nFileSizeLow;
        fileSize.HighPart = fileInfo.nFileSizeHigh;
        driver.fileSize = static_cast<DWORD>(fileSize.QuadPart);

        // Store file times directly
        driver.creationTime = fileInfo.ftCreationTime;
        driver.lastModifiedTime = fileInfo.ftLastWriteTime;
    }
}

bool DriverScanner::checkForReadWriteCapability(const std::vector<BYTE>& driverContent) {
    // Common patterns for memory read/write operations
    const std::vector<std::string> rwPatterns = {
        "MmMapIoSpace",
        "MmMapIoSpaceEx",
        "ZwMapViewOfSection",
        "MmCopyVirtualMemory",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "PhysicalMemory"
    };

    std::string content(driverContent.begin(), driverContent.end());
    for (const auto& pattern : rwPatterns) {
        if (content.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool DriverScanner::checkForKillProcessCapability(const std::vector<BYTE>& driverContent) {
    // Common patterns for process termination
    const std::vector<std::string> killPatterns = {
        "ZwTerminateProcess",
        "TerminateProcess",
        "PsTerminateSystemThread",
        "ZwClose",
        "KillProcessByName"
    };

    std::string content(driverContent.begin(), driverContent.end());
    for (const auto& pattern : killPatterns) {
        if (content.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::vector<DriverScanner::DriverInfo> DriverScanner::scanForDrivers() {
    std::vector<DriverInfo> drivers;
    std::filesystem::path systemRoot = "C:\\Windows\\System32\\drivers";

    try {
        for (const auto& entry : std::filesystem::directory_iterator(systemRoot)) {
            if (entry.path().extension() == ".sys") {
                DriverInfo info;
                info.path = entry.path().wstring();
                info.name = entry.path().filename().wstring();
                info.hash = calculateFileHash(info.path);
                info.hasReadWriteCapability = false;
                info.hasKillProcessCapability = false;

                if (!info.hash.empty()) {
                    checkDriverCapabilities(info);
                    drivers.push_back(info);
                }
            }
        }
    }
    catch (const std::exception&) {
        // Handle any filesystem errors silently
    }

    return drivers;
}

bool DriverScanner::isDriverBlocked(const std::wstring& hash) {
    std::wstring lowerHash = hash;
    std::transform(lowerHash.begin(), lowerHash.end(), lowerHash.begin(), ::tolower);

    return std::find(blockedHashes.begin(), blockedHashes.end(), lowerHash) != blockedHashes.end();
}

std::wstring DriverScanner::calculateFileHash(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return L"";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[MD5_HASH_LENGTH];
    DWORD cbHash = MD5_HASH_LENGTH;
    std::wstring hash;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            BYTE rgbFile[4096];
            DWORD cbRead = 0;

            while (ReadFile(hFile, rgbFile, sizeof(rgbFile), &cbRead, NULL)) {
                if (cbRead == 0) break;
                if (!CryptHashData(hHash, rgbFile, cbRead, 0)) break;
            }

            if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
                std::wstringstream ss;
                for (DWORD i = 0; i < cbHash; i++) {
                    ss << std::hex << std::setw(2) << std::setfill(L'0') << (int)rgbHash[i];
                }
                hash = ss.str();
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
    return hash;
}

bool DriverScanner::fetchMsdbxList() {
    bool success = false;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    // Initialize WinHTTP
    hSession = WinHttpOpen(L"VulnDriverScanner/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession) {
        hConnect = WinHttpConnect(hSession, L"raw.githubusercontent.com",
            INTERNET_DEFAULT_HTTPS_PORT, 0);
    }

    if (hConnect) {
        hRequest = WinHttpOpenRequest(hConnect, L"GET",
            L"/microsoft/Microsoft-Recommended-Driver-Block-Rules/main/Microsoft%20Recommended%20Driver%20Block%20Rules.ashx",
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
    }

    if (hRequest) {
        if (WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(hRequest, NULL)) {

            DWORD dwSize = 0;
            DWORD dwDownloaded = 0;
            std::string response;

            do {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;

                if (dwSize == 0) break;

                std::vector<char> buffer(dwSize + 1);
                ZeroMemory(buffer.data(), dwSize + 1);

                if (!WinHttpReadData(hRequest, buffer.data(),
                    dwSize, &dwDownloaded)) break;

                response.append(buffer.data(), dwDownloaded);
            } while (dwSize > 0);

            // Parse the response and extract hashes
            std::istringstream stream(response);
            std::string line;

            while (std::getline(stream, line)) {
                size_t pos = line.find("<Hash>");
                if (pos != std::string::npos) {
                    size_t end = line.find("</Hash>");
                    if (end != std::string::npos) {
                        std::string hash = line.substr(pos + 6, end - (pos + 6));
                        blockedHashes.push_back(std::wstring(hash.begin(), hash.end()));
                    }
                }
            }
            success = true;
        }
    }

    // Cleanup
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return success;
}

bool DriverScanner::isDriverLoadedInKernel(const std::wstring& driverName) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        return false;
    }

    bool isLoaded = false;
    DWORD bytesNeeded = 0;
    DWORD numServices = 0;
    DWORD resumeHandle = 0;

    // First call to get required buffer size
    EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &numServices, &resumeHandle, NULL);

    if (bytesNeeded > 0) {
        std::vector<BYTE> buffer(bytesNeeded);
        LPENUM_SERVICE_STATUS_PROCESSW services =
            reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

        if (EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
            SERVICE_STATE_ALL, buffer.data(), bytesNeeded, &bytesNeeded,
            &numServices, &resumeHandle, NULL)) {

            for (DWORD i = 0; i < numServices; i++) {
                std::wstring serviceName(services[i].lpServiceName);

                // Convert both strings to lowercase for case-insensitive comparison
                std::wstring lowerServiceName = serviceName;
                std::wstring lowerDriverName = driverName;
                std::transform(lowerServiceName.begin(), lowerServiceName.end(),
                    lowerServiceName.begin(), ::towlower);
                std::transform(lowerDriverName.begin(), lowerDriverName.end(),
                    lowerDriverName.begin(), ::towlower);

                // Check if the driver name matches (with or without .sys extension)
                if (lowerServiceName == lowerDriverName ||
                    lowerServiceName == lowerDriverName + L".sys") {
                    // Check if the driver is actually running
                    isLoaded = (services[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING);
                    break;
                }
            }
        }
    }

    CloseServiceHandle(hSCManager);
    return isLoaded;
}