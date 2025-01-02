#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <filesystem>

class DriverScanner {
public:
    struct DriverInfo {
        std::wstring name;
        std::wstring path;
        std::wstring hash;
        std::wstring vendor;
        std::wstring version;
        bool hasReadWriteCapability;
        bool hasKillProcessCapability;
        bool hasRegistryCapability;
        bool hasFileSystemCapability;
        bool hasNetworkCapability;
        bool isSignedByCertificate;
        bool isMicrosoftSigned;
        FILETIME creationTime;
        FILETIME lastModifiedTime;
        DWORD fileSize;
        std::vector<std::string> suspiciousStrings;
        std::vector<std::string> detectedVulnerabilities;
    };

    DriverScanner();
    ~DriverScanner();

    // Main scanning functions
    std::vector<DriverInfo> scanForDrivers();
    bool isDriverBlocked(const std::wstring& hash);
    bool isDriverLoadedInKernel(const std::wstring& driverName);

    // Configuration
    void setCustomScanPath(const std::wstring& path);
    void enableDeepScan(bool enable);
    void setSignatureVerification(bool enable);

private:
    // Helper methods
    std::wstring calculateFileHash(const std::wstring& filePath);
    bool fetchMsdbxList();
    void checkDriverCapabilities(DriverInfo& driver);
    bool checkForReadWriteCapability(const std::vector<BYTE>& driverContent);
    bool checkForKillProcessCapability(const std::vector<BYTE>& driverContent);
    bool checkForRegistryCapability(const std::vector<BYTE>& driverContent);
    bool checkForFileSystemCapability(const std::vector<BYTE>& driverContent);
    bool checkForNetworkCapability(const std::vector<BYTE>& driverContent);

    // New analysis methods
    void analyzeDriverStrings(DriverInfo& driver, const std::vector<BYTE>& content);
    void checkVulnerabilities(DriverInfo& driver, const std::vector<BYTE>& content);
    bool verifyDigitalSignature(const std::wstring& filePath, DriverInfo& driver);
    void getFileMetadata(const std::wstring& filePath, DriverInfo& driver);

    // Data members
    std::vector<std::wstring> blockedHashes;
    std::wstring customScanPath;
    bool deepScanEnabled;
    bool signatureVerificationEnabled;

    // Known vulnerability patterns
    const std::vector<std::string> knownVulnPatterns = {
        "memcpy", "strcpy", "strcat", "sprintf", "vsprintf",
        "gets", "scanf", "sscanf", "fscanf", "vfscanf",
        "reallocarray", "alloca"
    };

    // Known dangerous capability patterns
    const std::vector<std::string> dangerousAPIs = {
        "ZwMapViewOfSection", "MmMapIoSpace", "MmMapLockedPages",
        "ZwCreateSection", "ZwOpenSection", "ZwAllocateVirtualMemory",
        "ObRegisterCallbacks", "PsSetCreateProcessNotifyRoutine",
        "PsSetLoadImageNotifyRoutine", "PsSetCreateThreadNotifyRoutine",
        "KeInsertQueueApc", "KeInitializeApc", "KeInsertQueueDpc"
    };
};