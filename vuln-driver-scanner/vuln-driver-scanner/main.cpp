#include "driver_scanner.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <conio.h>
#include <fcntl.h>
#include <io.h>
#include <fstream>
#include <map>
#include <algorithm>

// Helper function for safe string conversion
std::string wstring_to_string(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

void clearScreen() {
    system("cls");
}

void printHeader() {
    std::cout << "=================================================\n";
    std::cout << "        Advanced Vulnerable Driver Scanner        \n";
    std::cout << "=================================================\n\n";
}

void printDebugInfo(const std::string& message) {
    std::cout << "[DEBUG] " << message << "\n";
}

std::string formatFileTime(const FILETIME& ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    char buffer[100];
    sprintf_s(buffer, sizeof(buffer), "%02d/%02d/%d %02d:%02d:%02d",
        st.wMonth, st.wDay, st.wYear,
        st.wHour, st.wMinute, st.wSecond);
    return std::string(buffer);
}

void printDetailedScanSummary(const std::vector<DriverScanner::DriverInfo>& drivers) {
    int totalDrivers = drivers.size();
    int unsignedCount = 0;
    int rwCapableCount = 0;
    int killCapableCount = 0;
    int registryCapableCount = 0;
    int fsCapableCount = 0;
    int networkCapableCount = 0;
    int highRiskCount = 0;
    int criticalRiskCount = 0;

    for (const auto& driver : drivers) {
        if (!driver.isSignedByCertificate) unsignedCount++;
        if (driver.hasReadWriteCapability) rwCapableCount++;
        if (driver.hasKillProcessCapability) killCapableCount++;
        if (driver.hasRegistryCapability) registryCapableCount++;
        if (driver.hasFileSystemCapability) fsCapableCount++;
        if (driver.hasNetworkCapability) networkCapableCount++;

        // Calculate risk for statistics
        int risk = 0;
        if (!driver.isMicrosoftSigned) risk += 2;
        if (!driver.isSignedByCertificate) risk += 3;
        if (driver.hasReadWriteCapability) risk += 3;
        if (driver.hasKillProcessCapability) risk += 3;
        if (driver.hasRegistryCapability) risk += 1;
        if (driver.hasFileSystemCapability) risk += 1;
        if (driver.hasNetworkCapability) risk += 1;
        if (!driver.detectedVulnerabilities.empty()) {
            int vulnCount = static_cast<int>(driver.detectedVulnerabilities.size());
            risk += (vulnCount > 5) ? 5 : vulnCount;
        }

        if (risk >= 15) criticalRiskCount++;
        else if (risk >= 10) highRiskCount++;
    }

    std::cout << "\n=== DETAILED SCAN SUMMARY ===\n";
    std::cout << "Total Drivers Scanned: " << totalDrivers << "\n";
    std::cout << "\nSIGNATURE STATUS:\n";
    std::cout << "- Unsigned Drivers: " << unsignedCount << " ("
        << (totalDrivers ? (unsignedCount * 100 / totalDrivers) : 0) << "%)\n";

    std::cout << "\nCAPABILITY ANALYSIS:\n";
    std::cout << "- Memory R/W Capable: " << rwCapableCount << " ("
        << (totalDrivers ? (rwCapableCount * 100 / totalDrivers) : 0) << "%)\n";
    std::cout << "- Process Kill Capable: " << killCapableCount << " ("
        << (totalDrivers ? (killCapableCount * 100 / totalDrivers) : 0) << "%)\n";
    std::cout << "- Registry Access: " << registryCapableCount << " ("
        << (totalDrivers ? (registryCapableCount * 100 / totalDrivers) : 0) << "%)\n";
    std::cout << "- FileSystem Access: " << fsCapableCount << " ("
        << (totalDrivers ? (fsCapableCount * 100 / totalDrivers) : 0) << "%)\n";
    std::cout << "- Network Capable: " << networkCapableCount << " ("
        << (totalDrivers ? (networkCapableCount * 100 / totalDrivers) : 0) << "%)\n";

    std::cout << "\nRISK DISTRIBUTION:\n";
    std::cout << "- Critical Risk: " << criticalRiskCount << " ("
        << (totalDrivers ? (criticalRiskCount * 100 / totalDrivers) : 0) << "%)\n";
    std::cout << "- High Risk: " << highRiskCount << " ("
        << (totalDrivers ? (highRiskCount * 100 / totalDrivers) : 0) << "%)\n";
}

void printDriverInfo(const DriverScanner::DriverInfo& driver, bool detailed = false) {
    std::wcout << L"\nDriver: " << driver.name;
    if (!driver.vendor.empty()) {
        std::wcout << L" (by " << driver.vendor << L")";
    }
    std::wcout << L"\n";

    std::wcout << L"Version: " << (!driver.version.empty() ? driver.version : L"Unknown") << L"\n";
    std::wcout << L"Path: " << driver.path << L"\n";
    std::wcout << L"Hash: " << driver.hash << L"\n";

    // Signature information
    std::cout << "Signature Status: ";
    if (driver.isMicrosoftSigned) {
        std::cout << "Microsoft Signed (TRUSTED)\n";
    }
    else if (driver.isSignedByCertificate) {
        std::cout << "Third-party Signed (VERIFY PUBLISHER)\n";
    }
    else {
        std::cout << "UNSIGNED (HIGH RISK)\n";
    }

    // File metadata
    std::cout << "Created: " << formatFileTime(driver.creationTime) << "\n";
    std::cout << "Last Modified: " << formatFileTime(driver.lastModifiedTime) << "\n";
    std::cout << "Size: " << (driver.fileSize / 1024) << " KB\n";

    std::cout << "\nCapabilities:\n";
    std::cout << "- Read/Write Memory: " << (driver.hasReadWriteCapability ? "YES (DANGEROUS)" : "No") << "\n";
    std::cout << "- Process Termination: " << (driver.hasKillProcessCapability ? "YES (DANGEROUS)" : "No") << "\n";
    std::cout << "- Registry Operations: " << (driver.hasRegistryCapability ? "YES (Monitor)" : "No") << "\n";
    std::cout << "- File System Access: " << (driver.hasFileSystemCapability ? "YES (Monitor)" : "No") << "\n";
    std::cout << "- Network Operations: " << (driver.hasNetworkCapability ? "YES (Monitor)" : "No") << "\n";

    if (!driver.detectedVulnerabilities.empty()) {
        std::cout << "\nPotential Vulnerabilities Detected:\n";
        for (const auto& vuln : driver.detectedVulnerabilities) {
            std::cout << "! " << vuln << "\n";
        }
    }

    if (!driver.suspiciousStrings.empty()) {
        std::cout << "\nSuspicious Strings Found:\n";
        for (const auto& str : driver.suspiciousStrings) {
            std::cout << "- " << str << "\n";
        }
    }

    // Calculate risk score
    int riskScore = 0;
    if (!driver.isMicrosoftSigned) riskScore += 2;
    if (!driver.isSignedByCertificate) riskScore += 3;
    if (driver.hasReadWriteCapability) riskScore += 3;
    if (driver.hasKillProcessCapability) riskScore += 3;
    if (driver.hasRegistryCapability) riskScore += 1;
    if (driver.hasFileSystemCapability) riskScore += 1;
    if (driver.hasNetworkCapability) riskScore += 1;

    if (!driver.detectedVulnerabilities.empty()) {
        int vulnCount = static_cast<int>(driver.detectedVulnerabilities.size());
        riskScore += (vulnCount > 5) ? 5 : vulnCount;
    }

    std::cout << "\nRISK ASSESSMENT:\n";
    std::cout << "Risk Score: " << riskScore << "/20\n";
    std::cout << "Risk Level: ";
    if (riskScore >= 15) std::cout << "CRITICAL";
    else if (riskScore >= 10) std::cout << "HIGH";
    else if (riskScore >= 5) std::cout << "MEDIUM";
    else std::cout << "LOW";
    std::cout << "\n";

    std::cout << "----------------------------------------\n";
}

int main() {
    try {
        DriverScanner scanner;
        std::vector<DriverScanner::DriverInfo> blockedDrivers;
        std::vector<DriverScanner::DriverInfo> safeDrivers;
        char choice;

        do {
            clearScreen();
            printHeader();

            std::cout << "[1] Scan for vulnerable drivers (Quick Scan)\n";
            std::cout << "[2] Deep scan with vulnerability analysis\n";
            std::cout << "[3] Show blocked drivers\n";
            std::cout << "[4] Show unblocked drivers\n";
            std::cout << "[5] Show high-risk drivers (Both capabilities)\n";
            std::cout << "[6] Show currently loaded drivers\n";
            std::cout << "[7] Scan custom directory\n";
            std::cout << "[8] Show detailed scan report\n";
            std::cout << "[9] Exit\n\n";
            std::cout << "Choose an option: ";

            choice = _getch();

            switch (choice) {
            case '1': {
                clearScreen();
                printHeader();
                std::cout << "Performing quick scan...\n\n";

                printDebugInfo("Starting quick scan");
                scanner.enableDeepScan(false);
                auto drivers = scanner.scanForDrivers();
                blockedDrivers.clear();
                safeDrivers.clear();

                printDebugInfo("Processing scan results");
                for (const auto& driver : drivers) {
                    if (scanner.isDriverBlocked(driver.hash)) {
                        printDebugInfo("Found blocked driver: " + wstring_to_string(driver.name));
                        blockedDrivers.push_back(driver);
                    }
                    else {
                        safeDrivers.push_back(driver);
                    }
                }

                printDetailedScanSummary(drivers);
                std::cout << "\nPress any key to return to menu...";
                _getch();
                break;
            }

            case '2': {
                clearScreen();
                printHeader();
                std::cout << "Performing deep scan with vulnerability analysis...\n";
                std::cout << "This may take several minutes...\n\n";

                printDebugInfo("Starting deep scan");
                scanner.enableDeepScan(true);
                scanner.setSignatureVerification(true);
                auto drivers = scanner.scanForDrivers();
                blockedDrivers.clear();
                safeDrivers.clear();

                printDebugInfo("Processing deep scan results");
                for (const auto& driver : drivers) {
                    if (scanner.isDriverBlocked(driver.hash)) {
                        printDebugInfo("Found blocked driver: " + wstring_to_string(driver.name));
                        blockedDrivers.push_back(driver);
                    }
                    else {
                        if (driver.hasReadWriteCapability || driver.hasKillProcessCapability) {
                            printDebugInfo("Found potentially dangerous driver: " +
                                wstring_to_string(driver.name));
                        }
                        safeDrivers.push_back(driver);
                    }
                }

                printDetailedScanSummary(drivers);
                std::cout << "\nPress any key to return to menu...";
                _getch();
                break;
            }

            case '3': {
                clearScreen();
                printHeader();
                std::cout << "=== BLOCKED DRIVERS ===\n\n";

                if (blockedDrivers.empty()) {
                    std::cout << "No blocked drivers found. Run a scan first.\n";
                }
                else {
                    printDebugInfo("Displaying " + std::to_string(blockedDrivers.size()) + " blocked drivers");
                    for (const auto& driver : blockedDrivers) {
                        printDriverInfo(driver, true);
                    }
                }
                std::cout << "\nPress any key to return to menu...";
                _getch();
                break;
            }

            case '4': {
                clearScreen();
                printHeader();
                std::cout << "=== UNBLOCKED DRIVERS ===\n\n";

                if (safeDrivers.empty()) {
                    std::cout << "No unblocked drivers found. Run a scan first.\n";
                }
                else {
                    printDebugInfo("Displaying " + std::to_string(safeDrivers.size()) + " unblocked drivers");
                    for (const auto& driver : safeDrivers) {
                        printDriverInfo(driver, true);
                    }
                }
                std::cout << "\nPress any key to return to menu...";
                _getch();
                break;
            }

            case '5': {
                clearScreen();
                printHeader();
                std::cout << "=== HIGH RISK DRIVERS (R/W + KILL PROCESS) ===\n\n";

                bool found = false;
                printDebugInfo("Checking for high-risk drivers");

                for (const auto& driver : safeDrivers) {
                    if (driver.hasReadWriteCapability && driver.hasKillProcessCapability) {
                        if (!found) {
                            std::cout << "!!! WARNING: POTENTIALLY DANGEROUS UNBLOCKED DRIVERS FOUND !!!\n\n";
                            found = true;
                        }
                        printDebugInfo("Found high-risk driver: " + wstring_to_string(driver.name));
                        printDriverInfo(driver, true);
                    }
                }

                if (!found) {
                    std::cout << "No high-risk drivers found with both capabilities.\n";
                }

                std::cout << "\nPress any key to return to menu...";
                _getch();
                break;
            }

            case '6': {
                clearScreen();
                printHeader();
                std::cout << "=== CURRENTLY LOADED DRIVERS ===\n\n";

                printDebugInfo("Checking for loaded drivers");
                bool found = false;

                for (const auto& driver : safeDrivers) {
                    if (scanner.isDriverLoadedInKernel(driver.name)) {
                        if (!found) {
                            std::cout << "Currently loaded drivers:\n\n";
                            found = true;
                        }
                        printDebugInfo("Found loaded driver: " + wstring_to_string(driver.name));
                        printDriverInfo(driver, true);
                    }
                }

                if (!found) {
                    std::cout << "No scanned drivers are currently loaded.\n";
                }

                std::cout << "\nPress any key to return to menu...";
                _getch();
                break;
            }

            case '7': {
                clearScreen();
                printHeader();
                std::cout << "Enter path to scan (or press Enter for default): ";
                std::wstring customPath;
                std::getline(std::wcin >> std::ws, customPath);

                if (!customPath.empty()) {
                    printDebugInfo("Setting custom scan path: " + wstring_to_string(customPath));
                    scanner.setCustomScanPath(customPath);

                    // Perform scan with custom path
                    auto drivers = scanner.scanForDrivers();
                    blockedDrivers.clear();
                    safeDrivers.clear();

                    for (const auto& driver : drivers) {
                        if (scanner.isDriverBlocked(driver.hash)) {
                            blockedDrivers.push_back(driver);
                        }
                        else {
                            safeDrivers.push_back(driver);
                        }
                    }

                    printDetailedScanSummary(drivers);
                }

                std::cout << "\nPress any key to return to menu...";
                _getch();
                break;
            }

            case '8': {
                clearScreen();
                printHeader();
                std::cout << "=== DETAILED SCAN REPORT ===\n\n";

                if (blockedDrivers.empty() && safeDrivers.empty()) {
                    std::cout << "No scan data available. Run a scan first.\n";
                }
                else {
                    std::vector<DriverScanner::DriverInfo> allDrivers;
                    allDrivers.insert(allDrivers.end(), blockedDrivers.begin(), blockedDrivers.end());
                    allDrivers.insert(allDrivers.end(), safeDrivers.begin(), safeDrivers.end());

                    printDetailedScanSummary(allDrivers);

                    std::cout << "\n=== FULL DRIVER DETAILS ===\n";
                    for (const auto& driver : allDrivers) {
                        printDriverInfo(driver, true);
                    }
                }

                std::cout << "\nPress any key to return to menu...";
                _getch();
                break;
            }
            }

        } while (choice != '9');

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        std::cout << "\nPress any key to exit...";
        _getch();
        return 1;
    }

    return 0;
}