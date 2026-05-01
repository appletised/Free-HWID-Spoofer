#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <random>
#include <ctime>
#include <sstream>
#include <filesystem>

static HANDLE hcon = GetStdHandle(STD_OUTPUT_HANDLE);
static void color(int c) { SetConsoleTextAttribute(hcon, c); }

static std::mt19937 rng(static_cast<unsigned>(std::time(nullptr)));

static std::string roll(int len, const char* pool) {
    std::string s;
    int n = (int)strlen(pool);
    std::uniform_int_distribution<int> d(0, n - 1);
    for (int i = 0; i < len; i++) s += pool[d(rng)];
    return s;
}

static std::string alnum(int n) { return roll(n, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"); }
static std::string digits(int n) { return roll(n, "0123456789"); }
static std::string mixed(int n) { return roll(n, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"); }
static std::string upper(int n) { return roll(n, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
static std::string hex(int n) { return roll(n, "ABCDEF"); }

static std::string guid() {
    std::uniform_int_distribution<int> a(0, 65535), b(0, 4095), c(0, 16383);
    char buf[64];
    snprintf(buf, sizeof(buf), "{%04x%04x-%04x-%04x-%04x-%04x%04x%04x}",
        a(rng), a(rng), a(rng), b(rng) | 0x4000, c(rng) | 0x8000, a(rng), a(rng), a(rng));
    return buf;
}

static std::string capture(const std::string& cmd) {
    std::string out;
    FILE* p = _popen(cmd.c_str(), "r");
    if (!p) return out;
    char buf[256];
    while (fgets(buf, sizeof(buf), p)) out += buf;
    _pclose(p);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

static int run(const std::string& cmd) { return system(cmd.c_str()); }

static std::string wmic(const std::string& q) {
    std::string out = capture(q);
    std::istringstream ss(out);
    std::string line, last;
    while (std::getline(ss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (!line.empty()) last = line;
    }
    return last;
}

static std::string readreg(HKEY root, const char* sub, const char* name) {
    HKEY h;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &h) != ERROR_SUCCESS) return "";
    char buf[512];
    DWORD sz = sizeof(buf), type = 0;
    std::string out;
    if (RegQueryValueExA(h, name, nullptr, &type, (LPBYTE)buf, &sz) == ERROR_SUCCESS && type == REG_SZ)
        out = buf;
    RegCloseKey(h);
    return out;
}

static std::string here() {
    char buf[MAX_PATH];
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string p(buf);
    auto pos = p.find_last_of("\\/");
    if (pos != std::string::npos) p.resize(pos);
    return p;
}

static std::string amipath() { return here() + "\\AMIDEWINx64.EXE"; }
static bool fileexists(const std::string& p) { return GetFileAttributesA(p.c_str()) != INVALID_FILE_ATTRIBUTES; }
static bool hasami() { return fileexists(amipath()); }

static bool g_drv_failed = false;
static bool g_drv_warned = false;

static void reset() { g_drv_failed = false; g_drv_warned = false; }

static int ami(const std::vector<std::string>& args) {
    if (g_drv_failed) return -1;

    std::string dir = std::filesystem::path(amipath()).parent_path().string();
    std::string exe = std::filesystem::path(amipath()).filename().string();
    std::string cmd = "cd /d \"" + dir + "\" && " + exe;
    for (auto& a : args) cmd += " " + a;
    cmd += " >nul 2>&1";

    int code = system(cmd.c_str());

    if (code == 10 || code == -1073741819 || code == 3221225477) {
        g_drv_failed = true;
        if (!g_drv_warned) {
            g_drv_warned = true;
            printf("\n[!] Spoofer failed to load its kernel driver\n");
            printf("[!] To fix this, reboot into BIOS and:\n");
            printf("[!]   1. Enable CSM\n");
            printf("[!]   2. Disable Secure Boot\n");
            printf("[!] Then try again.\n\n");
            printf("[!] If this didn't work, your motherboard is Write Protected.\n\n");
        }
    }
    return code;
}

//restart wmi

static void wmi() {
    run("net stop winmgmt /y");
    run("net start winmgmt");
}

// print serials to screen
static void info() {
    color(11);
    printf("\n");
    printf("   ___          _      _    \n");
    printf("  / __| ___ _ _(_)__ _| |___\n");
    printf("  \\__ \\/ -_) '_| / _` | (_-<\n");
    printf("  |___/\\___|_| |_\\__,_|_/__/\n");
    printf("\n");
    color(7);
    printf(" Motherboard Manufacturer: %s\n", wmic("wmic baseboard get manufacturer").c_str());
    printf(" Motherboard Name: %s\n", wmic("wmic baseboard get product").c_str());
    printf(" BIOS Version: %s\n", wmic("wmic bios get version").c_str());
    printf(" CPU: %s\n", wmic("wmic cpu get name").c_str());

    printf("\n -----Serials------\n");
    struct { const char* label; const char* cmd; } s[] = {
        {" Baseboard Serial", "wmic baseboard get serialnumber"},
        {" Chassis Serial",   "wmic systemenclosure get serialnumber"},
        {" SMBIOS Serial",    "wmic path win32_computersystemproduct get uuid"},
        {" BIOS Serial",      "wmic bios get serialnumber"},
        {" CPU Serial",       "wmic cpu get serialnumber"},
    };
    for (auto& x : s) printf("%s: %s\n", x.label, wmic(x.cmd).c_str());

    printf("\n -----MAC Addresses-----\n");
    std::string macs = capture(
        "powershell -Command \"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.Name + '|' + $_.MacAddress }\"");
    if (macs.empty()) { printf(" N/A\n\n"); return; }
    std::istringstream ss(macs);
    std::string line;
    while (std::getline(ss, line)) {
        while (!line.empty() && (line.back() == '\r')) line.pop_back();
        if (line.empty()) continue;
        auto pos = line.find('|');
        if (pos != std::string::npos)
            printf(" %s: %s\n", line.substr(0, pos).c_str(), line.substr(pos + 1).c_str());
    }
    printf("\n");
}

//change the name of your pc (not really needed but nice to have)

static bool renamepc() {
    std::string name = alnum(8);
    std::string base = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName\"";
    int r = 0;
    r |= run(base + " /v ComputerName /t REG_SZ /d " + name + " /f");
    r |= run(base + " /v ActiveComputerName /t REG_SZ /d " + name + " /f");
    r |= run(base + " /v ComputerNamePhysicalDnsDomain /t REG_SZ /d \"\" /f");
    if (r == 0) { printf("[+] PC name set to: %s\n", name.c_str()); return true; }
    printf("[-] PC name failed (need admin).\n");
    return false;
}

static bool fakeguid() {
    std::string g = guid();
    std::string cmd = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001\" "
                      "/v HwProfileGuid /t REG_SZ /d " + g + " /f";
    if (run(cmd) == 0) { printf("[+] GUID set to: %s\n", g.c_str()); return true; }
    printf("[-] GUID failed (need admin).\n");
    return false;
}

//change gpu guids (works for some games)

static bool fakegpu() {
    std::string key = "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_10DE^&DEV_0DE1^&SUBSYS_37621462^&REV_A1";
    std::string klass = "{4d36e968-e325-11ce-bfc1-08002be10318}";
    std::string id = "PCIVEN_8086^&DEV_" + digits(4) + "^&SUBSYS_" + upper(4) + "^&REV_01";
    int r = 0;
    r |= run("reg add \"" + key + "\" /v HardwareID /t REG_SZ /d " + id + " /f");
    r |= run("reg add \"" + key + "\" /v CompatibleIDs /t REG_MULTI_SZ /d " + id + " /f");
    r |= run("reg add \"" + key + "\" /v Driver /t REG_SZ /d pci.sys /f");
    r |= run("reg add \"" + key + "\" /v ConfigFlags /t REG_DWORD /d 0 /f");
    r |= run("reg add \"" + key + "\" /v ClassGUID /t REG_SZ /d " + klass + " /f");
    r |= run("reg add \"" + key + "\" /v Class /t REG_SZ /d Display /f");
    if (r == 0) { printf("[+] GPU spoofed.\n"); return true; }
    printf("[-] GPU failed (need admin).\n");
    return false;
}

//changes your serials

static bool serials() {
    if (!hasami()) { printf("[-] AMIDEWINx64.EXE missing.\n"); return false; }
    std::string m = readreg(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardManufacturer");
    bool giga = m.find("Gigabyte") != std::string::npos;
    if (giga) {
        ami({"/CS", "\"Default string\""});
        ami({"/BS", "\"Default string\""});
        ami({"/PSN", "\"To be filled by O.E.M.\""});
        ami({"/SS", "\"Default string\""});
    } else {
        ami({"/CS", mixed(16)});
        ami({"/BS", digits(15)});
        ami({"/PSN", mixed(16)});
        ami({"/SS", digits(15)});
    }
    ami({"/SU", "AUTO"});
    wmi();
    printf("[+] Serials spoofed.\n");
    return true;
}

static void tail(const std::string& bs) {
    for (int i = 1; i <= 8; i++) ami({"/OS", std::to_string(i), "\"Default string\""});
    for (int i = 1; i <= 4; i++) ami({"/SCO", std::to_string(i), "\"Default string\""});
    ami({"/BS", bs});
    ami({"/SU", "AUTO"});
    wmi();
}

//semi legit smbios fixer

static bool gigabyte(const std::string& model) {
    if (!hasami()) { printf("[-] AMIDEWINx64.EXE missing.\n"); return false; }
    std::string q = "\"" + model + "\"", def = "\"Default string\"";
    ami({"/PSN", "Unknown"}); ami({"/PPN", "Unknown"}); ami({"/PAT", "Unknown"});
    ami({"/SM", "\"Gigabyte Technology Co., Ltd.\""});
    ami({"/SP", q}); ami({"/SV", def});
    ami({"/BM", "\"Gigabyte Technology Co., Ltd.\""});
    ami({"/BP", q}); ami({"/BV", "x.x"});
    ami({"/SK", def}); ami({"/BT", def});
    ami({"/BTH", "2", def}); ami({"/BLC", def}); ami({"/BLCH", "2", def});
    ami({"/CM", def}); ami({"/CV", def}); ami({"/CS", def}); ami({"/CA", def});
    ami({"/CT", "03h"}); ami({"/CO", "00000000h"}); ami({"/CSK", def});
    ami({"/CMH", "3", def}); ami({"/CVH", "3", def}); ami({"/CSH", "3", def});
    ami({"/CAH", "3", def}); ami({"/CSKH", "3", def});
    ami({"/SS", def});
    tail(def);
    printf("[+] Gigabyte SMBIOS done.\n");
    return true;
}

static bool asusintel(const std::string& model) {
    if (!hasami()) { printf("[-] AMIDEWINx64.EXE missing.\n"); return false; }
    std::string q = "\"" + model + "\"", oem = "\"To be filled by O.E.M.\"", def = "\"Default string\"";
    ami({"/PSN", oem}); ami({"/PPN", "Unknown"}); ami({"/PAT", "Unknown"});
    ami({"/SM", "\"ASUSTeK COMPUTER INC.\""});
    ami({"/SP", q}); ami({"/SV", oem});
    ami({"/BM", "\"ASUSTeK COMPUTER INC.\""});
    ami({"/BP", q}); ami({"/BV", "\"Rev 1.xx\""});
    ami({"/SK", oem}); ami({"/BT", oem});
    ami({"/BTH", "2", oem}); ami({"/BLC", oem}); ami({"/BLCH", "2", oem});
    ami({"/CM", oem}); ami({"/CV", oem}); ami({"/CS", oem}); ami({"/CA", oem});
    ami({"/CT", "03h"}); ami({"/CO", "00000000h"}); ami({"/CSK", def});
    ami({"/CMH", "3", def}); ami({"/CVH", "3", def}); ami({"/CSH", "3", oem});
    ami({"/CAH", "3", def}); ami({"/CSKH", "3", oem});
    ami({"/SS", oem});
    tail(digits(16));
    printf("[+] ASUS Intel SMBIOS done.\n");
    return true;
}

static bool asusamd(const std::string& model) {
    if (!hasami()) { printf("[-] AMIDEWINx64.EXE missing.\n"); return false; }
    std::string q = "\"" + model + "\"", oem = "\"To be filled by O.E.M.\"", def = "\"Default string\"";
    ami({"/PSN", "Unknown"}); ami({"/PPN", "Unknown"}); ami({"/PAT", "Unknown"});
    ami({"/SM", "\"ASUSTeK COMPUTER INC.\""});
    ami({"/SP", q}); ami({"/SV", "Unknown"});
    ami({"/BM", "\"ASUSTeK COMPUTER INC.\""});
    ami({"/BP", q}); ami({"/BV", "Unknown"});
    ami({"/SK", oem}); ami({"/BT", oem});
    ami({"/BTH", "2", oem}); ami({"/BLC", oem}); ami({"/BLCH", "2", oem});
    ami({"/CM", oem}); ami({"/CV", oem}); ami({"/CS", oem}); ami({"/CA", def});
    ami({"/CT", "03h"}); ami({"/CO", "00000000h"}); ami({"/CSK", def});
    ami({"/CMH", "3", def}); ami({"/CVH", "3", def}); ami({"/CSH", "3", def});
    ami({"/CAH", "3", def}); ami({"/CSKH", "3", def});
    ami({"/SS", oem});
    tail(digits(16));
    printf("[+] ASUS AMD SMBIOS done.\n");
    return true;
}

static bool msiintel(const std::string& model) {
    if (!hasami()) { printf("[-] AMIDEWINx64.EXE missing.\n"); return false; }
    std::string q = "\"" + model + "\"", oem = "\"To be filled by O.E.M.\"", def = "\"Default string\"";
    ami({"/PSN", oem}); ami({"/PPN", "Unknown"}); ami({"/PAT", "Unknown"});
    ami({"/SM", "\"Micro-Star International Co., Ltd.\""});
    ami({"/SP", q}); ami({"/SV", oem});
    ami({"/BM", "\"Micro-Star International Co., Ltd.\""});
    ami({"/BP", q}); ami({"/BV", oem});
    ami({"/SK", oem}); ami({"/BT", oem});
    ami({"/BTH", "2", oem}); ami({"/BLC", oem}); ami({"/BLCH", "2", oem});
    ami({"/CM", oem}); ami({"/CV", oem}); ami({"/CS", oem}); ami({"/CA", oem});
    ami({"/CT", "03h"}); ami({"/CO", "00000000h"}); ami({"/CSK", def});
    ami({"/CMH", "3", def}); ami({"/CVH", "3", def}); ami({"/CSH", "3", def});
    ami({"/CAH", "3", def}); ami({"/CSKH", "3", def});
    ami({"/SS", def});
    std::uniform_int_distribution<int> d1(1000, 9999), d2(100000, 999999);
    std::string bs = "07" + hex(1) + std::to_string(d1(rng)) + "_" + roll(1, "ML") + "11" + hex(1) + std::to_string(d2(rng));
    tail(bs);
    printf("[+] MSI Intel SMBIOS done.\n");
    return true;
}

static bool msiamd(const std::string& model) {
    if (!hasami()) { printf("[-] AMIDEWINx64.EXE missing.\n"); return false; }
    std::string q = "\"" + model + "\"", oem = "\"To be filled by O.E.M.\"", def = "\"Default string\"";
    ami({"/PSN", "Unknown"}); ami({"/PPN", "Unknown"}); ami({"/PAT", "Unknown"});
    ami({"/SM", "\"Micro-Star International Co., Ltd.\""});
    ami({"/SP", q}); ami({"/SV", oem});
    ami({"/BM", "\"Micro-Star International Co., Ltd.\""});
    ami({"/BP", q}); ami({"/BV", oem});
    ami({"/SK", oem}); ami({"/BT", oem});
    ami({"/BTH", "2", oem}); ami({"/BLC", oem}); ami({"/BLCH", "2", oem});
    ami({"/CM", oem}); ami({"/CV", oem}); ami({"/CS", oem}); ami({"/CA", oem});
    ami({"/CT", "03h"}); ami({"/CO", "00000000h"}); ami({"/CSK", def});
    ami({"/CMH", "3", def}); ami({"/CVH", "3", def}); ami({"/CSH", "3", def});
    ami({"/CAH", "3", def}); ami({"/CSKH", "3", def});
    ami({"/SS", oem});
    tail(oem);
    printf("[+] MSI AMD SMBIOS done.\n");
    return true;
}

static bool smbios() {
    color(11);
    printf("\n");
    printf("   ___ __  __ ___ ___ ___  ___ \n");
    printf("  / __|  \\/  | _ )_ _/ _ \\/ __|\n");
    printf("  \\__ \\ |\\/| | _ \\| | (_) \\__ \\\n");
    printf("  |___/_|  |_|___/___\\___/|___/\n");
    printf("\n");
    color(7);
    reset();
    printf("CPU type:\n  1. Intel\n  2. AMD\nChoice: ");
    int cpu;
    if (scanf("%d", &cpu) != 1) { getchar(); return false; }
    getchar();
    std::string ct = (cpu == 2) ? "AMD" : "Intel";

    printf("Manufacturer:\n  1. ASUS\n  2. Gigabyte\n  3. MSI\nChoice: ");
    int mfr;
    if (scanf("%d", &mfr) != 1) { getchar(); return false; }
    getchar();

    printf("Motherboard model (case sensitive): ");
    char buf[256];
    if (!fgets(buf, sizeof(buf), stdin)) return false;
    std::string model(buf);
    while (!model.empty() && (model.back() == '\n' || model.back() == '\r')) model.pop_back();

    if (mfr == 2) return gigabyte(model);
    if (mfr == 1 && ct == "Intel") return asusintel(model);
    if (mfr == 1 && ct == "AMD") return asusamd(model);
    if (mfr == 3 && ct == "Intel") return msiintel(model);
    if (mfr == 3 && ct == "AMD") return msiamd(model);
    printf("[-] Unsupported combination.\n");
    return false;
}

struct Board { std::string mfr, cpu, model; };

//motherboard detection (doesn't work if your smbios is messed up by another spoofer)

static Board detect() {
    Board b;
    std::string raw = readreg(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardManufacturer");
    b.model = readreg(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardProduct");
    std::string c = wmic("wmic cpu get name");
    if (c.find("Intel") != std::string::npos) b.cpu = "Intel";
    else if (c.find("AMD") != std::string::npos) b.cpu = "AMD";
    if (raw.find("Gigabyte") != std::string::npos) b.mfr = "Gigabyte";
    else if (raw.find("ASUS") != std::string::npos || raw.find("ASUSTeK") != std::string::npos) b.mfr = "ASUS";
    else if (raw.find("MSI") != std::string::npos || raw.find("Micro-Star") != std::string::npos) b.mfr = "MSI";
    return b;
}

//detects your cpu + motherboard combination before spoofing, if included in smbios fixer, it'll give you legitimate serials

static bool oneclick() {
    color(11);
    printf("\n");
    printf("    ___              ___ _ _    _   \n");
    printf("   / _ \\ _ _  ___  / __| (_)__| |__\n");
    printf("  | (_) | ' \\/ -_)| (__| | / _| / /\n");
    printf("   \\___/|_||_\\___| \\___|_|_\\__|_\\_\\\n");
    printf("\n");
    color(7);
    reset();
    bool ok = true;
    if (!renamepc()) ok = false;
    if (!fakeguid()) ok = false;
    if (!fakegpu()) ok = false;

    Board b = detect();
    if (!b.mfr.empty() && !b.cpu.empty()) {
        printf("[*] Detected: %s %s (%s)\n", b.mfr.c_str(), b.model.c_str(), b.cpu.c_str());
        bool got = false;
        if (b.mfr == "Gigabyte") got = gigabyte(b.model);
        else if (b.mfr == "ASUS" && b.cpu == "Intel") got = asusintel(b.model);
        else if (b.mfr == "ASUS" && b.cpu == "AMD") got = asusamd(b.model);
        else if (b.mfr == "MSI" && b.cpu == "Intel") got = msiintel(b.model);
        else if (b.mfr == "MSI" && b.cpu == "AMD") got = msiamd(b.model);
        if (!got && !serials()) ok = false;
    } else {
        if (!serials()) ok = false;
    }

    printf(ok ? "\n[+] Done.\n" : "\n[!] Some steps failed.\n");
    return ok;
}

//prints tpm hashes

static void tpm() {
    color(11);
    printf("\n");
    printf("   _____ ___ __  __\n");
    printf("  |_   _| _ \\  \\/  |\n");
    printf("    | | |  _/ |\\/| |\n");
    printf("    |_| |_| |_|  |_|\n");
    printf("\n");
    color(7);
    std::string out = capture(
        "powershell -Command \""
        "$h = (Get-TpmEndorsementKeyInfo -Hash sha256).PublicKeyHash;"
        "$bytes = [System.Text.Encoding]::UTF8.GetBytes($h);"
        "$sha1 = [System.BitConverter]::ToString((New-Object System.Security.Cryptography.SHA1CryptoServiceProvider).ComputeHash($bytes)).Replace('-','').ToLower();"
        "$md5 = [System.BitConverter]::ToString((New-Object System.Security.Cryptography.MD5CryptoServiceProvider).ComputeHash($bytes)).Replace('-','').ToLower();"
        "Write-Host 'MD5:    ' $md5;"
        "Write-Host 'SHA1:   ' $sha1;"
        "Write-Host 'SHA256: ' $h.ToLower();\"");
    printf("%s\n", out.empty() ? "Failed to read TPM" : out.c_str());
}



static void banner() {
    color(11);
    printf("\n");
    printf("   ____  _                                       \n");
    printf("  / ___|| | ___   _ _   ___      ____ _ _ __ ___ \n");
    printf("  \\___ \\| |/ / | | | | | \\ \\ /\\ / / _` | '__/ _ \\\n");
    printf("   ___) |   <| |_| | |_| |\\ V  V / (_| | | |  __/\n");
    printf("  |____/|_|\\_\\\\__, |\\__, | \\_/\\_/ \\__,_|_|  \\___|\n");
    printf("               |___/ |___/                        \n");
    color(7);
    printf("\n");
}

static void menu() {
    banner();
    printf("   "); color(11); printf("[1]"); color(7); printf(" One Click Spoof\n");
    printf("   "); color(11); printf("[2]"); color(7); printf(" SMBIOS Fixer\n");
    printf("   "); color(11); printf("[3]"); color(7); printf(" TPM Checker\n");
    printf("   "); color(11); printf("[4]"); color(7); printf(" Show Serials\n\n");
    printf("   "); color(12); printf("[0]"); color(7); printf(" Exit\n\n");
    color(8); printf("                  github.com/appletised\n\n");
    color(7);
    printf("  Choice: ");
}

static void hide() {
    std::string dir = here();
    const char* files[] = {
        "AMIDEWINx64.EXE", "AMIDEWIN.EXE", "DMI16.EXE", "DMIEDIT.EXE",
        "amifldrv64.sys", "UCOREDLL.DLL", "UCORESYS.SYS", "UCOREVXD.VXD",
        "UCOREW64.SYS", "Volumeid.exe", "Volumeid64.exe",
        "spoofer.bat", "spoofs.manifest", "spoofs.rc"
    };
    for (auto& f : files) {
        std::string p = dir + "\\" + f;
        DWORD a = GetFileAttributesA(p.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_HIDDEN))
            SetFileAttributesA(p.c_str(), a | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
}

int main() {
    hide();
    SetConsoleTitleA("discord.gg/skyyware (FREE SPOOFER)");
    banner();
    color(7);
    printf("   By using this software you agree\n");
    printf("   to the following:\n\n");
    printf("   - Provided as-is, no warranty\n");
    printf("   - You accept full responsibility for any damages, bans or issues\n");
    printf("   - Use at your own risk\n");
    printf("   - May not work on all boards\n\n");
    color(11);
    printf("   Press Enter to accept and continue...");
    color(7);
    getchar();
    system("cls");

    while (true) {
        menu();

        int c;
        if (scanf("%d", &c) != 1) { getchar(); continue; }
        getchar();
        system("cls");

        switch (c) {
            case 1: oneclick(); break;
            case 2: smbios(); break;
            case 3: tpm(); break;
            case 4: info(); break;
            case 0: return 0;
            default: break;
        }
        printf("\nPress Enter to continue...");
        getchar();
        system("cls");
    }
}
