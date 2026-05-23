#include "Encryptor.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

#ifdef _WIN32
  #include <windows.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif

namespace {

void setupConsole() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
}

void printBanner() {
    std::cout << "\n";
    std::cout << "+===================================================+\n";
    std::cout << "|          F I L E G U A R D  v1.0                 |\n";
    std::cout << "|   Educational File Encryption Tool - C++17        |\n";
    std::cout << "|   Modes: XOR Cipher  |  SPN (AES-inspired)        |\n";
    std::cout << "+===================================================+\n";
    std::cout << "\n";
}

void printUsage(const char* progName) {
    std::cout
        << "Usage:\n"
        << "  " << progName << " encrypt <mode> <input_file> <output_file>\n"
        << "  " << progName << " decrypt <mode> <input_file> <output_file>\n"
        << "\nModes:\n"
        << "  xor   XOR stream cipher\n"
        << "  spn   Substitution-Permutation Network\n"
        << "\nExamples:\n"
        << "  " << progName << " encrypt xor data/input.txt data/output.enc\n"
        << "  " << progName << " decrypt xor data/output.enc data/recovered.txt\n";
}

std::string readPassphrase(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string pass;
    std::getline(std::cin, pass);
    return pass;
}

fg::Mode parseMode(const std::string& modeStr) {
    if (modeStr == "xor") return fg::Mode::XOR;
    if (modeStr == "spn") return fg::Mode::SPN;
    throw std::invalid_argument("Unknown mode: '" + modeStr + "'. Use 'xor' or 'spn'.");
}

std::string formatBytes(std::uintmax_t bytes) {
    if (bytes < 1024)      return std::to_string(bytes) + " B";
    if (bytes < 1024*1024) return std::to_string(bytes / 1024) + " KB";
    return std::to_string(bytes / (1024 * 1024)) + " MB";
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    setupConsole();
    printBanner();

    if (argc != 5) {
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }

    const std::string operation = argv[1];
    const std::string modeStr   = argv[2];
    const std::filesystem::path inputPath  = argv[3];
    const std::filesystem::path outputPath = argv[4];

    if (operation != "encrypt" && operation != "decrypt") {
        std::cerr << "[ERROR] First argument must be 'encrypt' or 'decrypt'.\n";
        return EXIT_FAILURE;
    }

    fg::Mode mode{};
    try {
        mode = parseMode(modeStr);
    } catch (const std::invalid_argument& e) {
        std::cerr << "[ERROR] " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    std::string passphrase = readPassphrase("Enter passphrase: ");
    if (passphrase.empty()) {
        std::cerr << "[ERROR] Passphrase cannot be empty.\n";
        return EXIT_FAILURE;
    }

    try {
        fg::Encryptor enc(passphrase, mode);
        for (char& c : passphrase) c = '\0';
        passphrase.clear();

        std::cout << "\n";
        std::cout << "  Operation : " << operation << "\n";
        std::cout << "  Mode      : " << modeStr   << "\n";
        std::cout << "  Input     : " << inputPath.filename().string()  << "\n";
        std::cout << "  Output    : " << outputPath.filename().string() << "\n";
        std::cout << "\n";

        if (operation == "encrypt") {
            enc.encryptFile(inputPath, outputPath);
            std::cout << "[OK] Encryption complete!\n";
            std::cout << "     Input  : " << formatBytes(std::filesystem::file_size(inputPath))  << "\n";
            std::cout << "     Output : " << formatBytes(std::filesystem::file_size(outputPath)) << "\n";
        } else {
            enc.decryptFile(inputPath, outputPath);
            std::cout << "[OK] Decryption complete!\n";
            std::cout << "     Output : " << formatBytes(std::filesystem::file_size(outputPath)) << "\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "[i] Key wiped from memory.\n";
    return EXIT_SUCCESS;
}