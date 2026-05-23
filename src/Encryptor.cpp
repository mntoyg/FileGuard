#include "Encryptor.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <numeric>
#include <stdexcept>
#include <string>

namespace {

constexpr std::array<uint8_t, 256> SBOX = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

constexpr std::array<uint8_t, 16> PERM = {
    0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
};

// Hardcoded to avoid MSVC constexpr lambda issues
// INV_PERM[PERM[i]] = i
constexpr std::array<uint8_t, 16> INV_PERM = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3
};

// Computed at runtime to avoid MSVC constexpr lambda issues
const std::array<uint8_t, 256>& getInvSbox() {
    static std::array<uint8_t, 256> inv{};
    static bool ready = false;
    if (!ready) {
        for (int i = 0; i < 256; ++i)
            inv[SBOX[i]] = static_cast<uint8_t>(i);
        ready = true;
    }
    return inv;
}

void secureWipe(void* ptr, std::size_t len) noexcept {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (std::size_t i = 0; i < len; ++i)
        p[i] = 0;
}

std::array<uint8_t, fg::KEY_SCHEDULE_BYTES>
deriveKeySchedule(std::string_view passphrase) {
    std::array<uint8_t, fg::KEY_SCHEDULE_BYTES> sched{};
    sched.fill(0x5A);

    for (std::size_t i = 0; i < passphrase.size(); ++i)
        sched[i % fg::KEY_SCHEDULE_BYTES] ^= static_cast<uint8_t>(passphrase[i]);

    for (int round = 0; round < 32; ++round)
        for (std::size_t j = 0; j < fg::KEY_SCHEDULE_BYTES; ++j)
            sched[j] = SBOX[sched[j] ^ sched[(j + 1) % fg::KEY_SCHEDULE_BYTES]];

    return sched;
}

} // anonymous namespace

namespace fg {

SecureKey::SecureKey(std::string_view passphrase) {
    bytes = deriveKeySchedule(passphrase);
}

void SecureKey::wipe() noexcept {
    secureWipe(bytes.data(), bytes.size());
}

SecureKey::SecureKey(SecureKey&& other) noexcept : bytes(other.bytes) {
    other.wipe();
}

SecureKey& SecureKey::operator=(SecureKey&& other) noexcept {
    if (this != &other) {
        bytes = other.bytes;
        other.wipe();
    }
    return *this;
}

Encryptor::Encryptor(std::string_view passphrase, Mode mode)
    : key_(passphrase), mode_(mode) {}

std::vector<uint8_t> Encryptor::readFile(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path))
        throw std::runtime_error("File not found: " + path.string());

    if (!std::filesystem::is_regular_file(path))
        throw std::runtime_error("Not a regular file: " + path.string());

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open())
        throw std::runtime_error("Cannot open file: " + path.string());

    const auto size = std::filesystem::file_size(path);
    std::vector<uint8_t> buf(size);
    if (!ifs.read(reinterpret_cast<char*>(buf.data()),
                  static_cast<std::streamsize>(size)))
        throw std::runtime_error("Read error: " + path.string());

    return buf;
}

void Encryptor::writeFile(const std::filesystem::path& path,
                          const std::vector<uint8_t>&  data) {
    if (path.has_parent_path())
        std::filesystem::create_directories(path.parent_path());

    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open())
        throw std::runtime_error("Cannot write file: " + path.string());

    ofs.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));

    if (!ofs.good())
        throw std::runtime_error("Write error: " + path.string());
}

void Encryptor::encryptFile(const std::filesystem::path& inputPath,
                            const std::filesystem::path& outputPath) const {
    writeFile(outputPath, encryptBuffer(readFile(inputPath)));
}

void Encryptor::decryptFile(const std::filesystem::path& inputPath,
                            const std::filesystem::path& outputPath) const {
    writeFile(outputPath, decryptBuffer(readFile(inputPath)));
}

std::vector<uint8_t>
Encryptor::encryptBuffer(const std::vector<uint8_t>& plaintext) const {
    const uint32_t origSize = static_cast<uint32_t>(plaintext.size());
    std::vector<uint8_t> output;
    output.reserve(5 + plaintext.size());
    output.push_back(static_cast<uint8_t>(mode_));
    output.push_back(static_cast<uint8_t>(origSize & 0xFF));
    output.push_back(static_cast<uint8_t>((origSize >> 8) & 0xFF));
    output.push_back(static_cast<uint8_t>((origSize >> 16) & 0xFF));
    output.push_back(static_cast<uint8_t>((origSize >> 24) & 0xFF));

    std::vector<uint8_t> cipher;
    switch (mode_) {
        case Mode::XOR: cipher = xorTransform(plaintext); break;
        case Mode::SPN: cipher = spnEncrypt(plaintext);   break;
    }

    output.insert(output.end(), cipher.begin(), cipher.end());
    return output;
}

std::vector<uint8_t>
Encryptor::decryptBuffer(const std::vector<uint8_t>& ciphertext) const {
    constexpr std::size_t HEADER_SIZE = 5;
    if (ciphertext.size() < HEADER_SIZE)
        throw std::runtime_error("Ciphertext too short.");

    const auto storedMode = static_cast<Mode>(ciphertext[0]);
    if (storedMode != mode_)
        throw std::runtime_error("Mode mismatch.");

    const uint32_t origSize =
        static_cast<uint32_t>(ciphertext[1])         |
        (static_cast<uint32_t>(ciphertext[2]) << 8)  |
        (static_cast<uint32_t>(ciphertext[3]) << 16) |
        (static_cast<uint32_t>(ciphertext[4]) << 24);

    const std::vector<uint8_t> payload(ciphertext.begin() + HEADER_SIZE,
                                       ciphertext.end());

    std::vector<uint8_t> plain;
    switch (mode_) {
        case Mode::XOR: plain = xorTransform(payload); break;
        case Mode::SPN: plain = spnDecrypt(payload);   break;
    }

    if (plain.size() < origSize)
        throw std::runtime_error("Decrypted size smaller than expected.");

    plain.resize(origSize);
    return plain;
}

std::vector<uint8_t>
Encryptor::xorTransform(const std::vector<uint8_t>& data) const {
    std::vector<uint8_t> output(data.size());
    for (std::size_t i = 0; i < data.size(); ++i)
        output[i] = data[i] ^ key_.bytes[i % KEY_SCHEDULE_BYTES];
    return output;
}

static std::array<uint8_t, 16>
makeSubKey(const std::array<uint8_t, fg::KEY_SCHEDULE_BYTES>& sched, int round) {
    std::array<uint8_t, 16> subkey{};
    for (int j = 0; j < 16; ++j)
        subkey[j] = sched[(round * 16 + j) % fg::KEY_SCHEDULE_BYTES]
                    ^ static_cast<uint8_t>(round);
    return subkey;
}

void Encryptor::spnRoundEncrypt(std::array<uint8_t, 16>& block, int roundIndex) const {
    for (auto& b : block)
        b = SBOX[b];

    std::array<uint8_t, 16> permuted{};
    for (int i = 0; i < 16; ++i)
        permuted[i] = block[PERM[i]];
    block = permuted;

    const auto subkey = makeSubKey(key_.bytes, roundIndex);
    for (int i = 0; i < 16; ++i)
        block[i] ^= subkey[i];
}

void Encryptor::spnRoundDecrypt(std::array<uint8_t, 16>& block, int roundIndex) const {
    const auto& INV_SBOX = getInvSbox();

    const auto subkey = makeSubKey(key_.bytes, roundIndex);
    for (int i = 0; i < 16; ++i)
        block[i] ^= subkey[i];

    std::array<uint8_t, 16> unpermuted{};
    for (int i = 0; i < 16; ++i)
        unpermuted[i] = block[INV_PERM[i]];
    block = unpermuted;

    for (auto& b : block)
        b = INV_SBOX[b];
}

std::vector<uint8_t>
Encryptor::spnEncrypt(const std::vector<uint8_t>& plaintext) const {
    const std::size_t padLen = 16 - (plaintext.size() % 16);
    std::vector<uint8_t> padded = plaintext;
    padded.insert(padded.end(), padLen, static_cast<uint8_t>(padLen));

    std::vector<uint8_t> output;
    output.reserve(padded.size());

    for (std::size_t offset = 0; offset < padded.size(); offset += 16) {
        std::array<uint8_t, 16> block{};
        std::copy_n(padded.begin() + static_cast<std::ptrdiff_t>(offset), 16, block.begin());

        const auto initKey = makeSubKey(key_.bytes, 0);
        for (int i = 0; i < 16; ++i)
            block[i] ^= initKey[i];

        for (int r = 1; r <= SPN_ROUNDS; ++r)
            spnRoundEncrypt(block, r);

        output.insert(output.end(), block.begin(), block.end());
    }
    return output;
}

std::vector<uint8_t>
Encryptor::spnDecrypt(const std::vector<uint8_t>& ciphertext) const {
    if (ciphertext.size() % 16 != 0)
        throw std::runtime_error("SPN ciphertext length not multiple of 16.");

    std::vector<uint8_t> output;
    output.reserve(ciphertext.size());

    for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        std::array<uint8_t, 16> block{};
        std::copy_n(ciphertext.begin() + static_cast<std::ptrdiff_t>(offset), 16, block.begin());

        for (int r = SPN_ROUNDS; r >= 1; --r)
            spnRoundDecrypt(block, r);

        const auto initKey = makeSubKey(key_.bytes, 0);
        for (int i = 0; i < 16; ++i)
            block[i] ^= initKey[i];

        output.insert(output.end(), block.begin(), block.end());
    }
    return output;
}

} // namespace fg