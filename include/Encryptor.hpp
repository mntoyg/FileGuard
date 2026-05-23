#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace fg {

inline constexpr std::size_t KEY_SCHEDULE_BYTES = 32;
inline constexpr int SPN_ROUNDS = 10;

enum class Mode : uint8_t {
    XOR = 0x01,
    SPN = 0x02,
};

struct SecureKey {
    std::array<uint8_t, KEY_SCHEDULE_BYTES> bytes{};

    SecureKey() = default;

    explicit SecureKey(std::string_view passphrase);

    void wipe() noexcept;

    ~SecureKey() noexcept { wipe(); }

    SecureKey(const SecureKey&)            = delete;
    SecureKey& operator=(const SecureKey&) = delete;

    SecureKey(SecureKey&&) noexcept;
    SecureKey& operator=(SecureKey&&) noexcept;
};

class Encryptor {
public:
    explicit Encryptor(std::string_view passphrase,
                       Mode mode = Mode::XOR);

    void encryptFile(const std::filesystem::path& inputPath,
                     const std::filesystem::path& outputPath) const;

    void decryptFile(const std::filesystem::path& inputPath,
                     const std::filesystem::path& outputPath) const;

    [[nodiscard]] std::vector<uint8_t>
    encryptBuffer(const std::vector<uint8_t>& plaintext) const;

    [[nodiscard]] std::vector<uint8_t>
    decryptBuffer(const std::vector<uint8_t>& ciphertext) const;

    Encryptor(const Encryptor&)            = delete;
    Encryptor& operator=(const Encryptor&) = delete;
    Encryptor(Encryptor&&)                 = default;
    Encryptor& operator=(Encryptor&&)      = default;

private:
    SecureKey key_;
    Mode      mode_;

    [[nodiscard]] std::vector<uint8_t>
    xorTransform(const std::vector<uint8_t>& data) const;

    [[nodiscard]] std::vector<uint8_t>
    spnEncrypt(const std::vector<uint8_t>& plaintext) const;

    [[nodiscard]] std::vector<uint8_t>
    spnDecrypt(const std::vector<uint8_t>& ciphertext) const;

    void spnRoundEncrypt(std::array<uint8_t, 16>& block,
                         int roundIndex) const;

    void spnRoundDecrypt(std::array<uint8_t, 16>& block,
                         int roundIndex) const;

    [[nodiscard]] static std::vector<uint8_t>
    readFile(const std::filesystem::path& path);

    static void writeFile(const std::filesystem::path& path,
                          const std::vector<uint8_t>& data);
};

}