#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>
#include <mutex>
#include <thread>
#include <chrono>

class QuantumSafeKeyVault {
private:
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key;
    std::mutex access_mutex;
    bool locked = true;
    std::chrono::time_point<std::chrono::steady_clock> last_access;
    const std::chrono::seconds auto_lock_timeout{300}; // 5 minutos
    
    void secure_memzero(void* ptr, size_t len) {
        volatile unsigned char* vptr = static_cast<volatile unsigned char*>(ptr);
        while(len--) *vptr++ = 0;
    }
    
    void check_auto_lock() {
        auto now = std::chrono::steady_clock::now();
        if (!locked && (now - last_access) > auto_lock_timeout) {
            lock();
        }
    }

public:
    QuantumSafeKeyVault(const std::string& keyfile) 
        : key(nullptr, EVP_PKEY_free) {
        // Inicializar OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        
        // Carregar chave usando HSM
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_file(keyfile.c_str(), "r"), BIO_free);
        if (!bio) {
            throw std::runtime_error("Failed to open key file");
        }
        
        EVP_PKEY* raw_key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
        if (!raw_key) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            throw std::runtime_error(std::string("Failed to load private key: ") + err_buf);
        }
        
        key.reset(raw_key);
        locked = false;
        last_access = std::chrono::steady_clock::now();
    }
    
    ~QuantumSafeKeyVault() {
        lock();
        EVP_cleanup();
        ERR_free_strings();
    }

    std::string sign_transaction(const std::string& data) {
        std::lock_guard<std::mutex> guard(access_mutex);
        check_auto_lock();
        
        if(locked) throw std::runtime_error("Vault locked");
        last_access = std::chrono::steady_clock::now();
        
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
            EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx) {
            throw std::runtime_error("Failed to create signature context");
        }
        
        if (EVP_SignInit(ctx.get(), EVP_sha384()) != 1) {
            throw std::runtime_error("Failed to initialize signature");
        }
        
        if (EVP_SignUpdate(ctx.get(), data.c_str(), data.size()) != 1) {
            throw std::runtime_error("Failed to update signature");
        }
        
        std::vector<unsigned char> sig(EVP_PKEY_size(key.get()));
        unsigned int siglen = 0;
        
        if (EVP_SignFinal(ctx.get(), sig.data(), &siglen, key.get()) != 1) {
            throw std::runtime_error("Failed to finalize signature");
        }
        
        sig.resize(siglen);
        return std::string(reinterpret_cast<char*>(sig.data()), siglen);
    }

    void lock() {
        std::lock_guard<std::mutex> guard(access_mutex);
        if (!locked) {
            locked = true;
        }
    }
    
    bool unlock(const std::string& passphrase) {
        std::lock_guard<std::mutex> guard(access_mutex);
        // Implementação real verificaria a passphrase
        if (verify_passphrase(passphrase)) {
            locked = false;
            last_access = std::chrono::steady_clock::now();
            return true;
        }
        return false;
    }
    
private:
    bool verify_passphrase(const std::string& passphrase) {
        // Implementação real de verificação de passphrase
        return !passphrase.empty();
    }
};
