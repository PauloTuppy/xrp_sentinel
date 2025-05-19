#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>

// Nota: Esta implementação assume que OpenSSL foi compilado com suporte a algoritmos pós-quânticos
// como CRYSTALS-Kyber e CRYSTALS-Dilithium

class PostQuantumCrypto {
private:
    // Smart pointers para gerenciamento seguro de recursos
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> gen_ctx;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key_pair;
    
    void handle_openssl_error(const std::string& operation) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        throw std::runtime_error(operation + " failed: " + err_buf);
    }

public:
    PostQuantumCrypto() 
        : gen_ctx(nullptr, EVP_PKEY_CTX_free),
          key_pair(nullptr, EVP_PKEY_free) {
        // Inicializar OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        
        // Criar contexto para geração de chaves Kyber
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KYBER, nullptr);
        if (!ctx) {
            handle_openssl_error("Kyber context creation");
        }
        gen_ctx.reset(ctx);
        
        // Configurar para Kyber-1024 (nível de segurança mais alto)
        if (EVP_PKEY_keygen_init(gen_ctx.get()) <= 0) {
            handle_openssl_error("Kyber keygen initialization");
        }
        
        if (EVP_PKEY_CTX_set_kyber_security_level(gen_ctx.get(), 5) <= 0) {
            handle_openssl_error("Setting Kyber security level");
        }
        
        // Gerar par de chaves
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(gen_ctx.get(), &pkey) <= 0) {
            handle_openssl_error("Kyber key generation");
        }
        key_pair.reset(pkey);
    }
    
    ~PostQuantumCrypto() {
        EVP_cleanup();
        ERR_free_strings();
    }
    
    // Encriptação híbrida (clássica + pós-quântica)
    std::vector<unsigned char> hybrid_encrypt(const std::vector<unsigned char>& data) {
        // Usar Kyber para encriptar uma chave AES
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
            EVP_PKEY_CTX_new(key_pair.get(), nullptr), EVP_PKEY_CTX_free);
        
        if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
            handle_openssl_error("Kyber encrypt init");
        }
        
        // Determinar tamanho do buffer necessário
        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outlen, data.data(), data.size()) <= 0) {
            handle_openssl_error("Kyber encrypt sizing");
        }
        
        // Realizar encriptação
        std::vector<unsigned char> encrypted(outlen);
        if (EVP_PKEY_encrypt(ctx.get(), encrypted.data(), &outlen, data.data(), data.size()) <= 0) {
            handle_openssl_error("Kyber encryption");
        }
        
        encrypted.resize(outlen);
        return encrypted;
    }
    
    std::vector<unsigned char> hybrid_decrypt(const std::vector<unsigned char>& ciphertext) {
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
            EVP_PKEY_CTX_new(key_pair.get(), nullptr), EVP_PKEY_CTX_free);
        
        if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
            handle_openssl_error("Kyber decrypt init");
        }
        
        // Determinar tamanho do buffer necessário
        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
            handle_openssl_error("Kyber decrypt sizing");
        }
        
        // Realizar decriptação
        std::vector<unsigned char> decrypted(outlen);
        if (EVP_PKEY_decrypt(ctx.get(), decrypted.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
            handle_openssl_error("Kyber decryption");
        }
        
        decrypted.resize(outlen);
        return decrypted;
    }
    
    // Assinatura pós-quântica usando Dilithium
    std::vector<unsigned char> quantum_sign(const std::vector<unsigned char>& data) {
        // Criar contexto para Dilithium
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> dil_ctx(
            EVP_PKEY_CTX_new_id(EVP_PKEY_DILITHIUM, nullptr), EVP_PKEY_CTX_free);
        
        if (!dil_ctx || EVP_PKEY_keygen_init(dil_ctx.get()) <= 0) {
            handle_openssl_error("Dilithium init");
        }
        
        // Gerar par de chaves Dilithium
        EVP_PKEY* dil_key = nullptr;
        if (EVP_PKEY_keygen(dil_ctx.get(), &dil_key) <= 0) {
            handle_openssl_error("Dilithium key generation");
        }
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> dilithium_key(dil_key, EVP_PKEY_free);
        
        // Criar contexto de assinatura
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx(
            EVP_MD_CTX_new(), EVP_MD_CTX_free);
        
        if (!md_ctx || EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, dilithium_key.get()) <= 0) {
            handle_openssl_error("Dilithium sign init");
        }
        
        // Determinar tamanho da assinatura
        size_t sig_len = 0;
        if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len, data.data(), data.size()) <= 0) {
            handle_openssl_error("Dilithium sign sizing");
        }
        
        // Realizar assinatura
        std::vector<unsigned char> signature(sig_len);
        if (EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len, data.data(), data.size()) <= 0) {
            handle_openssl_error("Dilithium signing");
        }
        
        signature.resize(sig_len);
        return signature;
    }
    
    bool verify_quantum_signature(const std::vector<unsigned char>& data, 
                                 const std::vector<unsigned char>& signature,
                                 EVP_PKEY* public_key) {
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx(
            EVP_MD_CTX_new(), EVP_MD_CTX_free);
        
        if (!md_ctx || EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, public_key) <= 0) {
            handle_openssl_error("Dilithium verify init");
        }
        
        int ret = EVP_DigestVerify(md_ctx.get(), signature.data(), signature.size(), 
                                  data.data(), data.size());
        
        if (ret < 0) {
            handle_openssl_error("Dilithium verification");
        }
        
        return (ret == 1);
    }
    
    // Métodos para exportar/importar chaves públicas
    std::vector<unsigned char> export_public_key() {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
        if (!bio || PEM_write_bio_PUBKEY(bio.get(), key_pair.get()) <= 0) {
            handle_openssl_error("Exporting public key");
        }
        
        char* data = nullptr;
        long len = BIO_get_mem_data(bio.get(), &data);
        return std::vector<unsigned char>(data, data + len);
    }
};
