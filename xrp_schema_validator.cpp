#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>

class XRPSchemaValidator {
private:
    nlohmann::json schema;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> verificationKey;

    bool validate_json(const nlohmann::json& data) {
        // Implementação existente...
        return true;
    }

    bool verify_signature(const std::string& data, const std::string& sig) {
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx) return false;
        
        if (EVP_VerifyInit(ctx.get(), EVP_sha384()) != 1) return false;
        if (EVP_VerifyUpdate(ctx.get(), data.c_str(), data.size()) != 1) return false;
        
        int result = EVP_VerifyFinal(ctx.get(), 
                     reinterpret_cast<const unsigned char*>(sig.c_str()),
                     sig.size(), verificationKey.get());
                     
        return result == 1;
    }

public:
    XRPSchemaValidator(const std::string& schemaPath, const std::string& pubKey) 
        : verificationKey(nullptr, EVP_PKEY_free) {
        // Inicializar OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        
        // Carregar schema
        std::ifstream schemaFile(schemaPath);
        schema = nlohmann::json::parse(schemaFile);
        
        // Carregar chave pública EC para verificação
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_file(pubKey.c_str(), "r"), BIO_free);
        if (!bio) throw std::runtime_error("Failed to open public key file");
        
        EVP_PKEY* key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
        if (!key) throw std::runtime_error("Failed to load public key");
        
        verificationKey.reset(key);
    }

    ~XRPSchemaValidator() {
        // Cleanup OpenSSL
        EVP_cleanup();
        ERR_free_strings();
    }
};
