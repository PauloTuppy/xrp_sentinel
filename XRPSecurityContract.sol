// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title XRPSecurityContract
 * @dev Contrato para verificação segura de transações XRP
 */
contract XRPSecurityContract is ReentrancyGuard, AccessControl, Pausable {
    using ECDSA for bytes32;

    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    
    uint256 public constant VERIFICATION_TIMEOUT = 1 hours;
    uint256 public constant MAX_TRANSACTION_VALUE = 100000 * 10**6; // 100,000 XRP em drops
    
    struct Transaction {
        bytes32 schemaHash;      // Hash do schema da transação
        bytes32 contentHash;     // Hash do conteúdo da transação
        address sender;          // Endereço que enviou a transação
        uint256 timestamp;       // Timestamp da verificação
        bool isValid;            // Resultado da verificação
        uint8 validationLevel;   // Nível de validação (1-5)
        string ipfsMetadata;     // Referência IPFS para metadados adicionais
    }
    
    // Mapeamento principal de transações
    mapping(bytes32 => Transaction) public transactions;
    
    // Mapeamento de endereços para listas de transações
    mapping(address => bytes32[]) public userTransactions;
    
    // Mapeamento de hashes em lista negra
    mapping(bytes32 => bool) public blacklistedHashes;
    
    // Contador de transações para estatísticas
    uint256 public transactionCount;
    
    // Eventos
    event TransactionVerified(bytes32 indexed txid, bool isValid, uint8 validationLevel);
    event BlacklistUpdated(bytes32 hash, bool isBlacklisted);
    event EmergencyShutdown(address triggeredBy, uint256 timestamp);
    event ValidationThresholdUpdated(uint8 newThreshold);
    
    // Modificadores
    modifier onlyValidator() {
        require(hasRole(VALIDATOR_ROLE, msg.sender), "Caller is not a validator");
        _;
    }
    
    modifier validTransactionValue(uint256 value) {
        require(value <= MAX_TRANSACTION_VALUE, "Transaction value exceeds maximum");
        _;
    }
    
    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ADMIN_ROLE, msg.sender);
        _setupRole(EMERGENCY_ROLE, msg.sender);
        _setupRole(VALIDATOR_ROLE, msg.sender);
    }
    
    /**
     * @dev Verifica uma transação XRP
     * @param schemaHash Hash do schema da transação
     * @param contentHash Hash do conteúdo da transação
     * @param signature Assinatura da transação
     * @param value Valor da transação em drops
     * @param ipfsMetadata Referência IPFS para metadados adicionais
     */
    function verifyTransaction(
        bytes32 schemaHash,
        bytes32 contentHash,
        bytes calldata signature,
        uint256 value,
        string calldata ipfsMetadata
    ) 
        external 
        nonReentrant 
        whenNotPaused 
        validTransactionValue(value) 
        returns (bytes32)
    {
        // Criar ID único para a transação
        bytes32 txid = keccak256(abi.encodePacked(
            schemaHash, 
            contentHash, 
            msg.sender, 
            block.timestamp
        ));
        
        // Verificar se a transação já existe
        require(transactions[txid].timestamp == 0, "Transaction already exists");
        
        // Verificar se algum hash está na lista negra
        require(!blacklistedHashes[schemaHash], "Schema hash is blacklisted");
        require(!blacklistedHashes[contentHash], "Content hash is blacklisted");
        
        // Verificação criptográfica da assinatura
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked(schemaHash, contentHash, value)
        ).toEthSignedMessageHash();
        
        address recovered = ethSignedMessageHash.recover(signature);
        require(recovered != address(0), "Invalid signature");
        require(recovered == msg.sender, "Signer mismatch");
        
        // Determinar nível de validação com base no valor e outros fatores
        uint8 validationLevel = determineValidationLevel(value);
        
        // Verificar conformidade regulatória
        bool isValid = checkCompliance(schemaHash, contentHash, value);
        
        // Armazenar a transação
        transactions[txid] = Transaction({
            schemaHash: schemaHash,
            contentHash: contentHash,
            sender: msg.sender,
            timestamp: block.timestamp,
            isValid: isValid,
            validationLevel: validationLevel,
            ipfsMetadata: ipfsMetadata
        });
        
        // Adicionar à lista de transações do usuário
        userTransactions[msg.sender].push(txid);
        
        // Incrementar contador
        transactionCount++;
        
        // Emitir evento
        emit TransactionVerified(txid, isValid, validationLevel);
        
        return txid;
    }
    
    /**
     * @dev Determina o nível de validação necessário com base no valor
     * @param value Valor da transação em drops
     * @return Nível de validação (1-5)
     */
    function determineValidationLevel(uint256 value) internal pure returns (uint8) {
        if (value < 1000 * 10**6) return 1; // < 1,000 XRP
        if (value < 10000 * 10**6) return 2; // < 10,000 XRP
        if (value < 50000 * 10**6) return 3; // < 50,000 XRP
        if (value < 100000 * 10**6) return 4; // < 100,000 XRP
        return 5; // >= 100,000 XRP
    }
    
    /**
     * @dev Verifica a conformidade regulatória da transação
     * @param schemaHash Hash do schema da transação
     * @param contentHash Hash do conteúdo da transação
     * @param value Valor da transação
     * @return Resultado da verificação
     */
    function checkCompliance(
        bytes32 schemaHash, 
        bytes32 contentHash, 
        uint256 value
    ) 
        internal 
        pure 
        returns (bool) 
    {
        // Implementação de verificações regulatórias
        // Na implementação real, isso consultaria oráculos ou APIs externas
        
        // Verificações básicas de exemplo
        if (value > 50000 * 10**6) {
            // Transações de alto valor exigem verificações adicionais
            return contentHash != bytes32(0);
        }
        
        return true;
    }
    
    /**
     * @dev Adiciona um hash à lista negra
     * @param hash Hash a ser adicionado
     */
    function addToBlacklist(bytes32 hash) external onlyRole(ADMIN_ROLE) {
        blacklistedHashes[hash] = true;
        emit BlacklistUpdated(hash, true);
    }
    
    /**
     * @dev Remove um hash da lista negra
     * @param hash Hash a ser removido
     */
    function removeFromBlacklist(bytes32 hash) external onlyRole(ADMIN_ROLE) {
        blacklistedHashes[hash] = false;
        emit BlacklistUpdated(hash, false);
    }
    
    /**
     * @dev Ativa o modo de emergência, pausando o contrato
     */
    function triggerEmergencyShutdown() external onlyRole(EMERGENCY_ROLE) {
        _pause();
        emit EmergencyShutdown(msg.sender, block.timestamp);
    }
    
    /**
     * @dev Desativa o modo de emergência, retomando o contrato
     */
    function resumeOperations() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }
    
    /**
     * @dev Obtém todas as transações de um usuário
     * @param user Endereço do usuário
     * @return Array de IDs de transação
     */
    function getUserTransactions(address user) external view returns (bytes32[] memory) {
        return userTransactions[user];
    }
    
    /**
     * @dev Verifica se uma transação expirou
     * @param txid ID da transação
     * @return Resultado da verificação
     */
    function isTransactionExpired(bytes32 txid) external view returns (bool) {
        Transaction memory tx = transactions[txid];
        return tx.timestamp > 0 && (block.timestamp - tx.timestamp) > VERIFICATION_TIMEOUT;
    }
}