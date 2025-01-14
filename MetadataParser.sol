// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

/**
 * @title MetadataParser
 * @dev Handles parsing and preparation of cross-chain transaction metadata
 */
contract MetadataParser is ReentrancyGuard {
    using Counters for Counters.Counter;
    
    struct ProtocolInstruction {
        bytes32 originalProtocol;     // Original protocol identifier (Λ)
        bytes32 convertedProtocol;    // Converted protocol identifier (Λ')
        mapping(bytes32 => bytes32) opcodeMapping;  // Mapping of opcodes between protocols
    }

    struct ParsedMetadata {
        bytes32 transactionId;
        address sender;
        address recipient;
        uint256 timestamp;
        bytes32 sourceProtocol;
        bytes32 targetProtocol;
        bytes encryptedPayload;
        bytes authTag;
        bool isSpeculative;
        TransactionStatus status;
    }

    struct IRNode {
        bytes32 nodeType;
        bytes value;
        bytes32[] childrenIds;
        mapping(bytes32 => bytes32) keyValuePairs;
    }

    enum TransactionStatus {
        Pending,
        Speculative,
        Confirmed,
        Failed
    }

    // State variables
    mapping(bytes32 => ParsedMetadata) public parsedTransactions;
    mapping(bytes32 => ProtocolInstruction) public protocolInstructions;
    mapping(bytes32 => IRNode) public irNodes;
    Counters.Counter private _transactionIdCounter;

    // Events
    event MetadataParsed(bytes32 indexed transactionId, bool isSpeculative);
    event ProtocolConverted(bytes32 indexed originalProtocol, bytes32 indexed convertedProtocol);
    event TransactionStatusUpdated(bytes32 indexed transactionId, TransactionStatus status);

    /**
     * @dev Prepare transaction metadata for parsing
     */
    function prepareTransactionMetadata(
        address _recipient,
        bytes32 _sourceProtocol,
        bytes32 _targetProtocol,
        bytes calldata _payload,
        bool _isSpeculative
    ) external nonReentrant returns (bytes32) {
        bytes32 transactionId = generateTransactionId();
        
        ParsedMetadata storage metadata = parsedTransactions[transactionId];
        metadata.transactionId = transactionId;
        metadata.sender = msg.sender;
        metadata.recipient = _recipient;
        metadata.timestamp = block.timestamp;
        metadata.sourceProtocol = _sourceProtocol;
        metadata.targetProtocol = _targetProtocol;
        metadata.isSpeculative = _isSpeculative;
        metadata.status = TransactionStatus.Pending;

        // Parse and encrypt payload
        (bytes memory encryptedPayload, bytes memory authTag) = encryptPayload(_payload);
        metadata.encryptedPayload = encryptedPayload;
        metadata.authTag = authTag;

        emit MetadataParsed(transactionId, _isSpeculative);
        return transactionId;
    }

    /**
     * @dev Parse data into IR nodes
     */
    function parseToIRNode(
        bytes32 _nodeId,
        bytes32 _nodeType,
        bytes calldata _value
    ) external returns (bytes32) {
        IRNode storage node = irNodes[_nodeId];
        node.nodeType = _nodeType;
        node.value = _value;
        return _nodeId;
    }

    /**
     * @dev Add key-value pair to IR node
     */
    function addKeyValueToNode(
        bytes32 _nodeId,
        bytes32 _key,
        bytes32 _value
    ) external {
        IRNode storage node = irNodes[_nodeId];
        node.keyValuePairs[_key] = _value;
    }

    /**
     * @dev Convert protocol instructions
     */
    function convertProtocolInstructions(
        bytes32 _originalProtocol,
        bytes32 _targetProtocol,
        bytes32[] calldata _opcodes,
        bytes32[] calldata _convertedOpcodes
    ) external {
        require(_opcodes.length == _convertedOpcodes.length, "Array length mismatch");
        
        ProtocolInstruction storage instruction = protocolInstructions[_originalProtocol];
        instruction.originalProtocol = _originalProtocol;
        instruction.convertedProtocol = _targetProtocol;

        for (uint i = 0; i < _opcodes.length; i++) {
            instruction.opcodeMapping[_opcodes[i]] = _convertedOpcodes[i];
        }

        emit ProtocolConverted(_originalProtocol, _targetProtocol);
    }

    /**
     * @dev Update transaction status
     */
    function updateTransactionStatus(
        bytes32 _transactionId,
        TransactionStatus _status
    ) external {
        require(parsedTransactions[_transactionId].sender != address(0), "Transaction not found");
        parsedTransactions[_transactionId].status = _status;
        emit TransactionStatusUpdated(_transactionId, _status);
    }

    /**
     * @dev Generate unique transaction ID
     */
    function generateTransactionId() private returns (bytes32) {
        _transactionIdCounter.increment();
        return keccak256(abi.encodePacked(block.timestamp, msg.sender, _transactionIdCounter.current()));
    }

    /**
     * @dev Encrypt payload using ChaCha20-Poly1305 (mock implementation)
     * In production, this would interface with an external encryption service
     */
    function encryptPayload(bytes calldata _payload) private pure returns (bytes memory, bytes memory) {
        // Mock implementation - in production, implement actual ChaCha20-Poly1305 encryption
        bytes memory encryptedPayload = _payload; // Placeholder
        bytes memory authTag = abi.encodePacked(keccak256(_payload)); // Placeholder
        return (encryptedPayload, authTag);
    }
}
