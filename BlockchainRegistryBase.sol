// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title BlockchainRegistryBase
 * @dev Base contract containing shared data structures and events
 */
contract BlockchainRegistryBase {
    struct BlockchainInfo {
        string blockchainID;          // Unique identifier for the blockchain
        string dataStructure;         // Data structure format
        string programmingLanguage;   // Primary programming language
        string networkProtocol;       // Network protocol format
        uint256 currentState;         // Current state of the blockchain
        uint256 registrationTime;     // When the blockchain was registered
        bool isActive;                // Whether the blockchain is currently active
        mapping(bytes32 => bool) metRequirements;  // Track which requirements are met
    }

    // Events
    event BlockchainRegistered(string indexed blockchainID, uint256 timestamp);
    event BlockchainDeactivated(string indexed blockchainID, uint256 timestamp);
    event RequirementUpdated(string indexed blockchainID, bytes32 requirement, bool met);
    event SecurityAlertRaised(string indexed blockchainID, string alertType, uint256 timestamp);
    
    // Mapping from blockchain ID to its information
    mapping(string => BlockchainInfo) public registeredBlockchains;
    
    // Array to keep track of all registered blockchain IDs
    string[] public allBlockchainIDs;
    
    // Required characteristics for registration
    bytes32[] public registrationRequirements;
}

/**
 * @title BlockchainRegistry
 * @dev Handles the registration of blockchains in the PAYS system
 */
contract BlockchainRegistry is BlockchainRegistryBase, Ownable, Pausable, ReentrancyGuard {
    constructor() {
        // Initialize default registration requirements
        registrationRequirements.push(keccak256("VALID_CONSENSUS"));
        registrationRequirements.push(keccak256("SECURE_PROTOCOL"));
        registrationRequirements.push(keccak256("HEADER_VERIFICATION"));
    }

    /**
     * @dev Register a new blockchain with the system
     */
    function registerBlockchain(
        string memory _blockchainID,
        string memory _dataStructure,
        string memory _programmingLanguage,
        string memory _networkProtocol
    ) external whenNotPaused nonReentrant {
        require(bytes(_blockchainID).length > 0, "Invalid blockchain ID");
        require(!registeredBlockchains[_blockchainID].isActive, "Already registered");

        BlockchainInfo storage newChain = registeredBlockchains[_blockchainID];
        newChain.blockchainID = _blockchainID;
        newChain.dataStructure = _dataStructure;
        newChain.programmingLanguage = _programmingLanguage;
        newChain.networkProtocol = _networkProtocol;
        newChain.registrationTime = block.timestamp;
        newChain.isActive = true;
        
        allBlockchainIDs.push(_blockchainID);
        
        emit BlockchainRegistered(_blockchainID, block.timestamp);
    }

    /**
     * @dev Update requirement status for a blockchain
     */
    function updateRequirementStatus(
        string memory _blockchainID,
        bytes32 _requirement,
        bool _met
    ) external onlyOwner {
        require(registeredBlockchains[_blockchainID].isActive, "Blockchain not registered");
        
        registeredBlockchains[_blockchainID].metRequirements[_requirement] = _met;
        emit RequirementUpdated(_blockchainID, _requirement, _met);
    }

    /**
     * @dev Deactivate a blockchain registration
     */
    function deactivateBlockchain(string memory _blockchainID) external onlyOwner {
        require(registeredBlockchains[_blockchainID].isActive, "Blockchain not active");
        
        registeredBlockchains[_blockchainID].isActive = false;
        emit BlockchainDeactivated(_blockchainID, block.timestamp);
    }
}

/**
 * @title BlockchainMonitor
 * @dev Monitors registered blockchains for security and connectivity
 */
contract BlockchainMonitor is BlockchainRegistry {
    struct MonitoringInfo {
        uint256 lastCheckTimestamp;
        uint256 connectionQuality;    // 0-100 scale
        uint256 securityScore;        // 0-100 scale
        bool isConnected;
    }

    mapping(string => MonitoringInfo) public blockchainMonitoring;

    event ConnectionStatusUpdated(string indexed blockchainID, bool connected, uint256 quality);
    event SecurityScoreUpdated(string indexed blockchainID, uint256 score);

    /**
     * @dev Update monitoring information for a blockchain
     */
    function updateMonitoringInfo(
        string memory _blockchainID,
        bool _isConnected,
        uint256 _connectionQuality,
        uint256 _securityScore
    ) external onlyOwner {
        require(registeredBlockchains[_blockchainID].isActive, "Blockchain not active");
        require(_connectionQuality <= 100, "Invalid connection quality");
        require(_securityScore <= 100, "Invalid security score");

        MonitoringInfo storage info = blockchainMonitoring[_blockchainID];
        info.lastCheckTimestamp = block.timestamp;
        info.isConnected = _isConnected;
        info.connectionQuality = _connectionQuality;
        info.securityScore = _securityScore;

        emit ConnectionStatusUpdated(_blockchainID, _isConnected, _connectionQuality);
        emit SecurityScoreUpdated(_blockchainID, _securityScore);

        // Raise security alert if score is too low
        if (_securityScore < 50) {
            emit SecurityAlertRaised(_blockchainID, "LOW_SECURITY_SCORE", block.timestamp);
        }
    }

    /**
     * @dev Get monitoring information for a blockchain
     */
    function getMonitoringInfo(string memory _blockchainID) 
        external 
        view 
        returns (
            uint256 lastCheck,
            bool connected,
            uint256 connectionQuality,
            uint256 securityScore
        )
    {
        MonitoringInfo storage info = blockchainMonitoring[_blockchainID];
        return (
            info.lastCheckTimestamp,
            info.isConnected,
            info.connectionQuality,
            info.securityScore
        );
    }
}
