// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title RewardCalculator
 * @dev Handles reward calculations for different components
 */
contract RewardCalculator {
    // Precision for fixed-point arithmetic
    uint256 private constant PRECISION = 1e18;
    
    struct NodeReward {
        uint256 validationReward;
        uint256 executionReward;
        uint256 totalReward;
        bool isPaid;
    }
    
    struct ChannelReward {
        uint256 baseReward;
        uint256 performanceMultiplier;
        uint256 totalReward;
        bool isPaid;
    }
    
    struct AuxiliaryReward {
        uint256 componentReward;
        uint256 criticalityFactor;
        uint256 totalReward;
        bool isPaid;
    }
    
    // Reward mappings
    mapping(address => NodeReward) public nodeRewards;
    mapping(bytes32 => ChannelReward) public channelRewards;
    mapping(bytes32 => AuxiliaryReward) public auxiliaryRewards;
    
    // Weight constants
    uint256 public constant W1_VALIDATION = 600; // 0.6 * PRECISION
    uint256 public constant W2_EXECUTION = 400;  // 0.4 * PRECISION
    
    /**
     * @dev Calculates individual node reward
     * Di = w1 * Validation + w2 * Execution
     */
    function calculateNodeReward(
        address node,
        uint256 validationScore,
        uint256 executionScore
    ) internal returns (uint256) {
        uint256 validationComponent = (validationScore * W1_VALIDATION) / PRECISION;
        uint256 executionComponent = (executionScore * W2_EXECUTION) / PRECISION;
        
        uint256 totalReward = validationComponent + executionComponent;
        
        nodeRewards[node] = NodeReward({
            validationReward: validationComponent,
            executionReward: executionComponent,
            totalReward: totalReward,
            isPaid: false
        });
        
        return totalReward;
    }
}

/**
 * @title RewardDistributor
 * @dev Manages the distribution of rewards across different components
 */
contract RewardDistributor is RewardCalculator, ReentrancyGuard, AccessControl {
    IERC20 public rewardToken;
    
    struct DistributionState {
        uint256 channelShare;
        uint256 nodeShare;
        uint256 auxiliaryShare;
        uint256 totalDistributed;
        bool isComplete;
    }
    
    mapping(bytes32 => DistributionState) public distributions;
    
    event RewardDistributed(
        bytes32 indexed distributionId,
        address recipient,
        uint256 amount
    );
    
    constructor(address _rewardToken) {
        rewardToken = IERC20(_rewardToken);
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
    
    /**
     * @dev Calculates channel rewards
     * Dchannel = Σ(ωi * γi * φchannel(xi))
     */
    function calculateChannelReward(
        bytes32 channelId,
        uint256[] memory weights,
        uint256[] memory scalingFactors,
        uint256[] memory performances
    ) public returns (uint256) {
        require(
            weights.length == scalingFactors.length &&
            weights.length == performances.length,
            "Array lengths mismatch"
        );
        
        uint256 totalReward = 0;
        
        for (uint256 i = 0; i < weights.length; i++) {
            uint256 componentReward = multiplyFixedPoint(
                multiplyFixedPoint(weights[i], scalingFactors[i]),
                performances[i]
            );
            totalReward = addFixedPoint(totalReward, componentReward);
        }
        
        channelRewards[channelId] = ChannelReward({
            baseReward: totalReward,
            performanceMultiplier: calculatePerformanceMultiplier(performances),
            totalReward: totalReward,
            isPaid: false
        });
        
        return totalReward;
    }
    
    /**
     * @dev Calculates node rewards
     * Dnodes = λ * (Πδj) * Pcontribution
     */
    function calculateNodesReward(
        uint256 baseConstant,
        uint256[] memory performanceFactors,
        uint256 contributionScore
    ) public pure returns (uint256) {
        uint256 performance = PRECISION;
        
        for (uint256 i = 0; i < performanceFactors.length; i++) {
            performance = multiplyFixedPoint(performance, performanceFactors[i]);
        }
        
        return multiplyFixedPoint(
            multiplyFixedPoint(baseConstant, performance),
            contributionScore
        );
    }
    
    /**
     * @dev Calculates auxiliary rewards
     * Dauxiliary = Σ(βk * σk * ξaux(ck))
     */
    function calculateAuxiliaryReward(
        bytes32 componentId,
        uint256[] memory weights,
        uint256[] memory criticalityFactors,
        uint256[] memory performances
    ) public returns (uint256) {
        require(
            weights.length == criticalityFactors.length &&
            weights.length == performances.length,
            "Array lengths mismatch"
        );
        
        uint256 totalReward = 0;
        
        for (uint256 i = 0; i < weights.length; i++) {
            uint256 componentReward = multiplyFixedPoint(
                multiplyFixedPoint(weights[i], criticalityFactors[i]),
                performances[i]
            );
            totalReward = addFixedPoint(totalReward, componentReward);
        }
        
        auxiliaryRewards[componentId] = AuxiliaryReward({
            componentReward: totalReward,
            criticalityFactor: calculateCriticalityFactor(criticalityFactors),
            totalReward: totalReward,
            isPaid: false
        });
        
        return totalReward;
    }
    
    /**
     * @dev Distributes total rewards
     * Dtotal = Dchannel + Dnodes + Dauxiliary
     */
    function distributeRewards(
        bytes32 distributionId,
        address[] memory recipients,
        uint256[] memory amounts
    ) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            recipients.length == amounts.length,
            "Recipients and amounts length mismatch"
        );
        
        DistributionState storage distribution = distributions[distributionId];
        require(!distribution.isComplete, "Distribution already complete");
        
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalAmount = addFixedPoint(totalAmount, amounts[i]);
        }
        
        require(
            rewardToken.balanceOf(address(this)) >= totalAmount,
            "Insufficient rewards"
        );
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(
                rewardToken.transfer(recipients[i], amounts[i]),
                "Transfer failed"
            );
            emit RewardDistributed(distributionId, recipients[i], amounts[i]);
        }
        
        distribution.totalDistributed = totalAmount;
        distribution.isComplete = true;
    }
    
    // Helper functions
    function calculatePerformanceMultiplier(
        uint256[] memory performances
    ) internal pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < performances.length; i++) {
            sum = addFixedPoint(sum, performances[i]);
        }
        return sum / performances.length;
    }
    
    function calculateCriticalityFactor(
        uint256[] memory factors
    ) internal pure returns (uint256) {
        uint256 product = PRECISION;
        for (uint256 i = 0; i < factors.length; i++) {
            product = multiplyFixedPoint(product, factors[i]);
        }
        return product;
    }
    
    function multiplyFixedPoint(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256) {
        return (a * b) / PRECISION;
    }
    
    function addFixedPoint(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256) {
        return a + b;
    }
}
