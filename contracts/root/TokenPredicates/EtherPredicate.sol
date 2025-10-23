pragma solidity 0.6.6;

import {AccessControlMixin} from "../../common/AccessControlMixin.sol";
import {RLPReader} from "../../lib/RLPReader.sol";
import {ITokenPredicate} from "./ITokenPredicate.sol";
import {Initializable} from "../../common/Initializable.sol";

contract EtherPredicate is ITokenPredicate, AccessControlMixin, Initializable {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant TOKEN_TYPE = keccak256("Ether");
    bytes32 public constant TRANSFER_EVENT_SIG = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef;

    // Mapping to track posthack deposits: user => token => amount
    // Used to differentiate between prehack victims and posthack depositors
    mapping(address => mapping(address => uint256)) public postHackDeposits;

    // SOU address
    address public souContract;
    // WETH contract address to represent ether on SOU | TODO: update for mainnet
    address public constant WETH = 0xF7CA820332Db9eFd8f1d724747732ccf4B432006;

    event LockedEther(
        address indexed depositor,
        address indexed depositReceiver,
        uint256 amount
    );

    event ExitedEther(
        address indexed exitor,
        uint256 amount
    );

    constructor() public {}

    function initialize(address _owner) external initializer {
        _setupContractId("EtherPredicate");
        _setupRole(DEFAULT_ADMIN_ROLE, _owner);
        _setupRole(MANAGER_ROLE, _owner);
    }

    /**
     * @notice Receive Ether to lock for deposit, callable only by manager
     */
    receive() external payable only(MANAGER_ROLE) {}

    /**
     * @notice handle ether lock, callable only by manager
     * @param depositor Address who wants to deposit tokens
     * @param depositReceiver Address (address) who wants to receive tokens on child chain
     * @param depositData ABI encoded amount
     */
    function lockTokens(
        address depositor,
        address depositReceiver,
        address,
        bytes calldata depositData
    )
        external
        override
        only(MANAGER_ROLE)
    {
        uint256 amount = abi.decode(depositData, (uint256));
        emit LockedEther(depositor, depositReceiver, amount);
        postHackDeposits[depositor][WETH] += amount;
    }

    /**
     * @notice Validates log signature, from and to address
     * then sends the correct amount to withdrawer
     * callable only by manager
     * @param log Valid ERC20 burn log from child chain
     */
    function exitTokens(
        address,
        bytes calldata log
    )
        external
        override
        only(MANAGER_ROLE)
    {
        RLPReader.RLPItem[] memory logRLPList = log.toRlpItem().toList();
        RLPReader.RLPItem[] memory logTopicRLPList = logRLPList[1].toList(); // topics

        require(
            bytes32(logTopicRLPList[0].toUint()) == TRANSFER_EVENT_SIG, // topic0 is event sig
            "EtherPredicate: INVALID_SIGNATURE"
        );

        address withdrawer = address(logTopicRLPList[1].toUint()); // topic1 is from address

        require(
            address(logTopicRLPList[2].toUint()) == address(0), // topic2 is to address
            "EtherPredicate: INVALID_RECEIVER"
        );

        uint256 amount = logRLPList[2].toUint(); // log data field is the amount

        uint256 postHackBalance = postHackDeposits[withdrawer][WETH];

        // Determine how much ether to send and whether to mint SOU
        uint256 etherToSend;
        uint256 souAmount;

        if (postHackBalance >= amount) {
            // User deposited enough posthack, exit full amount
            etherToSend = amount;
            souAmount = 0;
            // Updating state before external call
            postHackDeposits[withdrawer][WETH] = postHackBalance - amount;
        } else if (postHackBalance == 0) {
            // All prehack funds, mint full SOU and exit zero ether
            etherToSend = 0;
            souAmount = amount;
        } else {
            // Partial: some posthack, some prehack
            etherToSend = postHackBalance;
            souAmount = amount - postHackBalance;
            // Updating state before external call
            postHackDeposits[withdrawer][WETH] = 0;
        }

        emit ExitedEther(withdrawer, amount);

        // Mint SOU if needed
        if (souAmount > 0) {
            _mintSOU(withdrawer, WETH, souAmount);
        }
        // Transfer ether if needed
        if (etherToSend > 0) {
            (bool success, ) = withdrawer.call{value: etherToSend}("");
            if (!success) {
                revert("EtherPredicate: ETHER_TRANSFER_FAILED");
            }

        }
    }

    /**
     * @notice Set the SOU contract address
     * @param _souContract Address of the SOU contract
     */
    function setSOUContract(address _souContract) external only(MANAGER_ROLE) {
        require(_souContract != address(0), "SOUAdapter: INVALID_SOU_ADDRESS");
        souContract = _souContract;
    }

    /**
     * @notice Mint SOU NFT for bridge compensation
     * @param user Address of the user to receive the SOU NFT
     * @param token Address of the token being compensated
     * @param amount Amount of tokens being compensated
     * @return tokenId The ID of the minted SOU NFT (0 if failed)
     */
    function _mintSOU(
        address user,
        address token,
        uint256 amount
    ) private returns (uint256) {
        require(user != address(0), "SOUAdapter: INVALID_USER");
        require(token != address(0), "SOUAdapter: INVALID_TOKEN");
        require(amount > 0, "SOUAdapter: INVALID_AMOUNT");
        require(souContract != address(0), "SOUAdapter: SOU_NOT_SET");

        // Call: handleBridgeCompensation(address to, address bridgedToken, uint256 bridgedAmount)
        (bool success, bytes memory returnData) = souContract.call(
            abi.encodeWithSignature(
                "handleBridgeCompensation(address,address,uint256)",
                user,
                token,
                amount
            )
        );

        if (success && returnData.length >= 32) {
            uint256 tokenId = abi.decode(returnData, (uint256));
            return tokenId;
        } else {
            revert("EtherPredicate: SOU_MINT_FAILED");
        }
    }


}
