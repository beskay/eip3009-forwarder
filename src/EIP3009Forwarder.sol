// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title EIP3009Forwarder
 * @author TheGreatAxios
 * @notice A contract that enables gas-less ERC-20 token transfers using EIP-712 signatures.
 * @dev This contract acts as a forwarder for any standard ERC-20 token, allowing a third-party (relayer)
 * to submit a pre-signed authorization to execute a transfer on behalf of a token holder. The token holder
 * must first approve this contract to spend their tokens. This implementation is based on EIP-3009.
 */
contract EIP3009Forwarder is EIP712, ReentrancyGuard {
    using ECDSA for bytes32;

    // =============================================================
    //                           State
    // =============================================================

    /**
     * @notice The immutable address of the underlying ERC-20 token this forwarder interacts with.
     */
    IERC20 public immutable TOKEN;

    /**
     * @dev Mapping to track the usage of an authorization nonce for a specific authorizer.
     * `_authorizationStates[authorizer][nonce] = true` means the nonce has been used (either for a
     * transfer or cancellation) and cannot be used again. This is the primary replay protection mechanism.
     */
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;


    // =============================================================
    //                       EIP-712 Hashes
    // =============================================================

    /**
     * @dev The EIP-712 type hash for the `transferWithAuthorization` function.
     * The signature is created over a structure with these fields.
     */
    bytes32 private constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    /**
     * @dev The EIP-712 type hash for the `receiveWithAuthorization` function.
     * This is a variant of transfer where the recipient (`to`) must be the transaction submitter (`msg.sender`).
     */
    bytes32 private constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    /**
     * @dev The EIP-712 type hash for the `cancelAuthorization` function.
     * Allows an authorizer to invalidate a nonce before it is used.
     */
    bytes32 private constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");


    // =============================================================
    //                           Events
    // =============================================================

    /**
     * @notice Emitted when a signed authorization has been successfully used to execute a transfer.
     * @param authorizer The address that signed the authorization.
     * @param nonce The unique nonce of the authorization that was used.
     */
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    /**
     * @notice Emitted when a signed authorization has been successfully canceled.
     * @param authorizer The address that signed the cancellation.
     * @param nonce The unique nonce of the authorization that was canceled.
     */
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);


    // =============================================================
    //                         Custom Errors
    // =============================================================

    /// @notice The provided signature is invalid or does not match the authorizer.
    error InvalidSignature();
    /// @notice The authorization cannot be executed yet because `block.timestamp` is before `validAfter`.
    error AuthorizationNotYetValid();
    /// @notice The authorization has expired because `block.timestamp` is after `validBefore`.
    error AuthorizationExpired();
    /// @notice The authorization's nonce has already been used or canceled.
    error AuthorizationAlreadyUsed();
    /// @notice An address parameter was the zero address.
    error ZeroAddress();
    /// @notice The `from` address has not approved the forwarder for a sufficient token amount.
    error InsufficientAllowance();
    /// @notice The `from` address does not have a sufficient token balance to complete the transfer.
    error InsufficientBalance();
    /// @notice The provided `validAfter` timestamp is after the `validBefore` timestamp.
    error InvalidAuthorizationDates();


    // =============================================================
    //                         Constructor
    // =============================================================

    /**
     * @notice Initializes the forwarder contract.
     * @param _token The address of the ERC-20 token this forwarder will manage.
     * @param _name The name for the EIP-712 domain separator (e.g., "My Forwardable Token").
     * @param _version The version for the EIP-712 domain separator (e.g., "1").
     */
    constructor(
        address _token,
        string memory _name,
        string memory _version
    ) EIP712(_name, _version) {
        if (_token == address(0)) revert ZeroAddress();
        TOKEN = IERC20(_token);
    }


    // =============================================================
    //                   Authorization Functions
    // =============================================================

    /**
     * @notice Executes a token transfer authorized by a EIP-712 signature.
     * @dev This function can be called by anyone (a "relayer") who possesses a valid signature from the `from` address.
     * The `from` address must have approved this contract to spend at least `value` of their tokens.
     * @param from The address of the token holder who is authorizing the transfer.
     * @param to The address of the recipient.
     * @param value The amount of tokens to transfer.
     * @param validAfter The Unix timestamp after which the authorization is valid.
     * @param validBefore The Unix timestamp before which the authorization expires.
     * @param nonce A unique, user-generated value to prevent replay attacks.
     * @param v The recovery ID of the ECDSA signature.
     * @param r The r-value of the ECDSA signature.
     * @param s The s-value of the ECDSA signature.
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        if (from == address(0) || to == address(0)) revert ZeroAddress();
        if (validAfter > validBefore) revert InvalidAuthorizationDates();
        if (block.timestamp < validAfter) revert AuthorizationNotYetValid();
        if (block.timestamp > validBefore) revert AuthorizationExpired();
        if (_authorizationStates[from][nonce]) revert AuthorizationAlreadyUsed();

        // forge-lint: disable-start(asm-keccak256)
        bytes32 structHash = keccak256(
            abi.encode(
                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );
        // forge-lint: disable-end(asm-keccak256)
        
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(v, r, s);
        
        if (signer != from) revert InvalidSignature();

        // Checks-Effects-Interactions: Update state before external call.
        _authorizationStates[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        if (TOKEN.allowance(from, address(this)) < value) revert InsufficientAllowance();
        if (TOKEN.balanceOf(from) < value) revert InsufficientBalance();

        bool success = TOKEN.transferFrom(from, to, value);
        require(success, "Transfer failed");
    }

    /**
     * @notice Executes a token transfer where the recipient (`to`) must be the transaction submitter (`msg.sender`).
     * @dev This prevents a relayer from front-running the transaction to a different recipient. It is useful
     * when the recipient is intended to be the one submitting and paying for the transaction.
     * @param from The address of the token holder who is authorizing the transfer.
     * @param to The address of the recipient, which must be `msg.sender`.
     * @param value The amount of tokens to transfer.
     * @param validAfter The Unix timestamp after which the authorization is valid.
     * @param validBefore The Unix timestamp before which the authorization expires.
     * @param nonce A unique, user-generated value to prevent replay attacks.
     * @param v The recovery ID of the ECDSA signature.
     * @param r The r-value of the ECDSA signature.
     * @param s The s-value of the ECDSA signature.
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        if (to != msg.sender) revert InvalidSignature();
        if (from == address(0)) revert ZeroAddress();
        if (validAfter > validBefore) revert InvalidAuthorizationDates();
        if (block.timestamp < validAfter) revert AuthorizationNotYetValid();
        if (block.timestamp > validBefore) revert AuthorizationExpired();
        if (_authorizationStates[from][nonce]) revert AuthorizationAlreadyUsed();
        
        // forge-lint: disable-start(asm-keccak256)
        bytes32 structHash = keccak256(
            abi.encode(
                RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
                from,
                to,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );
        // forge-lint: disable-end(asm-keccak256)
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(v, r, s);
        
        if (signer != from) revert InvalidSignature();

        // Checks-Effects-Interactions: Update state before external call.
        _authorizationStates[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);

        if (TOKEN.allowance(from, address(this)) < value) revert InsufficientAllowance();
        if (TOKEN.balanceOf(from) < value) revert InsufficientBalance();

        bool success = TOKEN.transferFrom(from, to, value);
        require(success, "Transfer failed");
    }

    /**
     * @notice Cancels an unused authorization, preventing it from being used in the future.
     * @dev The authorizer must sign a cancellation message for the specific nonce they wish to invalidate.
     * @param authorizer The address that is canceling the authorization.
     * @param nonce The nonce of the authorization to cancel.
     * @param v The recovery ID of the ECDSA signature for the cancellation.
     * @param r The r-value of the ECDSA signature.
     * @param s The s-value of the ECDSA signature.
     */
    function cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (_authorizationStates[authorizer][nonce]) revert AuthorizationAlreadyUsed();

        // forge-lint: disable-start(asm-keccak256)
        bytes32 structHash = keccak256(
            abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce)
        );
        // forge-lint: disable-end(asm-keccak256)

        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(v, r, s);
        
        if (signer != authorizer) revert InvalidSignature();

        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }


    // =============================================================
    //                       View Functions
    // =============================================================

    /**
     * @notice Checks whether an authorization has been used or canceled.
     * @param authorizer The address of the authorizer.
     * @param nonce The nonce of the authorization.
     * @return bool True if the nonce has been used, false otherwise.
     */
    function authorizationState(address authorizer, bytes32 nonce)
        external
        view
        returns (bool)
    {
        return _authorizationStates[authorizer][nonce];
    }

    /**
     * @notice Returns the EIP-712 domain separator for this contract.
     * @dev The domain separator is unique to the contract and chain, preventing signatures from being
     * replayed on other contracts or chains.
     * @return The 32-byte domain separator hash.
     */
    // forge-lint: disable-start(mixed-case-variable)
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
    // forge-lint: disable-end(mixed-case-variable)

    /**
     * @notice A convenience function to get the underlying token address.
     * @return The address of the wrapped ERC-20 token.
     */
    function underlyingToken() external view returns (address) {
        return address(TOKEN);
    }

    /**
     * @notice Checks if a token owner has approved this contract to spend a certain amount.
     * @param owner The address of the token owner.
     * @param amount The amount to check for allowance.
     * @return bool True if the allowance is greater than or equal to the amount, false otherwise.
     */
    function hasApproval(address owner, uint256 amount) external view returns (bool) {
        return TOKEN.allowance(owner, address(this)) >= amount;
    }

    /**
     * @notice Gets the current allowance the specified owner has granted to this contract.
     * @param owner The address of the token owner.
     * @return The allowance amount.
     */
    function getAllowance(address owner) external view returns (uint256) {
        return TOKEN.allowance(owner, address(this));
    }
}