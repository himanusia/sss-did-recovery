// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title DIDRegistry
 * @notice Minimal DID registry with threshold account recovery.
 *
 * A DID document holds:
 *  - authKey: the key that authenticates logins on every connected app
 *  - recoveryKey: an address derived from a secret split with Shamir's Secret
 *    Sharing. Shares never touch the chain; only a Merkle root of the share
 *    commitments does.
 *  - shareRoot/threshold/shareCount: the committed share configuration
 *
 * Recovery is two-phase. Anyone may open a request (the owner may have lost
 * every key), but executing it requires a signature from the recovery key and
 * a timelock window during which the current auth key can cancel. No secret or
 * share value is ever submitted or stored on-chain.
 */
contract DIDRegistry {
    uint64 public immutable recoveryDelay;

    struct DIDDocument {
        address authKey;
        address recoveryKey;
        bytes32 shareRoot;
        uint8 threshold;
        uint8 shareCount;
        uint64 createdAt;
        uint64 updatedAt;
        uint32 version;
        bool active;
    }

    struct RecoveryRequest {
        address newAuthKey;
        address newRecoveryKey;
        bytes32 newShareRoot;
        uint8 threshold;
        uint8 shareCount;
        uint64 requestedAt;
        uint64 executeAfter;
        bool executed;
        bool cancelled;
    }

    mapping(bytes32 => DIDDocument) private _documents;
    mapping(bytes32 => RecoveryRequest) private _recoveries;
    mapping(bytes32 => uint256) public recoveryRequestCount;

    bytes32 private constant REGISTER_TYPEHASH = keccak256(
        "Register(bytes32 didHash,address authKey,address recoveryKey,bytes32 shareRoot,uint8 threshold,uint8 shareCount,uint256 chainId,address registry)"
    );
    bytes32 private constant RECOVER_TYPEHASH = keccak256(
        "Recover(bytes32 didHash,uint256 requestId,address newAuthKey,address newRecoveryKey,bytes32 newShareRoot,uint8 threshold,uint8 shareCount,uint256 chainId,address registry)"
    );
    bytes32 private constant CANCEL_TYPEHASH = keccak256(
        "CancelRecovery(bytes32 didHash,uint256 requestId,uint256 chainId,address registry)"
    );
    // secp256k1n / 2, rejects malleable signatures.
    uint256 private constant _HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    event DIDRegistered(
        bytes32 indexed didHash,
        address indexed authKey,
        address recoveryKey,
        bytes32 shareRoot,
        uint8 threshold,
        uint8 shareCount
    );
    event KeyRotated(
        bytes32 indexed didHash,
        address indexed oldAuthKey,
        address indexed newAuthKey,
        uint32 version
    );
    event RecoveryInitiated(
        bytes32 indexed didHash,
        uint256 indexed requestId,
        address newAuthKey,
        uint64 executeAfter
    );
    event RecoveryCancelled(bytes32 indexed didHash, uint256 indexed requestId);
    event RecoveryExecuted(
        bytes32 indexed didHash,
        uint256 indexed requestId,
        address indexed newAuthKey,
        uint32 version
    );

    error AlreadyRegistered();
    error NotRegistered();
    error InvalidParameters();
    error InvalidSignature();
    error RecoveryPending();
    error NoPendingRecovery();
    error TimelockActive();

    constructor(uint64 delay) {
        recoveryDelay = delay;
    }

    function register(
        bytes32 didHash,
        address authKey,
        address recoveryKey,
        bytes32 shareRoot,
        uint8 threshold,
        uint8 shareCount,
        bytes calldata signature
    ) external {
        if (_documents[didHash].authKey != address(0)) revert AlreadyRegistered();
        _validateKeys(authKey, recoveryKey, shareRoot, threshold, shareCount);

        bytes32 digest = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                didHash,
                authKey,
                recoveryKey,
                shareRoot,
                threshold,
                shareCount,
                block.chainid,
                address(this)
            )
        );
        if (_recover(digest, signature) != authKey) revert InvalidSignature();

        _documents[didHash] = DIDDocument({
            authKey: authKey,
            recoveryKey: recoveryKey,
            shareRoot: shareRoot,
            threshold: threshold,
            shareCount: shareCount,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp),
            version: 1,
            active: true
        });

        emit DIDRegistered(didHash, authKey, recoveryKey, shareRoot, threshold, shareCount);
    }

    /**
     * @notice Opens a recovery request. Permissionless by design: the owner may
     * have no working key left. Nothing changes until the recovery key signs.
     */
    function initiateRecovery(
        bytes32 didHash,
        address newAuthKey,
        address newRecoveryKey,
        bytes32 newShareRoot,
        uint8 threshold,
        uint8 shareCount
    ) external returns (uint256 requestId) {
        DIDDocument storage doc = _documents[didHash];
        if (doc.authKey == address(0) || !doc.active) revert NotRegistered();
        _validateKeys(newAuthKey, newRecoveryKey, newShareRoot, threshold, shareCount);

        RecoveryRequest storage pending = _recoveries[didHash];
        if (pending.requestedAt != 0 && !pending.executed && !pending.cancelled) {
            revert RecoveryPending();
        }

        requestId = ++recoveryRequestCount[didHash];
        uint64 executeAfter = uint64(block.timestamp) + recoveryDelay;
        _recoveries[didHash] = RecoveryRequest({
            newAuthKey: newAuthKey,
            newRecoveryKey: newRecoveryKey,
            newShareRoot: newShareRoot,
            threshold: threshold,
            shareCount: shareCount,
            requestedAt: uint64(block.timestamp),
            executeAfter: executeAfter,
            executed: false,
            cancelled: false
        });

        emit RecoveryInitiated(didHash, requestId, newAuthKey, executeAfter);
    }

    /**
     * @notice Cancels a pending request on behalf of the current auth key.
     * The auth key signs off-chain so a gasless relayer can submit the
     * cancellation; msg.sender is not trusted for authority.
     */
    function cancelRecovery(bytes32 didHash, uint256 requestId, bytes calldata signature) external {
        DIDDocument storage doc = _documents[didHash];
        if (doc.authKey == address(0)) revert NotRegistered();

        RecoveryRequest storage pending = _recoveries[didHash];
        if (pending.requestedAt == 0 || pending.executed || pending.cancelled) {
            revert NoPendingRecovery();
        }
        if (requestId != recoveryRequestCount[didHash]) revert InvalidParameters();

        bytes32 digest = cancelDigest(didHash, requestId);
        if (_recover(digest, signature) != doc.authKey) revert InvalidSignature();

        pending.cancelled = true;
        emit RecoveryCancelled(didHash, requestId);
    }

    /**
     * @notice Executes a pending request with proof of recovery-secret
     * possession: a signature by the recovery key over the new key material.
     */
    function executeRecovery(bytes32 didHash, uint256 requestId, bytes calldata signature) external {
        DIDDocument storage doc = _documents[didHash];
        if (doc.authKey == address(0) || !doc.active) revert NotRegistered();

        RecoveryRequest storage pending = _recoveries[didHash];
        if (pending.requestedAt == 0 || pending.executed || pending.cancelled) {
            revert NoPendingRecovery();
        }
        if (requestId != recoveryRequestCount[didHash]) revert InvalidParameters();
        if (block.timestamp < pending.executeAfter) revert TimelockActive();

        bytes32 digest = keccak256(
            abi.encode(
                RECOVER_TYPEHASH,
                didHash,
                requestId,
                pending.newAuthKey,
                pending.newRecoveryKey,
                pending.newShareRoot,
                pending.threshold,
                pending.shareCount,
                block.chainid,
                address(this)
            )
        );
        if (_recover(digest, signature) != doc.recoveryKey) revert InvalidSignature();

        address oldAuthKey = doc.authKey;
        doc.authKey = pending.newAuthKey;
        doc.recoveryKey = pending.newRecoveryKey;
        doc.shareRoot = pending.newShareRoot;
        doc.threshold = pending.threshold;
        doc.shareCount = pending.shareCount;
        doc.updatedAt = uint64(block.timestamp);
        doc.version += 1;
        pending.executed = true;

        emit RecoveryExecuted(didHash, requestId, pending.newAuthKey, doc.version);
        emit KeyRotated(didHash, oldAuthKey, pending.newAuthKey, doc.version);
    }

    function getDocument(bytes32 didHash) external view returns (DIDDocument memory) {
        return _documents[didHash];
    }

    function getRecovery(bytes32 didHash) external view returns (RecoveryRequest memory) {
        return _recoveries[didHash];
    }

    function isAuthKey(bytes32 didHash, address key) external view returns (bool) {
        DIDDocument storage doc = _documents[didHash];
        return doc.active && doc.authKey == key;
    }

    function recoveryDigest(
        bytes32 didHash,
        uint256 requestId,
        address newAuthKey,
        address newRecoveryKey,
        bytes32 newShareRoot,
        uint8 threshold,
        uint8 shareCount
    ) public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    RECOVER_TYPEHASH,
                    didHash,
                    requestId,
                    newAuthKey,
                    newRecoveryKey,
                    newShareRoot,
                    threshold,
                    shareCount,
                    block.chainid,
                    address(this)
                )
            );
    }

    function cancelDigest(bytes32 didHash, uint256 requestId) public view returns (bytes32) {
        return
            keccak256(
                abi.encode(CANCEL_TYPEHASH, didHash, requestId, block.chainid, address(this))
            );
    }

    function registerDigest(
        bytes32 didHash,
        address authKey,
        address recoveryKey,
        bytes32 shareRoot,
        uint8 threshold,
        uint8 shareCount
    ) public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    REGISTER_TYPEHASH,
                    didHash,
                    authKey,
                    recoveryKey,
                    shareRoot,
                    threshold,
                    shareCount,
                    block.chainid,
                    address(this)
                )
            );
    }

    function _validateKeys(
        address authKey,
        address recoveryKey,
        bytes32 shareRoot,
        uint8 threshold,
        uint8 shareCount
    ) private pure {
        if (authKey == address(0) || recoveryKey == address(0)) revert InvalidParameters();
        if (authKey == recoveryKey) revert InvalidParameters();
        if (shareRoot == bytes32(0)) revert InvalidParameters();
        if (threshold < 2 || shareCount < threshold || shareCount > 255) revert InvalidParameters();
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > _HALF_ORDER) revert InvalidSignature();
        if (v != 27 && v != 28) revert InvalidSignature();
        address signer = ecrecover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)),
            v,
            r,
            s
        );
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }
}
