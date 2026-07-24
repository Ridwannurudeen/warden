// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title WardenLogAnchor
/// @notice Publishes immutable X Layer witnesses for signed Warden APA log checkpoints.
contract WardenLogAnchor {
    error InvalidPublisher();
    error InvalidRoot();
    error NonIncreasingSequence(uint64 currentSequence, uint64 proposedSequence);
    error UnauthorizedPublisher(address caller);

    address public immutable publisher;
    uint64 public anchorCount;
    uint64 public latestLogSequence;

    event CheckpointAnchored(
        uint64 indexed anchorIndex,
        uint64 indexed seq,
        bytes32 root
    );

    constructor(address publisher_) {
        if (publisher_ == address(0)) revert InvalidPublisher();
        publisher = publisher_;
    }

    function anchor(bytes32 root, uint64 seq) external {
        if (msg.sender != publisher) revert UnauthorizedPublisher(msg.sender);
        if (root == bytes32(0)) revert InvalidRoot();
        if (seq <= latestLogSequence) {
            revert NonIncreasingSequence(latestLogSequence, seq);
        }

        latestLogSequence = seq;
        anchorCount += 1;
        emit CheckpointAnchored(anchorCount, seq, root);
    }
}
