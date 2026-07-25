// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

contract ReputationRegistryHarness {
    error InvalidAgent(uint256 agentId);
    error SelfFeedback(uint256 agentId, address caller);

    mapping(uint256 agentId => address owner) public owners;
    mapping(uint256 agentId => uint64 count) public feedbackCount;

    event NewFeedback(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 feedbackIndex,
        int128 value,
        uint8 valueDecimals,
        string indexed indexedTag1,
        string tag1,
        string tag2,
        string endpoint,
        string feedbackURI,
        bytes32 feedbackHash
    );

    constructor(uint256 agentId, address owner) {
        owners[agentId] = owner;
    }

    function giveFeedback(
        uint256 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    ) external {
        address owner = owners[agentId];
        if (owner == address(0)) revert InvalidAgent(agentId);
        if (msg.sender == owner) revert SelfFeedback(agentId, msg.sender);

        uint64 feedbackIndex = feedbackCount[agentId];
        feedbackCount[agentId] = feedbackIndex + 1;
        emit NewFeedback(
            agentId,
            msg.sender,
            feedbackIndex,
            value,
            valueDecimals,
            tag1,
            tag1,
            tag2,
            endpoint,
            feedbackURI,
            feedbackHash
        );
    }
}
