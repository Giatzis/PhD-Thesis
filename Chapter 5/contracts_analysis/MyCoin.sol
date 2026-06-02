// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyCoin is ERC20, Ownable {
    bool private initialized = false;

    // Constructor: Initializes the token name and symbol
    constructor() ERC20("MY_COIN", "MYC") {}

    // Initialization function: Sets up the initial supply (onlyOwner can call it once)
    function init(uint256 initialSupply) public onlyOwner {
        require(!initialized, "Already initialized");
        _mint(msg.sender, initialSupply);
        initialized = true;
    }

    // Mint new coins. Only the owner (treasury) can mint additional tokens.
    function mint(address recipient, uint256 amount) public onlyOwner {
        _mint(recipient, amount);
    }

    // Override the decimals function to use 6 decimals, like in the Sui Move contract
    function decimals() public view virtual override returns (uint8) {
        return 6;
    }
}