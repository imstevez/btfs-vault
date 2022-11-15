// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma abicoder v2;
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetMinterPauser.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/ERC1967/ERC1967UpgradeUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";



/**
@title Vault contract without waivers
@author The Btfs Authors
@notice The Vault contract allows the issuer of the Vault to send cheques to an unlimited amount of counterparties.
Furthermore, solvency can be guaranteed via hardDeposits
@dev as an issuer, no cheques should be send if the cumulative worth of a cheques send is above the cumulative worth of all deposits
as a beneficiary, we should always take into account the possibility that a cheque bounces
*/
contract Vault is ERC1967UpgradeUpgradeable,UUPSUpgradeable{
  using SafeMath for uint;
  using EnumerableSet for EnumerableSet.AddressSet;

  event ChequeCashed(
    address indexed beneficiary,
    address indexed recipient,
    address indexed caller,
    address token,
    uint totalPayout,
    uint cumulativePayout,
    uint callerPayout
  );
  event ChequeBounced(address token);
  event VaultWithdraw(address token, address indexed from, uint amount);
  event VaultDeposit(address token, address indexed from, uint amount);
  event MultiTokensAdded(address[] tokens);
  event MultiTokensRemoved(address[] tokens);

  struct EIP712Domain {
    string name;
    string version;
    uint256 chainId;
  }

  bytes32 public constant EIP712DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId)"
  );
  bytes32 public constant CHEQUE_TYPEHASH = keccak256(
    "Cheque(address vault,address beneficiary,address token,uint256 cumulativePayout)"
  );



  // the EIP712 domain this contract uses
  //function domain() internal pure returns (EIP712Domain memory) {
  function domain() internal view returns (EIP712Domain memory) {
    uint256 chainId;
    assembly {
      chainId := chainid()
    }
    return EIP712Domain({
    name: "Vault",
    version: "1.0",
    chainId: chainId
    });
  }

  // compute the EIP712 domain separator. this cannot be constant because it depends on chainId
  function domainSeparator(EIP712Domain memory eip712Domain) internal pure returns (bytes32) {
    return keccak256(abi.encode(
        EIP712DOMAIN_TYPEHASH,
        keccak256(bytes(eip712Domain.name)),
        keccak256(bytes(eip712Domain.version)),
        eip712Domain.chainId
      ));
  }

  // recover a signature with the EIP712 signing scheme
  function recoverEIP712(bytes32 hash, bytes memory sig) internal view returns (address) {
    bytes32 digest = keccak256(abi.encodePacked(
        "\x19\x01",
        domainSeparator(domain()),
        hash
      ));
    return ECDSA.recover(digest, sig);
  }

  /* The token against which this Vault writes cheques */
  ERC20 public token;
  /* associates every beneficiary with how much has been paid out to them */
  mapping (address => uint) public paidOut;
  /* total amount paid out */
  uint public totalPaidOut;
  /* issuer of the contract, set at construction */
  address public issuer;
  /* indicates wether a cheque bounced in the past */
  bool public bounced;

  /* supported multi-tokens set */
  EnumerableSet.AddressSet private _multiTokensSet;
  /* paid out for multi-tokens */
  mapping (address => mapping(address => uint)) public multiTokensPaidOut;
  /* total paid out for multi-tokens */
  mapping (address => uint) public multiTokensTotalPaidOut;
  /* bounced for multi-tokens */
  mapping (address => bool) public multiTokensBounced;

  /**
  @param _issuer the issuer of cheques from this Vault (needed as an argument for "Setting up a Vault as a payment").
  _issuer must be an Externally Owned Account, or it must support calling the function cashCheque
  @param _token the token this Vault uses
  */
  function init(address _issuer, address _token) public initializer {
    require(_issuer != address(0), "invalid issuer");
    require(issuer == address(0), "already initialized");
    UUPSUpgradeable.__UUPSUpgradeable_init();
    ERC1967UpgradeUpgradeable.__ERC1967Upgrade_init();
    issuer = _issuer;
    token = ERC20(_token);
  }

  /// @return the token(wbtt) balance of the Vault
  function totalbalance() public view returns(uint) {
    return token.balanceOf(address(this));
  }

  /// @return the specified token balance of the Vault
  function totalBalanceOf(address _token) public view returns(uint) {
    return ERC20(_token).balanceOf(address(this));
  }

  /**
  @dev internal function responsible for checking the issuerSignature, updating hardDeposit balances and doing transfers.
  Called by cashCheque and cashChequeBeneficary
  @param beneficiary the beneficiary to which cheques were assigned. Beneficiary must be an Externally Owned Account
  @param recipient receives the differences between cumulativePayment and what was already paid-out to the beneficiary minus callerPayout
  @param cumulativePayout cumulative amount of cheques assigned to beneficiary
  @param issuerSig if issuer is not the sender, issuer must have given explicit approval on the cumulativePayout to the beneficiary
  */
  function _cashChequeInternal(
    address beneficiary,
    address recipient,
    address _token,
    uint cumulativePayout,
    bytes memory issuerSig
  ) internal {
    /* The issuer must have given explicit approval to the cumulativePayout, either by being the caller or by signature*/
    if (msg.sender != issuer) {
      require(issuer == recoverEIP712(chequeHash(address(this), beneficiary, _token, cumulativePayout), issuerSig),
        "invalid issuer signature");
    }

    if (_token == address(token)) {
      require(cumulativePayout > paidOut[beneficiary], "Vault: cannot cash");
      uint totalPayout = cumulativePayout.sub(paidOut[beneficiary]);
      uint balance = totalBalanceOf(_token);
      /* let the world know that the issuer has over-promised on outstanding cheques */
      if (totalPayout > balance) {
        bounced = true;
        emit ChequeBounced(_token);
      }
      require(totalPayout <= balance, "Vault: insufficient fund");

      /* increase the stored paidOut amount to avoid double payout */
      paidOut[beneficiary] = paidOut[beneficiary].add(totalPayout);
      totalPaidOut = totalPaidOut.add(totalPayout);

      /* do the actual payment */
      require(token.transfer(recipient, totalPayout), "transfer failed");
      emit ChequeCashed(beneficiary, recipient, msg.sender, _token, totalPayout, cumulativePayout, 0);
    } else {
      require(cumulativePayout > multiTokensPaidOut[_token][beneficiary], "Vault: cannot cash");
      uint totalPayout = cumulativePayout.sub(multiTokensPaidOut[_token][beneficiary]);
      uint balance = totalBalanceOf(_token);
      /* let the world know that the issuer has over-promised on outstanding cheques */
      if (totalPayout > balance) {
        multiTokensBounced[_token] = true;
        emit ChequeBounced(_token);
      }
      require(totalPayout <= balance, "Vault: insufficient fund");

      /* increase the stored paidOut amount to avoid double payout */
      multiTokensPaidOut[_token][beneficiary] = multiTokensPaidOut[_token][beneficiary].add(totalPayout);
      multiTokensTotalPaidOut[_token] = multiTokensTotalPaidOut[_token].add(totalPaidOut);

      /* do the actual payment */
      require(ERC20(_token).transfer(recipient, totalPayout), "transfer failed");
      emit ChequeCashed(beneficiary, recipient, msg.sender, _token, totalPayout, cumulativePayout, 0);
    }
  }

  /**
  @notice cash a cheque as beneficiary
  @param recipient receives the differences between cumulativePayment and what was already paid-out to the beneficiary minus callerPayout
  @param _token the specified cash token
  @param cumulativePayout amount requested to pay out
  @param issuerSig issuer must have given explicit approval on the cumulativePayout to the beneficiary
  */
  function cashChequeBeneficiary(address recipient, address _token, uint cumulativePayout, bytes memory issuerSig) public {
    _cashChequeInternal(msg.sender, recipient, _token, cumulativePayout, issuerSig);
  }

  function withdraw(address _token, uint amount) public {
    /* only issuer can do this */
    require(msg.sender == issuer, "not issuer");
    /* ensure we don't take anything from the hard deposit */
    require(amount <= totalBalanceOf(_token), "total balance not sufficient");
    require(ERC20(_token).transfer(issuer, amount), "transfer failed");
    emit VaultWithdraw(_token, issuer, amount);
  }

  /*
  * deposit wbtt to address(this), befrore it, must approve to address(this)
  */
  function deposit(address _token, uint amount) public {
    require(ERC20(_token).transferFrom(msg.sender, address(this), amount), "deposit failed");
    emit VaultDeposit(_token, msg.sender, amount);
  }

  function chequeHash(address vault, address beneficiary, address _token, uint cumulativePayout)
  internal pure returns (bytes32) {
    return keccak256(abi.encode(
        CHEQUE_TYPEHASH,
        vault,
        beneficiary,
        _token,
        cumulativePayout
      ));
  }

  function addMultiTokens(address[] calldata _tokens) external {
    require(msg.sender == issuer, "not issuer");
    for (uint256 i = 0; i < _tokens.length; i++) {
      require(_tokens[i] != address(0), "invalid token");
      _multiTokensSet.add(_tokens[i]);
    }
    emit MultiTokensAdded(_tokens);
  }

  function removeMultiTokens(address[] calldata _tokens) external {
    require(msg.sender == issuer, "not issuer");
    for (uint256 i = 0; i < _tokens.length; i++) {
      _multiTokensSet.remove(_tokens[i]);
    }
    emit MultiTokensRemoved(_tokens);
  }

  function getMultiTokens() external view returns (address[] memory) {
    return _multiTokensSet.values();
  }

  function getMultiToken(address _token) external view returns (bool) {
    return _multiTokensSet.contains(_token);
  }

  function _authorizeUpgrade(address) internal  view override {
    require(msg.sender == issuer, "not issuer");
  }

  function implementation() public view returns (address impl) {
    return ERC1967UpgradeUpgradeable._getImplementation();
  }
}
