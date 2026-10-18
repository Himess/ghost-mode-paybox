import { parseAbi } from "viem";

export const ghostPoolAbi = parseAbi([
  "struct TransactArgs { uint256 root; uint256 aspRoot; uint256[2] nullifiers; uint256[2] outCommitments; uint256 publicOut; address recipient; uint256 fee; uint256 deadline; address relayer; bytes encryptedOutput0; bytes encryptedOutput1; }",
  "event NewCommitment(uint256 indexed commitment, uint32 leafIndex, bytes encryptedOutput)",
  "event Deposited(address indexed depositor, uint256 indexed commitment, uint256 label, uint256 amount, uint32 leafIndex)",
  "event NewNullifier(uint256 indexed nullifier)",
  "event Transacted(address indexed relayer, address indexed recipient, uint256 publicOut, uint256 fee)",
  "function deposit(uint256 amount, uint256 precommitment, bytes encryptedNote)",
  "function transact(bytes proof, TransactArgs a)",
  "function setAspRoot(uint256 root)",
  "function getLastRoot() view returns (uint256)",
  "function currentAspRoot() view returns (uint256)",
  "function isKnownRoot(uint256 root) view returns (bool)",
  "function isKnownAspRoot(uint256 root) view returns (bool)",
  "function nullifierSpent(uint256 nullifier) view returns (bool)",
  "function DOMAIN_SEPARATOR() view returns (bytes32)",
]);

export const erc20Abi = parseAbi([
  "function approve(address spender, uint256 amount) returns (bool)",
  "function balanceOf(address owner) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)",
]);
