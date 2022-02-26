import ethers from "ethers";

// Expects: 0x319676528382cd5a2E3074E0f5180e2FfeAC870a

const { utils } = ethers;

const rawTx = "0xf8668085051f4d5c0082520894e2af91e419974999c22b1de7eaada5bf02c4e09f8203e8801ca09bbee06a5b9983aade35be64fb5b8f8f9c1b9a4d5d39c963819d4699c7a7a474a0451fc804ca5235368bb6b57188ba12ecd7bb80771bc8990bca8d6f4e15d3105b";

// Works the same, in either v4 or v5
const tx = utils.parseTransaction(rawTx);
console.log(tx.from);
