import ethers from "ethers";

// Expects: 0x319676528382cd5a2E3074E0f5180e2FfeAC870a

const { utils } = ethers;

const msg = Buffer.from("e9f0f909819e39abd6f96ec0125fd98ded870c5ea90ab4c4854a326f4e22cbb7", "hex");

/*
// THIS WORKS!!
const r = "fa2a9ad00263cf5465e7dcd4f740b1cd6655eb8da9669b17790dddac85c7f051";
const s = "02f9662ab131c45871fcedc09857619e19880b7a0b7f02a7e9894b80c9573dc5";
const recid = Buffer.from("1B", "hex");
*/

/*
// THIS WORKS!!
const r = "492be03b3fd29d773cb1c6897f551a1e0721ff3993bf460b33ec6df32ed7110d";
const s = "1aaa952e1605a9ee55f85684baffdd4c320d445fa7f9c58e9ce892ae759a8e63";
const recid = Buffer.from("1B", "hex");
*/

/*
// THIS WORKS!!
const r = "48ef96b356d92ebe64fde0c237da3dd17e1899761822ec2f69436bdaa42418e8";
const s = "66b3198c6888d4571fa487cd4dced4a6c59f75a4ea91da425f661a0bd6eecf68";
const recid = Buffer.from("1B", "hex");
*/

/*
const r = "332bfb10f5d251fecac598fdc5f557602d796b4ae828197c94272ea6e4d2b5b7";
const s = "1566008622e05eb699d0db57967c6285b53a42bd124f0fe982124cba3961bcfc";
const recid = Buffer.from("1C", "hex");
*/

const r = "9bbee06a5b9983aade35be64fb5b8f8f9c1b9a4d5d39c963819d4699c7a7a474";
const s = "451fc804ca5235368bb6b57188ba12ecd7bb80771bc8990bca8d6f4e15d3105b";
const recid = Buffer.from("1C", "hex");

const signature = Buffer.concat([
  Buffer.from(r, "hex"),
  Buffer.from(s, "hex"),
  recid,
]);

const recoveredAddress = utils.recoverAddress(msg, signature);
console.log(recoveredAddress);
