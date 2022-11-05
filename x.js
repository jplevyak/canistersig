import agent from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
import { lebEncode, lebDecode } from '@dfinity/candid';
import { webcrypto as crypto } from 'crypto';
import { unwrapDER } from '@dfinity/identity';
import * as ed from '@noble/ed25519';

let delegation = {
delegations:[
  {delegation:{
    expiration : "1726ecb7ed82a83c",
    pubkey : "302a300506032b6570032100d0591a3e42d95cd59d52ea12aa42c05ba00f5c8067c005177553430547d1dfec"},
    "signature":"d9d9f7a26b6365727469666963617465590223d9d9f7a2647472656583018301830183024863616e69737465728301820458201ab15ebe180b75f925bf85dee7d4ac2f4cdb60d19d84e89d9573a9eab3f22e728301830182045820a3dc9d8bc09cbe5163076b5d0a4caf844244d4891aa1a4cd6e1ceb00bbd9be1c83018204582075d53bb308a2127b31c244ffb22800446d0a3d3333bc7bbc38ff42b7c3e6543783024a000000000000000b010183018301830183024e6365727469666965645f6461746182035820f500fcb3fb8cbd183fda30e6d7cde4304d3b187df724cd7d7a809fb9ad6da4f882045820ffc9884b642d9eb751e27538cd05ab8377377b5c878f1dec0a83ded667e8f64382045820489e6e5ccf6c7570f2771536b7533ff5c97ac754f0805ef322a7f5b3deadc32f8204582076f29de7799631e29048316415aa228eb43e177ceac0f117c4688f9f76edaa5782045820f95d73da6c3bfece49a8409e50bb8715e11f89170335efe9a8e0d471d49304c5820458205496d946e7e6fae1dbc1596aef424833eb0d195284d2485d5f6605705baa74a982045820e8c2eabe2eaa94acbd52aa5208e7c361dc385c6cd529df19df3032bfade9acc68301820458202c8139e1e6a48b6b580cba701257a590e0f0397021ec0d31b240de0ca381f71f83024474696d65820349e0b580c881d5b19217697369676e617475726558308a36c1f1bec76ebfeeade052feca59cafa8cc19dbce912bedfe4dc6c37520130bcabe894d2898d3380b62e3eeebcbb316474726565830182045820ea01cf20cafabdc6f4381e116fd139463ddc715301c5d1ac9f2230e225af0f5f83024373696783025820266327b47952e3eb66c08ca7084d930612c740481d72c47c75274db59d0bcc588302582002ec5f3879f1d802b7dee55a559b08605eb7bd47a1e1b515a66afa0556cc8305820340"}],
  publicKey: "303c300c060a2b0601040183b8430102032c000a000000000000000b0101bea4123b6ef44519521a2e8e2eaa7a1dda073a2412195e4504244a7a596b0b5e"};

let challenge = "ic0online challenge (1667676181879)";
let signedChallenge = "c7bbca410150b49604e9f5a6768ff70a6cec62b6df8e6b637de963c25637343dd21b3b4679c8a6ac34a93261a2389b7d8f46f3097daacffb65fdaa01e3106003";

let canisterId = 'qhbym-qaaaa-aaaaa-aaafq-cai';

const IC_ROOT_KEY =
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814' +
      'c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d968' +
      '5f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484' +
      'b01291091c5f87b98883463f98091a0baaae';

const ROOT_KEY = new Uint8Array([48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 183, 185, 44, 221, 206, 170, 1, 233, 59, 239, 81, 238, 210, 75, 209, 185, 168, 235, 21, 145, 17, 98, 167, 190, 166, 62, 78, 93, 78, 39, 251, 202, 78, 72, 112, 131, 187, 52, 167, 10, 156, 188, 208, 125, 193, 8, 244, 215, 5, 94, 250, 74, 213, 141, 226, 164, 41, 177, 152, 65, 168, 103, 91, 181, 3, 5, 22, 118, 2, 109, 61, 200, 95, 91, 146, 252, 14, 157, 114, 23, 220, 239, 160, 254, 215, 4, 24, 37, 85, 117, 186, 85, 165, 155, 151, 22]);

   
const principal = "rzd6v-qq7sr-slo2x-s3ad4-gak6r-tgx4s-qllet-myynk-hrxut-on46i-oae";
const hexRe = new RegExp(/^([0-9A-F]{2})*$/i);
const DER_ED25519_PREFIX = "302a300506032b6570032100";
const pubkey = "d0591a3e42d95cd59d52ea12aa42c05ba00f5c8067c005177553430547d1dfec";

function fromHex(hex) {
    if (!hexRe.test(hex)) {
      throw new Error('Invalid hexadecimal string.');
    }
    const buffer = [...hex]
      .reduce((acc, curr, i) => {
        // tslint:disable-next-line:no-bitwise
        acc[(i / 2) | 0] = (acc[(i / 2) | 0] || '') + curr;
        return acc;
      }, [] )
    .map(x => Number.parseInt(x, 16));

  return new Uint8Array(buffer).buffer;
}

function isBufferEqual(a, b) {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  const a8 = new Uint8Array(a);
  const b8 = new Uint8Array(b);
  for (let i = 0; i < a8.length; i++) {
    if (a8[i] !== b8[i]) {
      return false;
    }
  }
  return true;
}

export function lookup_path( path, tree) {
  //console.log('1');
  if (path.length === 0) {
    switch (tree[0]) {
      case 3: {
        return new Uint8Array(tree[1]).buffer;
      }
      default: {
        //console.log('2');
        return undefined;
      }
    }
  }

  const label = typeof path[0] === 'string' ? new TextEncoder().encode(path[0]) : path[0];
  //console.log(flatten_forks(tree));
  const t = find_label(label, flatten_forks(tree));
  if (t) {
    return lookup_path(path.slice(1), t);
  }
}

function flatten_forks(t) {
  //console.log('5');
  switch (t[0]) {
    case 0:
      return [];
    case 1:
      return flatten_forks(t[1]).concat(flatten_forks(t[2]));
    default:
      //console.log('6', t[1], new TextDecoder('utf-8').decode(t[1]), Buffer.from(t[1]).toString('hex'));
      return [t];
  }
}

function find_label(l, trees){
  //console.log('3');
  if (trees.length === 0) {
    //console.log('4');
    return undefined;
  }
  for (const t of trees) {
    if (t[0] === 2) {
      const p = t[1];
      //console.log('9', p, l);
      if (isBufferEqual(l, p)) {
        return t[2];
      }
    }
  }
  //console.log('8');
  return undefined;
}

function equal(buf1, buf2) {
  if (buf1.byteLength !== buf2.byteLength) {
    return false;
  }
  const a1 = new Uint8Array(buf1);
  const a2 = new Uint8Array(buf2);
  for (let i = 0; i < a1.length; i++) {
    if (a1[i] != a2[i]) {
      return false;
    }
  }
  return true;
}

function hashTreeToString2(tree) {
  const indent = (s) =>
    s
      .split('\n')
      .map(x => '  ' + x)
      .join('\n');
  function labelToString(label) {
    const decoder = new TextDecoder(undefined, { fatal: true });
    try {
      return JSON.stringify(decoder.decode(label));
    } catch (e) {
      return `data(...${toHex(new Uint8Array(label))}`;
    }
  }

  switch (tree[0]) {
    case 0:
      return '()';
    case 1: {
      const left = hashTreeToString2(tree[1]);
      const right = hashTreeToString2(tree[2]);
      return `sub(\n left:\n${indent(left)}\n---\n right:\n${indent(right)}\n)`;
    }
    case 2: {
      const label = labelToString(tree[1]);
      const sub = hashTreeToString2(tree[2]);
      return `label(\n label:\n${indent(label)}\n sub:\n${indent(sub)}\n)`;
    }
    case 3: {
      return `leaf(...${tree[1].byteLength} ${toHex(new Uint8Array(tree[1]))})`;
    }
    case 4: {
      return `pruned(${toHex(new Uint8Array(tree[1]))}`;
    }
    default: {
      return `unknown(${JSON.stringify(tree[0])})`;
    }
  }
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join('');
}

const DER_PREFIX = fromHex('303c300c060a2b0601040183b8430102032c00');


function extractDER(buf) {
  const prefix = buf.slice(0, DER_PREFIX.byteLength);
  if (!isBufferEqual(prefix, DER_PREFIX)) {
    throw new TypeError(
      `BLS DER-encoded public key is invalid. Expect the following prefix: ${DER_PREFIX}, but get ${prefix}`,
    );
  }
  return buf.slice(DER_PREFIX.byteLength);
}

function concat(...buffers) {
  const result = new Uint8Array(buffers.reduce((acc, curr) => acc + curr.byteLength, 0));
  let index = 0;
  for (const b of buffers) {
    result.set(new Uint8Array(b), index);
    index += b.byteLength;
  }
  return result;
}

async function makePayloadHash(delegation) {
  console.log('delegation.pubkey', delegation.pubkey);
  let pubkeyHash = concat(
    await crypto.subtle.digest('SHA-256', new TextEncoder("utf-8").encode('pubkey')),
    await crypto.subtle.digest('SHA-256', fromHex(delegation.pubkey)));
  console.log('pubkeyHash', toHex(pubkeyHash));
  let expiration = lebEncode(BigInt('0x' + delegation.expiration));
  console.log('expiration', toHex(expiration));
  console.log('expiration hash', toHex(await crypto.subtle.digest('SHA-256', expiration)));
  let expirationHash = concat(
    await crypto.subtle.digest('SHA-256', new TextEncoder("utf-8").encode('expiration')),
    await crypto.subtle.digest('SHA-256', expiration));
  console.log('expirationHash', toHex(expirationHash));
  // expiration always sorts before pubkey.
  let mapHash = await crypto.subtle.digest('SHA-256', concat(expirationHash, pubkeyHash));
  console.log('mapHash', toHex(mapHash));
  console.log('separator', toHex(new TextEncoder("utf-8").encode("\x1Aic-request-auth-delegation")));
  let payload = concat(new TextEncoder("utf-8").encode("\x1Aic-request-auth-delegation"), mapHash);
  console.log('payload', toHex(payload));
  let payloadHash = await crypto.subtle.digest('SHA-256', payload);
  console.log('payloadHash', toHex(payloadHash));
  return payloadHash;
}

async function validate() {
  try {
    let signature = agent.Cbor.decode(fromHex(delegation.delegations[0].signature));
    console.log('signature', signature);
    let certificate = agent.Cbor.decode(signature.certificate);
    let canisterPrincipal = Principal.fromText(canisterId);
    console.log('certificate', certificate);
    const cert = await agent.Certificate.create({
      certificate: signature.certificate,
      canisterId: canisterPrincipal,
      rootKey: ROOT_KEY
    });
    const certifiedData = cert.lookup([
      'canister',
      canisterPrincipal.toUint8Array(),
      'certified_data',
    ]);
    if (!certifiedData) {
      throw new Error('Could not find certified data in the certificate.');
    }
    let tree = signature.tree;
    let reconstructed = await agent.reconstruct(tree);
    console.log('signature tree', reconstructed);
    if (!equal(certifiedData, reconstructed)) {
      throw new Error('Signature delgation invalid.');
    }
    console.log('pub', delegation.publicKey);
    let pub = fromHex(delegation.publicKey);
    let apub = new Uint8Array(extractDER(pub));
    console.log('apub', toHex(apub));
    let canisterIdLen = apub[0];
    console.log('canisterIdLen', apub[0]);
    let canister = apub.slice(1, canisterIdLen+1);
    console.log('canister', toHex(canister));
    let seed = apub.slice(canisterIdLen+1);
    console.log('seed', toHex(seed));
    const seedHash = await crypto.subtle.digest('SHA-256', seed);
    console.log('seedHash', seedHash);
    console.log('seedHash', toHex(seedHash));
    console.log('\n\n\n');
    let payloadHash = await makePayloadHash(delegation.delegations[0].delegation);
    console.log('tree', hashTreeToString2(tree));
    let witness = lookup_path(['sig', seedHash, payloadHash], tree);
    if (!witness) {
      throw new Error(
        'Could not find certified data for this canister in the certificate.'
      );
    }
    let key = fromHex(pubkey);
    console.log('verify', await ed.verify(
      signedChallenge,
      toHex(new Uint8Array(challenge)),
      toHex(key)));
  } catch (error) {
    console.log(error);
    return false;
  }
  return true;
}


console.log(principal);
validate(delegation).then(r => console.log('validate', r));
