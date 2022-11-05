import agent from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
import { lebEncode, lebDecode } from '@dfinity/candid';
import { webcrypto as crypto } from 'crypto';
import { unwrapDER } from '@dfinity/identity';

/*
 * let delegation = {
"delegations":[
  {
    "delegation":
    {
      {
        "expiration" : "17225741aef9ef95",
          "pubkey" : "302a300506032b6570032100e6fb75979864b499b17b2127f9ecdcd58ac8d62e8bfb868e1ff5d26237212b33"
      },
      "signature" : "d9d9f7a26b6365727469666963617465590223d9d9f7a2647472656583018301830183024863616e6973746572830183018204582061d184a9e9013312a2fada940badc2050a3a7d323cbd3e2b1da4ee1aaf050db6830182045820e24a9987cbbd41a4123c7546d92d20fa302f61de9b5395592e96a124d2b997878301820458202946d643e18744dcfbf78b5c331f9e104109b08e2390854868fb9397872e8fe483024a0000000000000007010183018301830183024e6365727469666965645f6461746182035820d31049b43d2757951dec65c1735df452f1d55123a3e7e1bc267853ef2b0cf98182045820fd5b59459758c8afecaf7285da359e4b5adb945fb86a3c1f0efd996c21a9693882045820e872843059989fd8f4b051d1c420833575932e70cc6f0e2d0ef93d461da03f298204582039980f61949ea04477512d5cfad84ff4510a21196431c2825f31769b9f0f6aef820458208e52d997e4b4e635eecff11a833754d5d2d78c9b6c5707cf21a03681a47fbc0682045820fe6b546ade7aef40eec58614fe0703869c6fb4f39dcba09031da7886d24cdef3820458201fa8c5328ba39d2e03a8a5bcfd032b9abf7019ccdbeb0a5d548eec161d0bd1a3830182045820de733455c3f6106134662a4602e368ecacc6727dfa76b740402dba531d19642483024474696d65820349d0aea4bfa0a68c9017697369676e61747572655830a2807e26c18b2436e68ce2641f4ceca272926e6be407201ea3a7d36d7c237cc524c603a5370d2575b0e7220903debc486474726565830182045820667ea9a81c4e944ba9891dab8458a3a17906fd9c0784d2e2cc1f6a29c8a3860f830243736967830258209a9e61da63c20cb4130cbede782f0ca8d99b40bb81e8844cee34ebf258716059830258201ad9eaea2714161d09eb031da0182be237e442d66ea0190b8e8c881f9449192f820340"
    }
],
  "publicKey":"303c300c060a2b0601040183b8430102032c000a00000000000000070101a4ab56f8e1e2f5a85ae5e8eb2c95259a6da7ec0ba6055829c9fc7b41dde02c22"};
  */

let delegation = {
     "delegations":[
             {
                        "delegation":{
                                      "expiration":"17225e63bd589e21",
                                      "pubkey":"302a300506032b6570032100aefaccf60180e8595fc72fe735af186e4d89aa3204732ab0e1e4faf337b60e23"
                                   },
                        "signature":"d9d9f7a26b6365727469666963617465590223d9d9f7a2647472656583018301830183024863616e69737465728301830182045820e342b1741530f212fba3a2cd952c5d3fdf76187147c7c98a2d89e213afd937928301820458208ac764a3fcee7f13a0a99c24fe67ab275f83742d011882b069f1a1fe9f0f96e28301820458202946d643e18744dcfbf78b5c331f9e104109b08e2390854868fb9397872e8fe483024a0000000000000007010183018301830183024e6365727469666965645f646174618203582023e374426cda80d3dfd674c997575ce5323c2409bd40fa7c99d46a4876205f3982045820fd5b59459758c8afecaf7285da359e4b5adb945fb86a3c1f0efd996c21a9693882045820e872843059989fd8f4b051d1c420833575932e70cc6f0e2d0ef93d461da03f298204582039980f61949ea04477512d5cfad84ff4510a21196431c2825f31769b9f0f6aef820458208e52d997e4b4e635eecff11a833754d5d2d78c9b6c5707cf21a03681a47fbc0682045820c59ac8e36e308951bda80b503b1b7126bb951e7e3036a7332d0ab3fabc1f7b6582045820fbf4dce758e610bada4ae6ac744066e66c297a6832da6aaf9177118c2f32fc08830182045820de733455c3f6106134662a4602e368ecacc6727dfa76b740402dba531d19642483024474696d65820349c9e897b1c18a8e9017697369676e6174757265583099f3e61b14b49605d22ff86a7ec6a41ab751912dc5ab09d4e71a13374a221130427fde1361b0755d3e58289db79e28a96474726565830182045820667ea9a81c4e944ba9891dab8458a3a17906fd9c0784d2e2cc1f6a29c8a3860f8302437369678301830182045820d92d86509f3bb95a7a13f5ded8841a9587a3d596f311c1a1d7be248eb84d4647830182045820dcf6f1753c5850ae53fc4351e093770a1820a078f9ded82ee30635fcfa0d5cd1830258209a9e61da63c20cb4130cbede782f0ca8d99b40bb81e8844cee34ebf25871605983025820bf167fe83578930179be5054e62bb181555a81c5885912bac74385eb6874894b820340820458202d6d0415d836a0ae1990ecb8ac85e63dc9b7101343f113aee42be72d329e1772"
                     }
          ],
     "publicKey":"303c300c060a2b0601040183b8430102032c000a00000000000000070101a4ab56f8e1e2f5a85ae5e8eb2c95259a6da7ec0ba6055829c9fc7b41dde02c22"
}

let signedChallenge = "303c300c060a2b0601040183b8430102032c000a000000000000000b0101bea4123b6ef44519521a2e8e2eaa7a1dda073a2412195e4504244a7a596b0b5e";

let canisterId = 'rdmx6-jaaaa-aaaaa-aaadq-cai'

const IC_ROOT_KEY =
      '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814' +
      'c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d968' +
      '5f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484' +
      'b01291091c5f87b98883463f98091a0baaae';
   
const principal = "rzd6v-qq7sr-slo2x-s3ad4-gak6r-tgx4s-qllet-myynk-hrxut-on46i-oae";
const challenge = 'ic0online challenge (' + Date.now().toString() + ')';
const hexRe = new RegExp(/^([0-9A-F]{2})*$/i);

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
      rootKey: fromHex(IC_ROOT_KEY)
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
  } catch (error) {
    console.log(error);
    return false;
  }
  return true;
}


console.log(principal);
validate(delegation).then(r => console.log('validate', r));
