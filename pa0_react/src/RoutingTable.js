import Backend from './api';

// --- Utility Functions ---
const hex2bin = (hex) => {
  let bin = "";
  for (let i = 0; i < hex.length; i++) {
    bin += parseInt(hex[i], 16).toString(2).padStart(4, '0');
  }
  return bin;
};

// --- Foundations ---
// They return the basic primitive objects.
export const getFoundation = (type) => {
  if (type === 'AES') {
    return {
      type: 'AES',
      name: 'AES-128 (PRP)',
      prp: async (k, x) => {
        const res = await Backend.pa2AesPrf(k, x);
        return res.y; // We use the backend AES_PRF endpoint as our PRP/PRF foundation
      }
    };
  } else {
    return {
      type: 'DLP',
      name: 'DLP (OWP)',
      owp: async (x) => {
        const res = await Backend.pa1OwfDlp(x);
        return res.f_x; 
      }
    };
  }
};

// --- Leg 1: Foundation -> Source Primitive A ---
export const buildSource = async (foundation, targetA, inputHex) => {
  let trace = [];
  let oracle = null;

  if (foundation.type === 'AES') {
    if (targetA === 'PRP' || targetA === 'PRF') {
      oracle = foundation.prp;
      const actualOut = await oracle(inputHex, "00000000000000000000000000000000").catch(e => "Error: " + e.message);
      trace.push({ step: "PRP/PRF Switching Lemma", in: inputHex, out: actualOut });
    } else if (targetA === 'PRG') {
      oracle = async (seed) => {
        const b0 = await foundation.prp(seed, "00000000000000000000000000000000");
        const b1 = await foundation.prp(seed, "00000000000000000000000000000001");
        return b0 + b1;
      };
      const actualOut = await oracle(inputHex).catch(e => "Error: " + e.message);
      trace.push({ step: "PRF => PRG", in: inputHex, out: actualOut });
    } else if (targetA === 'MAC') {
      oracle = async (k, m) => {
        let pad_m = m.padEnd(32, '0').slice(0, 32);
        return await foundation.prp(k, pad_m);
      };
      const actualOut = await oracle(inputHex, "demo_message").catch(e => "Error: " + e.message);
      trace.push({ step: "PRF => MAC", in: inputHex, out: actualOut });
    } else {
      oracle = async () => "STUB_" + targetA;
      trace.push({ step: `AES -> ${targetA} (Stub)`, in: inputHex, out: "STUB" });
    }
  } else {
    // Foundation = DLP (OWP)
    if (targetA === 'OWP' || targetA === 'OWF') {
      oracle = foundation.owp;
      let safeInp = parseInt(inputHex, 16) || 1234;
      const actualOut = await oracle(safeInp).catch(e => "Error: " + e.message);
      trace.push({ step: "Identity", in: inputHex, out: actualOut });
    } else if (targetA === 'PRG') {
      oracle = async (seed) => {
        let safeSeed = parseInt(seed, 16) || 1234;
        const res = await Backend.pa1Prg(safeSeed, 16);
        return res.out;
      };
      const actualOut = await oracle(inputHex).catch(e => "Error: " + e.message);
      trace.push({ step: "OWP => PRG (HILL)", in: inputHex, out: actualOut });
    } else if (targetA === 'PRF') {
      oracle = async (k, x) => {
        const res = await Backend.pa2Ggm(k, x);
        return res.out;
      };
      const actualOut = await oracle(inputHex, "1011").catch(e => "Error: " + e.message);
      trace.push({ step: "OWP => PRG => PRF", in: inputHex, out: actualOut });
    } else {
      oracle = async () => "STUB_" + targetA;
      trace.push({ step: `DLP -> ${targetA} (Stub)`, in: inputHex, out: "STUB" });
    }
  }
  return { oracle, trace };
};

// --- Leg 2: Source Primitive A -> Target Primitive B ---
export const reducePrimitive = async (sourceType, targetType, sourceOracle, input) => {
  let trace = [];
  let result = null;

  if (sourceType === 'PRG' && targetType === 'PRF') {
    // GGM Tree: F_k(x) = G_{x_n}( ... G_{x_1}(k) )
    // input is an object { k: hex, x: bitstring }
    let state = input.k;
    trace.push({ step: "Init GGM", val: state });
    for (let i = 0; i < input.x.length; i++) {
      let bit = input.x[i];
      let expanded = await sourceOracle(state); 
      if (!expanded) throw new Error("Source oracle returned no output. Check leg 1 input.");
      // Assume expanded is hex string. Split in half.
      let half = Math.floor(expanded.length / 2);
      state = bit === '0' ? expanded.slice(0, half) : expanded.slice(half);
      trace.push({ step: `GGM bit ${bit}`, val: state });
    }
    result = state;
  } else if (sourceType === 'PRF' && targetType === 'MAC') {
    trace.push({ step: "MAC_k(m) = F_k(m)", val: input.m });
    result = await sourceOracle(input.k, input.m);
    trace.push({ step: "Output", val: result });
  } else if (sourceType === 'OWF' && targetType === 'PRG') {
    trace.push({ step: "HILL Construction", val: input.seed || input.k });
    result = await sourceOracle(input.seed || input.k);
    trace.push({ step: "Expanded", val: result });
  } else if (sourceType === 'PRG' && targetType === 'OWF') {
    trace.push({ step: "f(s) = G(s) [Backward]", val: input.seed || input.k });
    result = await sourceOracle(input.seed || input.k);
    trace.push({ step: "Inversion = PRG break", val: result });
  } else if (sourceType === 'PRF' && targetType === 'PRG') {
    trace.push({ step: "G(s) = F_s(0) || F_s(1) [Backward]", val: input.k });
    const b0 = await sourceOracle(input.k, "00000000000000000000000000000000");
    const b1 = await sourceOracle(input.k, "00000000000000000000000000000001");
    result = b0 + b1;
    trace.push({ step: "Concatenated", val: result });
  } else if (sourceType === 'MAC' && targetType === 'PRF') {
    trace.push({ step: "F_k(m) = MAC_k(m) [Backward]", val: input.x || input.m });
    result = await sourceOracle(input.k, input.x || input.m);
    trace.push({ step: "Evaluated MAC as PRF", val: result });
  } else {
    // Generic stub
    result = "STUB_REDUCTION_" + sourceType + "_TO_" + targetType;
    trace.push({ step: "Unsupported Reduction", val: result });
  }

  return { result, trace };
};

export const getProof = (a, b) => {
  const proofs = {
    'PRG-PRF': { theorem: 'GGM Tree', claim: 'If G is a secure PRG, then F is a secure PRF (advantage ε_prf ≤ q * ε_prg).' },
    'PRF-MAC': { theorem: 'MAC_k(m) = F_k(m)', claim: 'If F is a secure PRF, then MAC is EUF-CMA secure (advantage ε_mac ≤ ε_prf).' },
    'PRF-PRP': { theorem: 'Luby-Rackoff (3-round Feistel)', claim: 'If F is a secure PRF, a 3-round Feistel network is a secure PRP.' },
    'OWF-PRG': { theorem: 'HILL Hard-Core Bit', claim: 'If f is a OWF, f(x)||b(x) is a 1-bit expanding PRG.' },
    'PRG-OWF': { theorem: 'f(s) = G(s)', claim: 'If G is a secure PRG, then f is a OWF (inverting f allows distinguishing G).' },
    'PRF-PRG': { theorem: 'G(s) = F_s(0) || F_s(1)', claim: 'If F is a secure PRF, evaluating it on distinct fixed inputs yields a PRG.' },
    'MAC-PRF': { theorem: 'F_k(m) = MAC_k(m)', claim: 'A secure EUF-CMA MAC on uniform messages is a PRF. Distinguishing F breaks the MAC.' },
    'HMAC-CRHF': { theorem: 'H\'(m) = HMAC_k(m)', claim: 'A secure HMAC can be fixed with a key to act as a CRHF.' },
    'MAC-HMAC': { theorem: 'HMAC Structure', claim: 'Any secure PRF-based MAC can be cast into the double-hash HMAC structure.' }
  };
  return proofs[`${a}-${b}`] || { theorem: 'Chain / Unsupported', claim: `No direct implementation provided for ${a} → ${b}.` };
};
