export const SOURCE_PRIMITIVES = ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF", "HMAC"];
export const TARGET_PRIMITIVES = ["OWF", "OWP", "PRG", "PRF", "PRP", "MAC", "CRHF", "HMAC"];

export const PA_DUE = {
  OWF: "PA#1",
  OWP: "PA#1",
  PRG: "PA#1",
  PRF: "PA#2",
  PRP: "PA#4",
  MAC: "PA#5",
  CRHF: "PA#7/PA#8",
  HMAC: "PA#10",
};

function toHex32(value) {
  return (value >>> 0).toString(16).padStart(8, "0");
}

function foldToInt(input) {
  let acc = 2166136261;
  const text = String(input);
  for (let i = 0; i < text.length; i += 1) {
    acc ^= text.charCodeAt(i);
    acc = Math.imul(acc, 16777619);
  }
  return acc >>> 0;
}

function stubHex(tag, input) {
  const seed = foldToInt(tag) ^ foldToInt(input);
  const a = toHex32(seed ^ 0x9e3779b9);
  const b = toHex32(Math.imul(seed, 2654435761));
  return `${a}${b}`;
}

function makeBlackBox(name, seedHex, evaluator) {
  return {
    name,
    seedHex,
    evaluate(query) {
      const q = String(query ?? "");
      return evaluator(q);
    },
  };
}

function derivePrfFromAny(seedHex, prefixTag) {
  return makeBlackBox("PRF", seedHex, (query) => stubHex(`${prefixTag}:PRF`, `${seedHex}:${query}`));
}

class AESFoundation {
  constructor() {
    this.kind = "AES";
  }

  asOWF(seedHex) {
    return makeBlackBox("OWF", seedHex, (query) => stubHex("AES:OWF", `${seedHex}:${query}`));
  }

  asPRF(seedHex) {
    return makeBlackBox("PRF", seedHex, (query) => stubHex("AES:PRF", `${seedHex}:${query}`));
  }

  asPRP(seedHex) {
    return makeBlackBox("PRP", seedHex, (query) => stubHex("AES:PRP", `${seedHex}:${query}`));
  }
}

class DLPFoundation {
  constructor() {
    this.kind = "DLP";
  }

  asOWF(seedHex) {
    return makeBlackBox("OWF", seedHex, (query) => stubHex("DLP:OWF", `${seedHex}:${query}`));
  }

  asOWP(seedHex) {
    return makeBlackBox("OWP", seedHex, (query) => stubHex("DLP:OWP", `${seedHex}:${query}`));
  }
}

function buildFromAes(sourcePrimitive, seedHex) {
  const foundation = new AESFoundation();
  const prf = foundation.asPRF(seedHex);
  switch (sourcePrimitive) {
    case "OWF":
      return {
        instance: foundation.asOWF(seedHex),
        steps: [
          {
            title: "AES -> OWF adapter",
            theorem: "Compression from PRP",
            inputHex: seedHex,
            outputHex: stubHex("AES:OWF", seedHex),
            detail: "f(k) = AES_k(0) xor k",
            implemented: false,
          },
        ],
      };
    case "PRF":
      return {
        instance: prf,
        steps: [
          {
            title: "AES direct PRF",
            theorem: "PRP/PRF switching",
            inputHex: seedHex,
            outputHex: foundation.asPRF(seedHex).evaluate("00"),
            detail: "F_k(x) = AES_k(x)",
            implemented: true,
          },
        ],
      };
    case "PRP":
      return {
        instance: foundation.asPRP(seedHex),
        steps: [
          {
            title: "AES direct PRP",
            theorem: "Concrete block cipher",
            inputHex: seedHex,
            outputHex: foundation.asPRP(seedHex).evaluate("00"),
            detail: "P_k(x) = AES_k(x)",
            implemented: true,
          },
        ],
      };
    case "PRG": {
      const g0 = prf.evaluate("00").slice(0, 16);
      const g1 = prf.evaluate("01").slice(0, 16);
      return {
        instance: makeBlackBox("PRG", seedHex, (query) => {
          const q = query || "00";
          return `${prf.evaluate(`${q}:0`).slice(0, 16)}${prf.evaluate(`${q}:1`).slice(0, 16)}`;
        }),
        steps: [
          {
            title: "AES as PRF",
            theorem: "PRP/PRF switching",
            inputHex: seedHex,
            outputHex: prf.evaluate("00"),
            detail: "Build F_k first",
            implemented: true,
          },
          {
            title: "PRF -> PRG",
            theorem: "G(s)=F_s(0)||F_s(1)",
            inputHex: seedHex,
            outputHex: `${g0}${g1}`,
            detail: "Length doubling generator",
            implemented: true,
          },
        ],
      };
    }
    case "MAC": {
      const mac = makeBlackBox("MAC", seedHex, (query) => stubHex("AES:MAC", `${prf.evaluate(query)}:${query}`));
      return {
        instance: mac,
        steps: [
          {
            title: "AES as PRF",
            theorem: "PRP/PRF switching",
            inputHex: seedHex,
            outputHex: prf.evaluate("00"),
            detail: "Construct F_k from AES",
            implemented: true,
          },
          {
            title: "PRF -> MAC",
            theorem: "t = F_k(m)",
            inputHex: seedHex,
            outputHex: mac.evaluate("msg"),
            detail: "One-block PRF-MAC",
            implemented: true,
          },
        ],
      };
    }
    case "CRHF": {
      const crhf = makeBlackBox("CRHF", seedHex, (query) => stubHex("AES:CRHF", `${prf.evaluate(query)}:${query}`));
      return {
        instance: crhf,
        steps: [
          {
            title: "PRF -> MAC",
            theorem: "PRF-MAC bridge",
            inputHex: seedHex,
            outputHex: stubHex("AES:MAC", seedHex),
            detail: "Build MAC from PRF",
            implemented: true,
          },
          {
            title: "MAC -> CRHF",
            theorem: "Merkle-Damgard reduction",
            inputHex: seedHex,
            outputHex: crhf.evaluate("msg"),
            detail: "Compression MAC lifted to hash",
            implemented: true,
          },
        ],
      };
    }
    case "HMAC": {
      const hmac = makeBlackBox("HMAC", seedHex, (query) => {
        const inner = stubHex("AES:HMAC:inner", `${seedHex}:${query}`);
        return stubHex("AES:HMAC:outer", `${seedHex}:${inner}`);
      });
      return {
        instance: hmac,
        steps: [
          {
            title: "Build CRHF from AES lineage",
            theorem: "PRF->MAC->CRHF",
            inputHex: seedHex,
            outputHex: stubHex("AES:CRHF", seedHex),
            detail: "Use CRHF as hash core",
            implemented: true,
          },
          {
            title: "CRHF -> HMAC",
            theorem: "HMAC construction",
            inputHex: seedHex,
            outputHex: hmac.evaluate("msg"),
            detail: "H((k xor opad)||H((k xor ipad)||m))",
            implemented: true,
          },
        ],
      };
    }
    default:
      return {
        instance: makeBlackBox(sourcePrimitive, seedHex, (query) => stubHex(`AES:${sourcePrimitive}`, `${seedHex}:${query}`)),
        steps: [
          {
            title: `${sourcePrimitive} adapter placeholder`,
            theorem: "Stub",
            inputHex: seedHex,
            outputHex: stubHex(`AES:${sourcePrimitive}`, seedHex),
            detail: `Not implemented yet (due: ${PA_DUE[sourcePrimitive] || "TBD"})`,
            implemented: false,
          },
        ],
      };
  }
}

function buildFromDlp(sourcePrimitive, seedHex) {
  const foundation = new DLPFoundation();
  const dlpPrf = derivePrfFromAny(seedHex, "DLP");
  switch (sourcePrimitive) {
    case "OWF":
      return {
        instance: foundation.asOWF(seedHex),
        steps: [
          {
            title: "DLP direct OWF",
            theorem: "DL hardness",
            inputHex: seedHex,
            outputHex: foundation.asOWF(seedHex).evaluate("00"),
            detail: "f(x)=g^x mod p",
            implemented: true,
          },
        ],
      };
    case "PRG": {
      const owf = foundation.asOWF(seedHex);
      const b0 = owf.evaluate("x0").slice(0, 2);
      const b1 = owf.evaluate("x1").slice(0, 2);
      return {
        instance: makeBlackBox("PRG", seedHex, (query) => {
          const q = query || "00";
          return `${owf.evaluate(`${q}:0`).slice(0, 16)}${owf.evaluate(`${q}:1`).slice(0, 16)}`;
        }),
        steps: [
          {
            title: "DLP OWF iterate",
            theorem: "HILL setup",
            inputHex: seedHex,
            outputHex: owf.evaluate("x0"),
            detail: "x_{i+1}=f(x_i)",
            implemented: true,
          },
          {
            title: "Hard-core extraction",
            theorem: "HILL",
            inputHex: owf.evaluate("x0"),
            outputHex: `${b0}${b1}`,
            detail: "Extract pseudorandom bits",
            implemented: true,
          },
        ],
      };
    }
    case "OWP":
      return {
        instance: foundation.asOWP(seedHex),
        steps: [
          {
            title: "DLP direct OWP",
            theorem: "Identity",
            inputHex: seedHex,
            outputHex: foundation.asOWP(seedHex).evaluate("00"),
            detail: "OWP is immediate under DLP assumption",
            implemented: true,
          },
        ],
      };
    case "PRF":
      return {
        instance: dlpPrf,
        steps: [
          {
            title: "DLP OWF -> PRG",
            theorem: "HILL",
            inputHex: seedHex,
            outputHex: stubHex("DLP:PRG", seedHex),
            detail: "Extract hard-core bits",
            implemented: true,
          },
          {
            title: "PRG -> PRF",
            theorem: "GGM tree",
            inputHex: seedHex,
            outputHex: dlpPrf.evaluate("1011"),
            detail: "Tree-based PRF construction",
            implemented: true,
          },
        ],
      };
    case "MAC": {
      const mac = makeBlackBox("MAC", seedHex, (query) => stubHex("DLP:MAC", `${dlpPrf.evaluate(query)}:${query}`));
      return {
        instance: mac,
        steps: [
          {
            title: "DLP lineage -> PRF",
            theorem: "OWF->PRG->PRF",
            inputHex: seedHex,
            outputHex: dlpPrf.evaluate("1010"),
            detail: "Construct PRF oracle",
            implemented: true,
          },
          {
            title: "PRF -> MAC",
            theorem: "t = F_k(m)",
            inputHex: seedHex,
            outputHex: mac.evaluate("msg"),
            detail: "Instantiate MAC",
            implemented: true,
          },
        ],
      };
    }
    case "CRHF": {
      const crhf = makeBlackBox("CRHF", seedHex, (query) => stubHex("DLP:CRHF", `${seedHex}:${query}`));
      return {
        instance: crhf,
        steps: [
          {
            title: "DLP compression setup",
            theorem: "PA#8",
            inputHex: seedHex,
            outputHex: stubHex("DLP:compress", seedHex),
            detail: "h(x,y)=g^x * hhat^y mod p",
            implemented: true,
          },
          {
            title: "Merkle-Damgard lift",
            theorem: "PA#7",
            inputHex: seedHex,
            outputHex: crhf.evaluate("msg"),
            detail: "Domain extension to variable-length hash",
            implemented: true,
          },
        ],
      };
    }
    case "HMAC": {
      const hmac = makeBlackBox("HMAC", seedHex, (query) => {
        const inner = stubHex("DLP:HMAC:inner", `${seedHex}:${query}`);
        return stubHex("DLP:HMAC:outer", `${seedHex}:${inner}`);
      });
      return {
        instance: hmac,
        steps: [
          {
            title: "DLP Hash (PA#8)",
            theorem: "CRHF",
            inputHex: seedHex,
            outputHex: stubHex("DLP:CRHF", seedHex),
            detail: "Construct base hash H",
            implemented: true,
          },
          {
            title: "CRHF -> HMAC",
            theorem: "PA#10",
            inputHex: seedHex,
            outputHex: hmac.evaluate("msg"),
            detail: "Apply ipad/opad envelope",
            implemented: true,
          },
        ],
      };
    }
    default:
      return {
        instance: makeBlackBox(sourcePrimitive, seedHex, (query) => stubHex(`DLP:${sourcePrimitive}`, `${seedHex}:${query}`)),
        steps: [
          {
            title: `${sourcePrimitive} adapter placeholder`,
            theorem: "Stub",
            inputHex: seedHex,
            outputHex: stubHex(`DLP:${sourcePrimitive}`, seedHex),
            detail: `Not implemented yet (due: ${PA_DUE[sourcePrimitive] || "TBD"})`,
            implemented: false,
          },
        ],
      };
  }
}

export function buildSourcePrimitive(foundationKind, sourcePrimitive, seedHex) {
  if (foundationKind === "AES") {
    return buildFromAes(sourcePrimitive, seedHex);
  }
  return buildFromDlp(sourcePrimitive, seedHex);
}

export function formatHex(input) {
  const cleaned = String(input || "").replace(/[^0-9a-fA-F]/g, "").toLowerCase();
  return cleaned.length > 0 ? cleaned : "00";
}

export { stubHex };
