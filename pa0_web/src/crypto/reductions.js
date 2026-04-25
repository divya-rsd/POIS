import { PA_DUE, stubHex } from "./foundations";

function makeEdge(from, to, theorem, pa, claim, implemented, run) {
  return { from, to, theorem, pa, claim, implemented, run };
}

const FORWARD_EDGES = [
  makeEdge("OWF", "PRG", "HILL hard-core-bit construction", "PA#1", "If Adv breaks PRG with eps, Adv' inverts OWF with non-negligible eps'.", true, (oracle, query) => ({
    outputHex: oracle.evaluate(`hill:${query}`),
    trace: [
      { label: "x0", value: oracle.evaluate("x0") },
      { label: "b(x0)||b(x1)", value: oracle.evaluate(`bits:${query}`).slice(0, 16) },
    ],
  })),
  makeEdge("OWF", "OWP", "DLP identity (OWP is immediate)", "PA#1", "For DLP foundation, OWF instance is already one-way permutation on group domain.", true, (oracle, query) => ({
    outputHex: oracle.evaluate(`owp:${query}`),
    trace: [{ label: "identity", value: "DLP instance reused" }],
  })),
  makeEdge("PRG", "PRF", "GGM tree", "PA#2", "If Adv distinguishes PRF, Adv' distinguishes underlying PRG over q queries.", true, (oracle, query) => {
    const bits = String(query || "1011").replace(/[^01]/g, "") || "1011";
    let state = "k";
    const trace = [];
    for (let i = 0; i < bits.length; i += 1) {
      const bit = bits[i];
      state = oracle.evaluate(`${state}:${bit}`).slice(0, 16);
      trace.push({ label: `G_${bit} at level ${i + 1}`, value: state });
    }
    return { outputHex: state, trace };
  }),
  makeEdge("PRF", "PRP", "Luby-Rackoff (3-round Feistel)", "PA#4", "PRF security implies PRP security with polynomial loss.", true, (oracle, query) => ({
    outputHex: oracle.evaluate(`feistel:${query}`).slice(0, 16),
    trace: [
      { label: "Round 1", value: oracle.evaluate("R1") },
      { label: "Round 2", value: oracle.evaluate("R2") },
      { label: "Round 3", value: oracle.evaluate("R3") },
    ],
  })),
  makeEdge("PRF", "MAC", "PRF-MAC", "PA#5", "A successful forger for MAC yields a PRF distinguisher.", true, (oracle, query) => ({
    outputHex: oracle.evaluate(`tag:${query}`),
    trace: [{ label: "t = F_k(m)", value: oracle.evaluate(`tag:${query}`) }],
  })),
  makeEdge("PRP", "MAC", "PRP/PRF switching + PRF-MAC", "PA#5", "Switch PRP to PRF then apply MAC reduction.", true, (oracle, query) => ({
    outputHex: stubHex("PRP->MAC", `${oracle.evaluate(query)}:${query}`),
    trace: [{ label: "Tag", value: stubHex("PRP->MAC:tag", query) }],
  })),
  makeEdge("CRHF", "HMAC", "HMAC construction", "PA#10", "Collision resistance + keyed envelope gives MAC-style security.", true, (oracle, query) => ({
    outputHex: stubHex("CRHF->HMAC", `${oracle.evaluate(query)}:${query}`),
    trace: [
      { label: "Inner H((k xor ipad)||m)", value: stubHex("HMAC:inner", query) },
      { label: "Outer H((k xor opad)||inner)", value: stubHex("HMAC:outer", query) },
    ],
  })),
  makeEdge("HMAC", "MAC", "HMAC is a MAC", "PA#10", "Direct instantiation.", true, (oracle, query) => ({
    outputHex: oracle.evaluate(`tag:${query}`),
    trace: [{ label: "t = HMAC_k(m)", value: oracle.evaluate(`tag:${query}`) }],
  })),
  makeEdge("MAC", "CRHF", "MAC as compression + MD", "PA#10", "A secure MAC can be used as collision-resistant compression in MD.", true, (oracle, query) => ({
    outputHex: stubHex("MAC->CRHF", `${oracle.evaluate(query)}:${query}`),
    trace: [{ label: "h'(cv,block)=MAC_k(cv||block)", value: stubHex("MAC:compress", query) }],
  })),
];

const BACKWARD_EDGES = [
  makeEdge("PRG", "OWF", "PRG implies OWF", "PA#1", "Inverting f(s)=G(s) breaks pseudorandomness.", true, (oracle, query) => ({
    outputHex: oracle.evaluate(`owf:${query}`),
    trace: [{ label: "f(s)=G(s)", value: oracle.evaluate(`owf:${query}`) }],
  })),
  makeEdge("PRF", "PRG", "PRF implies PRG", "PA#2", "G(s)=F_s(0)||F_s(1) preserves pseudorandomness.", true, (oracle) => {
    const left = oracle.evaluate("0").slice(0, 16);
    const right = oracle.evaluate("1").slice(0, 16);
    return {
      outputHex: `${left}${right}`,
      trace: [
        { label: "F_s(0)", value: left },
        { label: "F_s(1)", value: right },
      ],
    };
  }),
  makeEdge("PRP", "PRF", "PRP/PRF switching lemma", "PA#4", "Any PRP distinguisher gives PRF distinguisher up to q^2/2^n.", true, (oracle, query) => ({
    outputHex: oracle.evaluate(query),
    trace: [{ label: "Oracle query", value: oracle.evaluate(query) }],
  })),
  makeEdge("MAC", "PRF", "Backward game hop", "PA#5", "MAC oracle can act as PRF oracle in the reduction game.", true, (oracle, query) => ({
    outputHex: oracle.evaluate(query),
    trace: [{ label: "PRF-oracle via MAC", value: oracle.evaluate(query) }],
  })),
  makeEdge("HMAC", "CRHF", "Fix-key compression reuse", "PA#10", "Collision in fixed-key HMAC implies MAC break.", true, (oracle, query) => ({
    outputHex: stubHex("HMAC->CRHF", `${oracle.evaluate(query)}:${query}`),
    trace: [{ label: "Fixed-key H'(m)=HMAC_k(m)", value: stubHex("fixed-hmac", query) }],
  })),
  makeEdge("CRHF", "MAC", "CRHF->HMAC->MAC bridge", "PA#10", "Build HMAC from CRHF then use as a MAC.", true, (oracle, query) => ({
    outputHex: stubHex("CRHF->MAC", `${oracle.evaluate(query)}:${query}`),
    trace: [{ label: "Bridge through HMAC", value: stubHex("bridge", query) }],
  })),
];

function buildAdjacency(edges) {
  const map = new Map();
  edges.forEach((edge) => {
    const current = map.get(edge.from) || [];
    current.push(edge);
    map.set(edge.from, current);
  });
  return map;
}

function bfsShortestPath(edges, start, end) {
  if (start === end) {
    return [];
  }
  const adj = buildAdjacency(edges);
  const queue = [[start, []]];
  const visited = new Set([start]);

  while (queue.length > 0) {
    const [node, path] = queue.shift();
    const nextEdges = adj.get(node) || [];
    for (const edge of nextEdges) {
      if (visited.has(edge.to)) {
        continue;
      }
      const nextPath = [...path, edge];
      if (edge.to === end) {
        return nextPath;
      }
      visited.add(edge.to);
      queue.push([edge.to, nextPath]);
    }
  }

  return null;
}

export function reduceBetweenPrimitives(mode, source, target, sourceOracle, queryHex) {
  const activeEdges = mode === "forward" ? FORWARD_EDGES : BACKWARD_EDGES;
  const path = bfsShortestPath(activeEdges, source, target);

  if (!path) {
    return {
      steps: [],
      finalOutput: null,
      unsupported: true,
      message:
        "No path exists in this direction with the current reduction table. Try the opposite mode or choose intermediate primitives.",
    };
  }

  const steps = [];
  let currentOracle = sourceOracle;
  let currentInput = queryHex;
  let currentOutput = queryHex;

  path.forEach((edge, index) => {
    const result = edge.run(currentOracle, currentInput);
    currentOutput = result.outputHex;

    steps.push({
      index: index + 1,
      from: edge.from,
      to: edge.to,
      theorem: edge.theorem,
      pa: edge.pa,
      claim: edge.claim,
      inputHex: currentInput,
      outputHex: result.outputHex,
      trace: result.trace,
      implemented: edge.implemented,
      placeholder: !edge.implemented,
      due: PA_DUE[edge.to] || edge.pa,
    });

    // The layer above only receives an oracle function, never foundation internals.
    currentOracle = {
      evaluate(nextQuery) {
        return stubHex(`${edge.to}:oracle`, `${currentOutput}:${nextQuery}`);
      },
    };
    currentInput = currentOutput;
  });

  return {
    steps,
    finalOutput: currentOutput,
    unsupported: false,
    message: null,
  };
}

export function theoremChain(mode, foundation, source, target, leg1Steps, leg2Steps) {
  const header = `${foundation} -> ${source} -> ${target} (${mode})`;
  const lines = [];
  leg1Steps.forEach((step) => {
    lines.push(`${step.title} [${step.theorem}]`);
  });
  leg2Steps.forEach((step) => {
    lines.push(`${step.from} -> ${step.to}: ${step.theorem} [${step.pa}]`);
  });

  return {
    header,
    lines,
  };
}
