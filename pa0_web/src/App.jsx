import { useMemo, useState } from "react";
import {
  PA_DUE,
  SOURCE_PRIMITIVES,
  TARGET_PRIMITIVES,
  buildSourcePrimitive,
  formatHex,
} from "./crypto/foundations";
import { reduceBetweenPrimitives, theoremChain } from "./crypto/reductions";

function StepCard({ step, showDue = false }) {
  return (
    <div className={`step-card ${step.placeholder ? "step-card-stub" : ""}`}>
      <div className="step-head">
        <strong>{step.title || `${step.from} -> ${step.to}`}</strong>
        <span>{step.theorem}</span>
      </div>
      <div className="step-row">
        <span>Input</span>
        <code>{step.inputHex}</code>
      </div>
      <div className="step-row">
        <span>Output</span>
        <code>{step.outputHex}</code>
      </div>
      {step.detail && (
        <div className="step-row">
          <span>Rule</span>
          <small>{step.detail}</small>
        </div>
      )}
      {step.trace && step.trace.length > 0 && (
        <div className="trace-list">
          {step.trace.map((entry) => (
            <div className="trace-item" key={`${step.title}-${entry.label}`}>
              <span>{entry.label}</span>
              <code>{entry.value}</code>
            </div>
          ))}
        </div>
      )}
      {showDue && !step.implemented && (
        <div className="due-tag">Not implemented yet (due: {step.due || PA_DUE[step.to] || "TBD"})</div>
      )}
      {showDue && step.placeholder && (
        <div className="due-tag">Placeholder output is used for PA#0 demo.</div>
      )}
    </div>
  );
}

function PrimitiveSelect({ label, value, options, onChange }) {
  return (
    <label className="field">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((primitive) => (
          <option key={primitive} value={primitive}>
            {primitive}
          </option>
        ))}
      </select>
    </label>
  );
}

export default function App() {
  const [foundation, setFoundation] = useState("AES");
  const [mode, setMode] = useState("forward");
  const [sourceA, setSourceA] = useState("PRG");
  const [targetB, setTargetB] = useState("PRF");
  const [seedHex, setSeedHex] = useState("a3f2c1b4e9d05678feedcafe");
  const [queryHex, setQueryHex] = useState("1011");

  const effectiveSource = mode === "forward" ? sourceA : targetB;
  const effectiveTarget = mode === "forward" ? targetB : sourceA;

  const leg1 = useMemo(
    () => buildSourcePrimitive(foundation, effectiveSource, formatHex(seedHex)),
    [foundation, effectiveSource, seedHex]
  );

  const leg2 = useMemo(
    () =>
      reduceBetweenPrimitives(
        mode,
        effectiveSource,
        effectiveTarget,
        leg1.instance,
        formatHex(queryHex)
      ),
    [mode, effectiveSource, effectiveTarget, leg1.instance, queryHex]
  );

  const summary = useMemo(
    () => theoremChain(mode, foundation, effectiveSource, effectiveTarget, leg1.steps, leg2.steps),
    [mode, foundation, effectiveSource, effectiveTarget, leg1.steps, leg2.steps]
  );

  const leg1Panel = (
    <section className="panel">
      <header className="panel-header">
        <p>Leg 1</p>
        <h2>Build: {foundation} {"->"} {effectiveSource}</h2>
      </header>
      <PrimitiveSelect
        label="Source primitive A"
        value={sourceA}
        options={SOURCE_PRIMITIVES}
        onChange={(next) => {
          setSourceA(next);
          if (next === targetB) {
            setTargetB("PRF");
          }
        }}
      />
      <label className="field">
        <span>Input key/seed (hex)</span>
        <input value={seedHex} onChange={(event) => setSeedHex(event.target.value)} />
      </label>
      <div className="step-list">
        {leg1.steps.map((step) => (
          <StepCard key={step.title} step={step} showDue />
        ))}
      </div>
      <div className="panel-output">
        <strong>Concrete {effectiveSource} oracle output</strong>
        <code>{leg1.instance.evaluate(formatHex(queryHex))}</code>
      </div>
    </section>
  );

  const leg2Panel = (
    <section className="panel">
      <header className="panel-header">
        <p>Leg 2</p>
        <h2>Reduce: {effectiveSource} {"->"} {effectiveTarget}</h2>
      </header>
      <PrimitiveSelect
        label="Target primitive B"
        value={targetB}
        options={TARGET_PRIMITIVES.filter((item) => item !== sourceA)}
        onChange={(next) => setTargetB(next)}
      />
      <label className="field">
        <span>Message/query</span>
        <input value={queryHex} onChange={(event) => setQueryHex(event.target.value)} />
      </label>
      {leg2.unsupported ? (
        <div className="unsupported">
          {leg2.message}
          <div>Hint: use {mode === "forward" ? "Backward (B -> A)" : "Forward (A -> B)"} mode.</div>
        </div>
      ) : (
        <div className="step-list">
          {leg2.steps.map((step) => (
            <StepCard key={`${step.from}-${step.to}-${step.index}`} step={step} showDue />
          ))}
        </div>
      )}
      <div className="panel-output">
        <strong>Reduction output ({effectiveTarget})</strong>
        <code>{leg2.finalOutput || "--"}</code>
      </div>
      <small className="blackbox-note">
        Column 2 only receives the oracle function produced by Column 1, never the foundation internals.
      </small>
    </section>
  );

  return (
    <div className="app-shell">
      <header className="topbar">
        <h1>CS8.401 Minicrypt Clique Explorer</h1>
        <div className="controls">
          <div className="toggle">
            <span>Foundation</span>
            <button
              type="button"
              className={foundation === "AES" ? "active" : ""}
              onClick={() => setFoundation("AES")}
            >
              AES-128 (PRP)
            </button>
            <button
              type="button"
              className={foundation === "DLP" ? "active" : ""}
              onClick={() => setFoundation("DLP")}
            >
              DLP (g^x mod p)
            </button>
          </div>
          <div className="toggle">
            <span>Direction</span>
            <button
              type="button"
              className={mode === "forward" ? "active" : ""}
              onClick={() => setMode("forward")}
            >
              Forward (A {"->"} B)
            </button>
            <button
              type="button"
              className={mode === "backward" ? "active" : ""}
              onClick={() => setMode("backward")}
            >
              Backward (B {"->"} A)
            </button>
          </div>
        </div>
      </header>

      <main className="main-grid">
        {mode === "forward" ? (
          <>
            {leg1Panel}
            {leg2Panel}
          </>
        ) : (
          <>
            {leg2Panel}
            {leg1Panel}
          </>
        )}
      </main>

      <details className="proof-panel">
        <summary>Reduction proof summary</summary>
        <div className="proof-content">
          <h3>{summary.header}</h3>
          <ul>
            {summary.lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          <p>
            Security chain: if an adversary breaks {effectiveTarget} with advantage eps, there exists a reduction that
            breaks {effectiveSource} with advantage eps' {">="} eps/q.
          </p>
        </div>
      </details>
    </div>
  );
}
