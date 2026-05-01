import React, { useState, useEffect } from 'react';
import './index.css';
import './extra.css';
import { getFoundation, buildSource, reducePrimitive, getProof } from './RoutingTable';

const PRIMITIVES = ['OWF', 'OWP', 'PRG', 'PRF', 'PRP', 'MAC', 'CRHF', 'HMAC'];

function App() {
  const [foundation, setFoundation] = useState('AES');
  const [sourceA, setSourceA] = useState('PRG');
  const [targetB, setTargetB] = useState('PRF');
  
  const [leg1Input, setLeg1Input] = useState('00000000000000000000000000000000');
  const [leg1Trace, setLeg1Trace] = useState([]);
  const [sourceOracle, setSourceOracle] = useState(null);

  const [leg2Input, setLeg2Input] = useState({ k: '00000000000000000000000000000000', m: 'hello', x: '1011' });
  const [leg2Trace, setLeg2Trace] = useState([]);
  const [leg2Result, setLeg2Result] = useState('');

  const [bidirectional, setBidirectional] = useState(false);

  const effectiveSource = bidirectional ? targetB : sourceA;
  const effectiveTarget = bidirectional ? sourceA : targetB;

  // Re-run Leg 1 when Foundation, effectiveSource, or Leg 1 Input changes
  useEffect(() => {
    async function runLeg1() {
      const f = getFoundation(foundation);
      try {
        const { oracle, trace } = await buildSource(f, effectiveSource, leg1Input);
        setSourceOracle(() => oracle);
        setLeg1Trace(trace);
      } catch (e) {
        setLeg1Trace([{ step: 'Error', out: e.message }]);
        setSourceOracle(null);
      }
    }
    runLeg1();
  }, [foundation, effectiveSource, leg1Input]);

  // Re-run Leg 2 when Source Oracle, effectiveTarget, or Leg 2 Input changes
  useEffect(() => {
    async function runLeg2() {
      if (!sourceOracle || sourceA === targetB) {
        setLeg2Trace([]);
        setLeg2Result('N/A (Select different targets)');
        return;
      }
      try {
        const { result, trace } = await reducePrimitive(effectiveSource, effectiveTarget, sourceOracle, leg2Input);
        setLeg2Trace(trace);
        setLeg2Result(result);
      } catch (e) {
        setLeg2Trace([{ step: 'Error', val: e.message }]);
        setLeg2Result('Error');
      }
    }
    runLeg2();
  }, [sourceOracle, effectiveSource, effectiveTarget, leg2Input, sourceA, targetB]);

  const proof = getProof(effectiveSource, effectiveTarget);

  return (
    <div className="layout-container">
      {/* TOP BAR */}
      <header className="topbar">
        <div className="logo">
          <div className="logo-icon">C</div>
          <div className="logo-text">Minicrypt <em>Explorer</em></div>
        </div>
        <div className="bar-section">
          <span className="bar-label">Foundation:</span>
          <div className="seg">
            <button className={foundation === 'AES' ? 'on' : ''} onClick={() => setFoundation('AES')}>AES-128 (PRP)</button>
            <button className={foundation === 'DLP' ? 'on' : ''} onClick={() => setFoundation('DLP')}>DLP (OWP)</button>
          </div>
        </div>
        <div className="bar-section">
          <span className="bar-label">Mode:</span>
          <div className="seg">
            <button className={!bidirectional ? 'on' : ''} onClick={() => setBidirectional(false)}>Forward (A → B)</button>
            <button className={bidirectional ? 'on' : ''} onClick={() => setBidirectional(true)}>Backward (B → A)</button>
          </div>
        </div>
        <a href="/demos/index.html" className="demo-link">View Individual PA Demos →</a>
      </header>

      {/* MAIN LAYOUT */}
      <div className="layout">
        {/* COLUMN 1 */}
        <div className="panel">
          <div className="panel-head">
            <div className="panel-leg">
              <div className="leg-indicator"></div> Column 1: Foundation → {bidirectional ? 'Target' : 'Source'}
            </div>
            <div className="panel-title">
              Instantiate {bidirectional ? 'Target' : 'Source'} Primitive <span className="arrow-badge">{bidirectional ? 'B' : 'A'}</span>
            </div>
          </div>
          <div className="panel-body">
            <div className="fg">
              <label className="fl">Source Primitive (A)</label>
              <select value={sourceA} onChange={(e) => setSourceA(e.target.value)}>
                {PRIMITIVES.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div className="fg">
              <label className="fl">Foundation Input (Key/Seed Hex)</label>
              <input type="text" value={leg1Input} onChange={(e) => setLeg1Input(e.target.value)} />
            </div>

            <div className="trace-box">
              <div className="trace-header">Construction Trace</div>
              {leg1Trace.map((t, i) => (
                <div key={i} className="trace-step">
                  <div className="ts-op">{t.step}</div>
                  <div className="ts-val">In: {t.in}</div>
                  <div className="ts-val">Out: {t.out}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* COLUMN 2 */}
        <div className="panel">
          <div className="panel-head">
            <div className="panel-leg">
              <div className="leg-indicator" style={{background: 'var(--green)'}}></div> Column 2: {bidirectional ? 'Target → Source' : 'Source → Target'}
            </div>
            <div className="panel-title">
              Black-box Reduction <span className="arrow-badge">{bidirectional ? 'B → A' : 'A → B'}</span>
            </div>
          </div>
          <div className="panel-body">
            <div className="fg">
              <label className="fl">Target Primitive (B)</label>
              <select value={targetB} onChange={(e) => setTargetB(e.target.value)}>
                {PRIMITIVES.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div className="fg">
              <label className="fl">Reduction Query (m / x)</label>
              <input type="text" value={leg2Input.x} onChange={(e) => setLeg2Input({...leg2Input, x: e.target.value})} />
            </div>

            <div className="trace-box" style={{borderColor: 'rgba(110,231,183,0.3)'}}>
              <div className="trace-header" style={{color: 'var(--green)'}}>Reduction Trace</div>
              {leg2Trace.map((t, i) => (
                <div key={i} className="trace-step">
                  <div className="ts-op">{t.step}</div>
                  <div className="ts-val">{t.val}</div>
                </div>
              ))}
              <div className="trace-result">
                <strong>Final B Output:</strong> {leg2Result}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* PROOF PANEL */}
      <details className="proof-panel" open>
        <summary className="proof-head">
          <span>Reduction Chain Summary</span>
          <span className="thm-tag">{proof.theorem}</span>
        </summary>
        <div className="proof-body">
          <p><strong>Path:</strong> {foundation} → {effectiveSource} → {effectiveTarget}</p>
          <p><strong>Security Claim:</strong> {proof.claim}</p>
          <p className="under-hood-note"><em>Note: Column 2 never directly invokes {foundation}. It exclusively calls the JavaScript wrapper for {effectiveSource}, demonstrating a perfect black-box reduction.</em></p>
        </div>
      </details>
    </div>
  );
}

export default App;
