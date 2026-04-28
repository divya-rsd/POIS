function toggleTrace() {
    const body = document.getElementById('trace-body');
    const caret = document.getElementById('trace-caret');
    if (body.style.display === 'block') {
        body.style.display = 'none';
        caret.innerText = '▼';
    } else {
        body.style.display = 'block';
        caret.innerText = '▲';
    }
}

async function runMillionaires() {
    const x = parseInt(document.getElementById('alice-x').value);
    const y = parseInt(document.getElementById('bob-y').value);
    const btn = document.getElementById('btn-run');
    const pbg = document.getElementById('progress-bg');
    const pfill = document.getElementById('progress-fill');
    const resBan = document.getElementById('result-banner');
    const traceCon = document.getElementById('trace-container');
    const traceBody = document.getElementById('trace-body');
    
    btn.disabled = true;
    resBan.style.display = 'none';
    traceCon.style.display = 'none';
    traceBody.innerHTML = '';
    
    pbg.style.display = 'block';
    pfill.style.width = '0%';
    
    try {
        const res = await fetch('/api/pa20/millionaires', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ x, y })
        });
        const data = await res.json();
        
        // Animate the trace to simulate gate-by-gate evaluation
        const trace = data.trace || [];
        const totalGates = trace.length;
        
        for (let i = 0; i < totalGates; i++) {
            const gate = trace[i];
            
            // Render gate into trace body
            const div = document.createElement('div');
            div.className = 'trace-gate';
            div.innerHTML = `[Wire ${gate.output_wire}] = <span class="op-${gate.op}">${gate.op}</span>(wires: [${gate.inputs.join(', ')}]) ➔ <span style="color:#fff">${gate.output_val}</span>`;
            traceBody.appendChild(div);
            
            // Update progress
            const pct = Math.round(((i + 1) / totalGates) * 100);
            pfill.style.width = `${pct}%`;
            
            // Auto scroll trace
            traceBody.scrollTop = traceBody.scrollHeight;
            
            // Wait 15ms per gate for a fast but visible animation
            await new Promise(r => setTimeout(r, 15));
        }
        
        // Show result
        pbg.style.display = 'none';
        resBan.innerText = data.result;
        resBan.style.display = 'block';
        traceCon.style.display = 'block';
        
    } catch(err) {
        console.error(err);
        alert("Backend connection failed.");
    } finally {
        btn.disabled = false;
    }
}
