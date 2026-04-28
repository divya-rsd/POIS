async function runTest() {
    const n = document.getElementById('inp-n').value.trim();
    const k = parseInt(document.getElementById('inp-k').value);
    const btn = document.getElementById('btn-run');
    
    if (!n) {
        alert("Please enter a number.");
        return;
    }
    
    btn.disabled = true;
    document.getElementById('result-banner').style.display = 'none';
    document.getElementById('trace-container').style.display = 'none';
    document.getElementById('trace-body').innerHTML = 'Testing...';
    
    try {
        const res = await fetch('/api/pa13/miller_rabin', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ n, k })
        });
        const data = await res.json();
        
        if (data.error) {
            alert(data.error);
            return;
        }
        
        const banner = document.getElementById('result-banner');
        if (data.is_prime) {
            banner.className = 'result-banner prime';
            banner.innerHTML = '✨ PROBABLY PRIME ✨';
        } else {
            banner.className = 'result-banner composite';
            banner.innerHTML = '🚨 DEFINITELY COMPOSITE 🚨';
        }
        banner.style.display = 'block';
        
        document.getElementById('trace-time').innerText = `Time: ${data.time_ms}ms`;
        
        const tb = document.getElementById('trace-body');
        tb.innerHTML = '';
        
        data.trace.forEach((r, idx) => {
            const div = document.createElement('div');
            div.className = 'trace-round';
            div.innerHTML = `[Round ${idx+1}] <span class="lbl">Witness a:</span> <span class="val">${r.a}</span><br>
                             &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="lbl">Exponentiation x:</span> <span class="val">${r.x}</span> ➔ <span>${r.result.toUpperCase()}</span>`;
            tb.appendChild(div);
        });
        
        document.getElementById('trace-container').style.display = 'block';
        
    } catch(err) {
        console.error(err);
        alert("Backend connection failed.");
    } finally {
        btn.disabled = false;
    }
}
