let logDiv;

window.onload = () => {
    logDiv = document.getElementById('chat-log');
}

function log(msg, cls="log-sys") {
    const d = document.createElement('div');
    d.className = `log-entry ${cls}`;
    d.innerHTML = msg;
    logDiv.appendChild(d);
    logDiv.scrollTop = logDiv.scrollHeight;
}

async function computeAND() {
    const a = parseInt(document.getElementById('inp-a').value);
    const b = parseInt(document.getElementById('inp-b').value);
    
    logDiv.innerHTML = "";
    document.getElementById('privacy-box').style.display = 'none';
    document.getElementById('truth-table').style.display = 'none';
    
    log(`Alice holds a=${a}. Bob holds b=${b}. Starting Secure AND protocol...`, 'log-sys');
    
    try {
        const res = await fetch('/api/pa19/demo_and', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ a, b })
        });
        const data = await res.json();
        
        await new Promise(r => setTimeout(r, 600));
        log(`Alice sets up OT messages (m0=0, m1=${a}).`, 'log-alice');
        
        await new Promise(r => setTimeout(r, 600));
        log(`Bob runs OT receiver step 1 with choice bit b=${b}. Generates (pk0, pk1) and sends to Alice.`, 'log-bob');
        
        await new Promise(r => setTimeout(r, 600));
        log(`Alice runs OT sender step with (0, ${a}). Computes (C0, C1) and sends to Bob.`, 'log-alice');
        
        await new Promise(r => setTimeout(r, 600));
        log(`Bob decrypts C${b} using his secret key.`, 'log-bob');
        
        await new Promise(r => setTimeout(r, 600));
        log(`<b>Result!</b> Bob receives m_b = <span style="color:var(--green); font-size:14px;">${data.res}</span>. Alice outputs the same.`, 'log-sys');
        
        // Populate privacy box
        document.getElementById('transcript-raw').innerText = JSON.stringify(data.transcript, null, 2);
        document.getElementById('privacy-box').style.display = 'block';
        
    } catch(err) {
        log(`Error: ${err}`, 'log-sys');
    }
}

async function runTruthTable() {
    const tableBody = document.getElementById('tt-body');
    tableBody.innerHTML = "";
    document.getElementById('truth-table').style.display = 'block';
    document.getElementById('privacy-box').style.display = 'none';
    logDiv.innerHTML = "<div class='log-sys'>Running truth table verification...</div>";
    
    const pairs = [[0,0], [0,1], [1,0], [1,1]];
    
    for (const [a, b] of pairs) {
        try {
            const res = await fetch('/api/pa19/demo_and', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ a, b })
            });
            const data = await res.json();
            
            const expected = a & b;
            const isCorrect = (data.res === expected);
            
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${a}</td>
                <td>${b}</td>
                <td class="${isCorrect ? 'true' : 'false'}">${data.res}</td>
                <td>${expected}</td>
                <td>${isCorrect ? '✓ Pass' : '✗ Fail'}</td>
            `;
            tableBody.appendChild(tr);
        } catch(err) {
            console.error(err);
        }
    }
    
    log(`Truth table complete. Verified all 4 combinations.`, 'log-sys');
}
