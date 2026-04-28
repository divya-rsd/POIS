let logDiv;
let m0, m1;
let b;

window.onload = async () => {
    logDiv = document.getElementById('chat-log');
    
    // Initial Setup
    try {
        const res = await fetch('/api/pa18/demo_setup', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ m0: 1337, m1: 80085 })
        });
        const data = await res.json();
        m0 = data.m0;
        m1 = data.m1;
        document.getElementById('inp-m0').value = "??? (Hidden)";
        document.getElementById('inp-m1').value = "??? (Hidden)";
    } catch(err) {
        log(`[Error] Failed to connect to backend: ${err}`, 'log-sys');
    }
}

function log(msg, cls="log-sys") {
    const d = document.createElement('div');
    d.className = `log-entry ${cls}`;
    d.innerHTML = msg;
    logDiv.appendChild(d);
    logDiv.scrollTop = logDiv.scrollHeight;
}

function truncateHex(hexStr, chars=20) {
    if (!hexStr) return "";
    if (hexStr.length > chars) return hexStr.substring(0, chars) + "...";
    return hexStr;
}

async function startProtocol(choice) {
    b = choice;
    document.getElementById('btn-choices').style.display = 'none';
    logDiv.innerHTML = ""; // clear log
    log(`Bob (You) chose bit b = ${b}. Generating keypairs...`, 'log-bob');
    
    try {
        // Step 1
        const res1 = await fetch('/api/pa18/demo_step1', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ b })
        });
        const data1 = await res1.json();
        log(`Generated pk0 (h=${truncateHex(data1.pk0_h)}) and pk1 (h=${truncateHex(data1.pk1_h)}). Sent to Alice.`, 'log-bob');
        
        // Wait a beat for realism
        await new Promise(r => setTimeout(r, 800));
        
        // Step 2
        log(`Alice received (pk0, pk1). She encrypts m0 with pk0 and m1 with pk1...`, 'log-alice');
        const res2 = await fetch('/api/pa18/demo_step2', { method: 'POST' });
        const data2 = await res2.json();
        log(`Alice sends C0 = (${truncateHex(data2.c0_c1)}, ${truncateHex(data2.c0_c2)}) and C1 = (${truncateHex(data2.c1_c1)}, ${truncateHex(data2.c1_c2)}).`, 'log-alice');
        
        await new Promise(r => setTimeout(r, 800));
        
        // Step 3
        log(`Bob receives C0 and C1. Decrypting C${b} using sk${b}...`, 'log-bob');
        const res3 = await fetch('/api/pa18/demo_step3', { method: 'POST' });
        const data3 = await res3.json();
        
        log(`<b>Success!</b> Decrypted message ${b}: <span style="color:var(--green); font-size:14px;">${data3.got}</span>`, 'log-bob');
        
        // Show cheat button
        document.getElementById('cheat-row').style.display = 'flex';
        
    } catch(err) {
        log(`Error in protocol: ${err}`, 'log-sys');
    }
}

async function cheatAttempt() {
    log(`Attempting to cheat: Brute-forcing the discrete log for pk${1-b} to decrypt C${1-b}...`, 'log-sys');
    document.getElementById('cheat-row').style.display = 'none';
    
    try {
        const res = await fetch('/api/pa18/demo_cheat', { method: 'POST' });
        const data = await res.json();
        
        if (!data.recovered) {
            log(`<span style="color:var(--red)">Cheat Failed!</span> Exhausted ${data.iters} iterations in ${data.time_s}s without finding log_g(fake_h). Receiver cannot decrypt the other message.`, 'log-sys');
        } else {
            log(`<span style="color:var(--amber)">Cheat Succeeded (Insecure group)!</span> Found DLP in ${data.iters} iterations. Recovered m${1-b} = ${data.recovered_message}`, 'log-sys');
        }
    } catch(err) {
        log(`Error cheating: ${err}`, 'log-sys');
    }
}
