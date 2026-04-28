let currentMode = 'textbook';

function setMode(mode) {
    currentMode = mode;
    document.getElementById('tab-textbook').className = mode === 'textbook' ? 'tab active' : 'tab';
    document.getElementById('tab-pkcs').className = mode === 'pkcs15' ? 'tab active' : 'tab';
    
    // Clear outputs when switching modes
    document.getElementById('box-c1').innerText = '';
    document.getElementById('box-c2').innerText = '';
    document.getElementById('banner-status').style.display = 'none';
    document.getElementById('padding-panel').style.display = 'none';
}

async function encryptTwice() {
    const msg = document.getElementById('inp-msg').value;
    const btn = document.getElementById('btn-enc');
    
    if (!msg) {
        alert("Please enter a short message.");
        return;
    }
    
    btn.disabled = true;
    document.getElementById('box-c1').innerText = 'Encrypting...';
    document.getElementById('box-c2').innerText = 'Encrypting...';
    document.getElementById('banner-status').style.display = 'none';
    document.getElementById('padding-panel').style.display = 'none';
    
    try {
        const res = await fetch('/api/pa12/encrypt_twice', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ m: msg, mode: currentMode })
        });
        const data = await res.json();
        
        document.getElementById('box-c1').innerText = data.c1;
        document.getElementById('box-c2').innerText = data.c2;
        
        const banner = document.getElementById('banner-status');
        if (data.match) {
            banner.className = 'banner red';
            banner.innerHTML = '🚨 Identical ciphertexts: plaintext leaked. (Deterministic)';
        } else {
            banner.className = 'banner green';
            banner.innerHTML = '✅ Ciphertexts differ each time. (Randomized)';
        }
        banner.style.display = 'block';
        
        if (currentMode === 'pkcs15' && !data.match) {
            document.getElementById('pad-ps1').innerText = data.ps1;
            document.getElementById('pad-ps2').innerText = data.ps2;
            document.getElementById('padding-panel').style.display = 'block';
        }
        
    } catch(err) {
        console.error(err);
        alert("Backend connection failed.");
    } finally {
        btn.disabled = false;
    }
}
