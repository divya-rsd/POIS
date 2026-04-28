const msgInp = document.getElementById('md-msg');
const chainCont = document.getElementById('md-chain-container');

async function updateChain() {
  const m = msgInp.value;
  try {
    const res = await Backend.pa7Hash(m);
    renderChain(res.trace);
  } catch(e) {
    chainCont.innerHTML = `<div class="status err">Error: ${e.message}</div>`;
  }
}

function renderChain(trace) {
  chainCont.innerHTML = '';
  
  for(let i=0; i<trace.length; i++) {
    const t = trace[i];
    
    const stepDiv = document.createElement('div');
    stepDiv.className = 'md-step';
    
    const idxDiv = document.createElement('div');
    idxDiv.className = 'md-idx';
    idxDiv.textContent = t.block_idx === -1 ? 'IV' : `Blk ${t.block_idx}`;
    stepDiv.appendChild(idxDiv);
    
    const contDiv = document.createElement('div');
    contDiv.className = 'md-content';
    
    if (t.block_idx !== -1) {
      const bDiv = document.createElement('div');
      bDiv.innerHTML = `<span style="font-size:9px; color:var(--text3); font-family:var(--mono)">Message Block</span> <div class="mono">${t.block}</div>`;
      contDiv.appendChild(bDiv);
    }
    
    const cvDiv = document.createElement('div');
    cvDiv.innerHTML = `<span style="font-size:9px; color:var(--text3); font-family:var(--mono)">Chaining Value / Output</span> <div class="mono" style="color:var(--green); border-color:rgba(110,231,183,.3)">${t.chaining}</div>`;
    contDiv.appendChild(cvDiv);
    
    stepDiv.appendChild(contDiv);
    chainCont.appendChild(stepDiv);
    
    if (i < trace.length - 1) {
      const arr = document.createElement('div');
      arr.className = 'arrow-down';
      arr.innerHTML = '↓';
      chainCont.appendChild(arr);
    }
  }
}

let debounceTimer;
msgInp.addEventListener('input', () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(updateChain, 300);
});

// Init
updateChain();
