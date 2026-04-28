const kInp = document.getElementById('mr-k');
const kVal = document.getElementById('mr-k-val');
const btnTest = document.getElementById('btn-test');
const nInp = document.getElementById('mr-n');
const statusBox = document.getElementById('mr-status');
const timeBox = document.getElementById('mr-time');
const traceBox = document.getElementById('mr-trace');

kInp.addEventListener('input', () => {
  kVal.textContent = kInp.value;
});

btnTest.addEventListener('click', async () => {
  const nStr = nInp.value.trim();
  const kStr = kInp.value;
  
  if(!nStr) return;
  
  btnTest.disabled = true;
  statusBox.style.display = 'none';
  timeBox.textContent = 'Testing...';
  traceBox.innerHTML = 'Testing...';
  
  try {
    const res = await Backend.pa13Primality(nStr, kStr);
    
    if(res.error) {
      statusBox.style.display = 'block';
      statusBox.className = 'status err';
      statusBox.textContent = res.error;
      timeBox.textContent = '';
      traceBox.innerHTML = '';
      btnTest.disabled = false;
      return;
    }
    
    statusBox.style.display = 'block';
    if(res.is_prime) {
      statusBox.className = 'status ok';
      statusBox.textContent = 'PROBABLY PRIME';
    } else {
      statusBox.className = 'status err';
      statusBox.textContent = 'COMPOSITE';
    }
    
    timeBox.textContent = `Completed in ${res.time_ms} ms.`;
    
    // Render trace
    traceBox.innerHTML = '';
    if(res.trace && res.trace.length > 0) {
      res.trace.forEach(tr => {
        const d = document.createElement('div');
        d.className = 'trace-item';
        if(tr.event === 'factor') {
          d.innerHTML = `Factor out 2: N-1 = 2^${tr.r} * ${tr.d}`;
        } else if(tr.event === 'round') {
          d.innerHTML = `Round ${tr.round}: <span class="witness">a=${tr.a}</span>. x=${tr.x}`;
        } else if(tr.event === 'composite') {
          d.innerHTML = `<span class="composite-reason">Return Composite: ${tr.reason}</span>`;
        } else if(tr.event === 'prime') {
          d.innerHTML = `<span class="witness">Return Probably Prime</span>`;
        } else {
          d.textContent = JSON.stringify(tr);
        }
        traceBox.appendChild(d);
      });
    } else {
      traceBox.textContent = "No trace available (N might be trivial).";
    }
    
  } catch(e) {
    statusBox.style.display = 'block';
    statusBox.className = 'status err';
    statusBox.textContent = 'Error: ' + e.message;
    timeBox.textContent = '';
  }
  
  btnTest.disabled = false;
});
