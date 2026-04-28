const bitsInp = document.getElementById('hash-bits');
const btnRun = document.getElementById('btn-run');
const statusDiv = document.getElementById('run-status');

let chart = null;

function updateStats() {
  const b = parseInt(bitsInp.value, 10);
  document.getElementById('bit-val').textContent = b;
  const N = Math.pow(2, b);
  document.getElementById('space-val').textContent = b;
  document.getElementById('space-num').textContent = N;
  
  // Expected attempts ~ sqrt(pi/2 * N)
  const expected = Math.round(Math.sqrt(Math.PI / 2 * N));
  document.getElementById('exp-val').textContent = expected;
  document.getElementById('stat-theory').textContent = expected;
}

bitsInp.addEventListener('input', updateStats);

function theoreticalProb(k, N) {
  // P(collision) = 1 - e^(-k^2 / 2N)
  return 1 - Math.exp(-(k*k) / (2*N));
}

btnRun.addEventListener('click', async () => {
  const b = parseInt(bitsInp.value, 10);
  const N = Math.pow(2, b);
  
  btnRun.disabled = true;
  statusDiv.style.display = 'block';
  statusDiv.className = 'status';
  statusDiv.textContent = 'Running 10 attack iterations on backend...';
  
  let totalAttempts = 0;
  let attackResults = [];
  
  for(let i=0; i<10; i++) {
    try {
      const res = await Backend.pa9Birthday(b);
      // naive attack returns dict with collision/iters
      if(res.collision) {
        totalAttempts += res.iters;
        attackResults.push(res.iters);
      }
    } catch(e) {
      statusDiv.textContent = 'Error: ' + e.message;
      btnRun.disabled = false;
      return;
    }
  }
  
  const avg = Math.round(totalAttempts / 10);
  document.getElementById('stat-avg').textContent = avg;
  
  statusDiv.className = 'status ok';
  statusDiv.textContent = `Completed. Average attempts to collision: ${avg}`;
  
  plotGraph(b, N, avg);
  
  btnRun.disabled = false;
});

function plotGraph(bits, N, avg) {
  if (chart) chart.destroy();
  const ctx = document.getElementById('attackChart').getContext('2d');
  
  // Generate X values (number of hashes computed) up to 2.5 * Expected
  const expected = Math.sqrt(Math.PI / 2 * N);
  const maxX = Math.round(expected * 2.5);
  const step = Math.max(1, Math.floor(maxX / 40));
  
  let labels = [];
  let theoryData = [];
  
  for(let k=0; k<=maxX; k+=step) {
    labels.push(k);
    theoryData.push(theoreticalProb(k, N));
  }
  
  // Empirical point
  let empPoint = { x: avg, y: theoreticalProb(avg, N) };
  // But scatter chart with line is slightly complex in simple chart.js config,
  // we can just add a vertical line or an annotation. Or add a single point dataset
  // mapped closely to the x axis.
  
  // For simplicity, let's just make the empirical point a scatter dataset
  let empData = labels.map(x => (Math.abs(x - avg) <= step/2) ? theoreticalProb(avg, N) : null);
  
  chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Theoretical Probability',
          data: theoryData,
          borderColor: '#4ecdc4',
          borderWidth: 2,
          fill: false,
          pointRadius: 0
        },
        {
          label: 'Empirical Average',
          data: empData,
          borderColor: '#a78bfa',
          backgroundColor: '#a78bfa',
          pointRadius: 6,
          pointStyle: 'crossRot',
          showLine: false
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: {display: true, text: 'Hashes Computed', color:'#8892aa'}, grid: {color: 'rgba(46,53,80,0.5)'}, ticks: {color: '#8892aa'} },
        y: { title: {display: true, text: 'P(Collision)', color:'#8892aa'}, min: 0, max: 1, grid: {color: 'rgba(46,53,80,0.5)'}, ticks: {color: '#8892aa'} }
      },
      plugins: { legend: { labels: { color: '#dde3f0', font: { family: 'IBM Plex Mono'} } } }
    }
  });
}

// Init
updateStats();
