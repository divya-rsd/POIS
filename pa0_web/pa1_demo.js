const seedInp = document.getElementById('prg-seed');
const lenInp = document.getElementById('prg-len');
const lenVal = document.getElementById('prg-len-val');
const outBox = document.getElementById('prg-out');
const testDiv = document.getElementById('test-results');

let currentChart = null;

lenInp.addEventListener('input', () => {
  lenVal.textContent = lenInp.value;
});

document.getElementById('btn-generate').addEventListener('click', async () => {
  try {
    let seedStr = seedInp.value;
    let seedInt = parseInt(seedStr, 16);
    if (isNaN(seedInt)) seedInt = 42;
    
    const bits = parseInt(lenInp.value, 10);
    const res = await Backend.pa1Prg(seedInt, bits);
    
    outBox.value = res.out;
    testDiv.style.display = 'none'; // hide test until clicked
  } catch(e) {
    outBox.value = "Error: " + e.message;
  }
});

document.getElementById('btn-test').addEventListener('click', () => {
  const hex = outBox.value.trim();
  if (!hex || hex.startsWith('Error')) return;
  
  // Count bits
  let ones = 0;
  let zeros = 0;
  for (let i=0; i<hex.length; i++) {
    const val = parseInt(hex[i], 16);
    for (let b=0; b<4; b++) {
      if ((val >> b) & 1) ones++;
      else zeros++;
    }
  }
  
  testDiv.style.display = 'block';
  
  if (currentChart) currentChart.destroy();
  const ctx = document.getElementById('randomChart').getContext('2d');
  
  currentChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Zeros (0)', 'Ones (1)'],
      datasets: [{
        label: 'Bit Count',
        data: [zeros, ones],
        backgroundColor: [
          'rgba(167, 139, 250, 0.6)',
          'rgba(110, 231, 183, 0.6)'
        ],
        borderColor: [
          '#a78bfa',
          '#6ee7b7'
        ],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { beginAtZero: true, grid: { color: '#2e3550' }, ticks: { color: '#8892aa' } },
        x: { grid: { display: false }, ticks: { color: '#8892aa' } }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
});
