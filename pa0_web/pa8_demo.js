const msgInp = document.getElementById('dlp-msg');
const outBox = document.getElementById('dlp-out');
const huntBtn = document.getElementById('btn-hunt');
const progCont = document.getElementById('prog-cont');
const progBar = document.getElementById('prog-bar');
const statusTxt = document.getElementById('hunt-status');
const colBox = document.getElementById('col-box');

document.getElementById('btn-hash').addEventListener('click', async () => {
  const m = msgInp.value;
  if(!m) return;
  try {
    const res = await Backend.pa8Hash(m);
    outBox.value = res.hash;
  } catch(e) {
    outBox.value = "Error: " + e.message;
  }
});

huntBtn.addEventListener('click', async () => {
  huntBtn.disabled = true;
  colBox.style.display = 'none';
  progCont.style.display = 'block';
  progBar.style.width = '0%';
  statusTxt.textContent = "Hunting... (Querying backend)";
  
  // To simulate the progression, we'll run a quick animation then fetch the backend result.
  // The backend does it instantly but an animation looks nicer.
  
  let p = 0;
  const interval = setInterval(() => {
    p += Math.random() * 15;
    if(p > 90) p = 90;
    progBar.style.width = p + '%';
    statusTxt.textContent = `Computing hashes... (~${Math.floor(p * 2.5)} attempts)`;
  }, 100);

  try {
    const res = await Backend.pa8Hunt(16); // 16 bits
    clearInterval(interval);
    progBar.style.width = '100%';
    
    if(res.collision) {
      statusTxt.textContent = `Collision found after ${res.iters} iterations!`;
      document.getElementById('col-m1').textContent = res.m1;
      document.getElementById('col-m2').textContent = res.m2;
      document.getElementById('col-hash').textContent = res.hash;
      colBox.style.display = 'block';
    } else {
      statusTxt.textContent = "Failed to find collision in limit.";
    }
  } catch(e) {
    clearInterval(interval);
    statusTxt.textContent = "Error: " + e.message;
  }
  
  huntBtn.disabled = false;
});
