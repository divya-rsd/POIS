const tabs = document.querySelectorAll('.tab');
let activeMode = 'CBC';
tabs.forEach(t => {
  t.addEventListener('click', () => {
    tabs.forEach(tb => tb.classList.remove('active'));
    t.classList.add('active');
    activeMode = t.getAttribute('data-mode');
    document.getElementById('anim-area').style.display = 'none';
  });
});

const k = "00112233445566778899aabbccddeeff"; // static 16-byte key
let currentIV = null;
let currentCT = null; // full hex string
let blockCTs = []; // array of hex blocks
let isFlipped = [false, false, false]; 
let basePTBlocks = []; // for error highlighting

const msgInp = document.getElementById('pt-msg');
const animArea = document.getElementById('anim-area');
const blocksCont = document.getElementById('blocks-container');

function padMsg(str) {
  let b = new TextEncoder().encode(str);
  let needed = 48; // exactly 3 blocks of 16
  let res = new Uint8Array(needed);
  for(let i=0; i<Math.min(b.length, needed); i++) res[i] = b[i];
  return new TextDecoder("latin1").decode(res); // string safe for backend
}

function hexToBlocks(hex) {
  let b = [];
  for(let i=0; i<hex.length; i+=32) {
    if (i+32 <= hex.length) b.push(hex.substring(i, i+32));
  }
  return b;
}

document.getElementById('btn-enc').addEventListener('click', async () => {
  const mStr = padMsg(msgInp.value);
  basePTBlocks = [mStr.substring(0,16), mStr.substring(16,32), mStr.substring(32,48)];
  isFlipped = [false, false, false];
  
  let iv = null;
  if (document.getElementById('reuse-iv').checked) {
    iv = "00000000000000000000000000000000"; // fixed IV
  }

  try {
    const res = await Backend.pa4Modes(activeMode, k, mStr, iv);
    currentIV = res.iv;
    currentCT = res.ct;
    blockCTs = hexToBlocks(currentCT);
    await renderBlocks();
  } catch(e) {
    alert(e.message);
  }
});

document.getElementById('btn-reset').addEventListener('click', () => {
  animArea.style.display = 'none';
});

async function renderBlocks() {
  animArea.style.display = 'block';
  blocksCont.innerHTML = '';
  
  // Reconstruct full CT
  let finalCT = blockCTs.join('');
  
  // Decrypt to show propagation
  let decPTBlocks = [];
  try {
    const resDec = await Backend.pa4Decrypt(activeMode, k, finalCT, currentIV);
    let decStr = resDec.pt;
    // split into 16-byte blocks
    for(let i=0; i<3; i++) {
      decPTBlocks.push(decStr.substring(i*16, i*16+16));
    }
  } catch(e) {
    decPTBlocks = ["ERROR", "ERROR", "ERROR"];
  }

  for(let i=0; i<3; i++) {
    const col = document.createElement('div');
    col.className = 'block-col';
    
    // Original PT
    const ptBox = document.createElement('div');
    ptBox.className = 'block';
    ptBox.textContent = `PT${i}: ${basePTBlocks[i]}`;
    col.appendChild(ptBox);
    
    const arr1 = document.createElement('div');
    arr1.className = 'arr-down';
    arr1.innerHTML = '↓';
    col.appendChild(arr1);
    
    // CT block
    const ctBox = document.createElement('div');
    ctBox.className = 'block' + (isFlipped[i] ? ' corrupted' : '');
    ctBox.textContent = `CT${i}: ${blockCTs[i].substring(0, 16)}...`;
    
    // Check identical blocks for reuse IV in CBC
    if (activeMode === 'CBC' && i>0 && document.getElementById('reuse-iv').checked) {
      if (basePTBlocks[i] === basePTBlocks[i-1] && blockCTs[i] === blockCTs[i-1]) {
        ctBox.classList.add('identical');
      }
    }

    const flipBtn = document.createElement('button');
    flipBtn.className = 'btn-flip';
    flipBtn.textContent = 'FLIP BIT';
    flipBtn.onclick = () => flipBit(i);
    ctBox.appendChild(flipBtn);
    
    col.appendChild(ctBox);
    
    const arr2 = document.createElement('div');
    arr2.className = 'arr-down';
    arr2.innerHTML = '↓';
    col.appendChild(arr2);
    
    // Decrypted PT
    const decBox = document.createElement('div');
    decBox.className = 'block';
    if (decPTBlocks[i] !== basePTBlocks[i]) decBox.classList.add('corrupted');
    
    let displayDec = decPTBlocks[i];
    // sanitize invisible chars if corrupted
    if (decPTBlocks[i] !== basePTBlocks[i]) {
      displayDec = displayDec.replace(/[^\x20-\x7E]/g, '');
    }
    decBox.textContent = `DEC${i}: ${displayDec}`;
    
    col.appendChild(decBox);
    
    blocksCont.appendChild(col);
  }
}

function flipBit(blockIdx) {
  let hex = blockCTs[blockIdx];
  // flip the last character in hex
  let lastChar = hex[hex.length-1];
  let val = parseInt(lastChar, 16);
  val = val ^ 1; // flip lowest bit
  let newHex = hex.substring(0, hex.length-1) + val.toString(16);
  blockCTs[blockIdx] = newHex;
  isFlipped[blockIdx] = true;
  renderBlocks();
}
