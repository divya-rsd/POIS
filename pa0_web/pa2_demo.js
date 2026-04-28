const keyInp = document.getElementById('ggm-key');
const queryInp = document.getElementById('ggm-query');
const outBox = document.getElementById('ggm-out');
const treeCont = document.getElementById('tree-container');

function renderTree(bits) {
  treeCont.innerHTML = '';
  const depth = bits.length;
  
  // To avoid massive trees, cap visualization to 8 bits
  if (depth > 8) {
    treeCont.innerHTML = '<div class="warn status">Tree too deep to visualize (>8 bits)</div>';
    return;
  }
  
  let currentPathIndex = 0; // The root node
  
  for (let d = 0; d <= depth; d++) {
    const levelDiv = document.createElement('div');
    levelDiv.className = 'tree-level';
    
    // Number of nodes in this level is 2^d
    const numNodes = Math.pow(2, d);
    
    // To fit on screen, cap visible nodes at 64, or just render them compactly
    for (let i = 0; i < numNodes; i++) {
      const node = document.createElement('div');
      node.className = 'tree-node';
      
      if (i === currentPathIndex) {
        node.classList.add('active');
      }
      
      levelDiv.appendChild(node);
    }
    
    treeCont.appendChild(levelDiv);
    
    if (d < depth) {
      // update path index for next level
      const bit = parseInt(bits[d], 10);
      currentPathIndex = currentPathIndex * 2 + bit;
    }
  }
}

document.getElementById('btn-eval').addEventListener('click', async () => {
  try {
    let key = keyInp.value || "00";
    let bits = queryInp.value.replace(/[^01]/g, '') || "0";
    
    // Limit to 8 bits for visualizer
    if (bits.length > 8) {
      bits = bits.substring(0, 8);
      queryInp.value = bits;
    }

    const res = await Backend.pa2Ggm(key, bits);
    outBox.value = res.out;
    renderTree(bits);
    
  } catch(e) {
    outBox.value = "Error: " + e.message;
  }
});

// Init
renderTree("101");
