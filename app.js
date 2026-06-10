/**
 * PassIntel – Professional Password Security Suite
 * Developed by: P. Mahan Sashank Yadav
 * Cybersecurity Student | Chandigarh University
 * 
 * Application Logic (app.js)
 */

// A cleaned list of the most common passwords (removed duplicates and sorted)
const COMMON_PASSWORDS = new Set([
  "000000", "111111", "112233", "121212", "123123", "1234", "12345", "123456", 
  "1234567", "12345678", "123456789", "1234567890", "1q2w3e", "1q2w3e4r", "654321", 
  "696969", "abc123", "access", "admin", "admin123", "administrator", "arsenal", 
  "asdfghjkl", "baseball", "batman", "changeme", "chelsea", "corvette", "dragon", 
  "football", "guest", "harley", "hello", "hello123", "hunter", "iloveyou", 
  "jordan", "letmein", "login", "master", "maverick", "michael", "monkey", 
  "mustang", "ninja", "pa$$word", "pass", "pass1", "pass123", "password", 
  "password!", "password1", "password123", "passw0rd", "p@ss", "p@ssword", 
  "p@ssw0rd", "princess", "qazwsx", "qwerty", "qwerty123", "qwertyuiop", 
  "ranger", "root", "shadow", "soccer", "solo", "starwars", "sunshine", 
  "superman", "test", "trustno1", "user", "welcome", "welcome1", "yankees", 
  "zxcvbnm"
]);

// Track password input visibility state
let isPasswordVisible = false;

/**
 * Toggle the visibility of the analyzer input field
 */
function toggleVis() {
  isPasswordVisible = !isPasswordVisible;
  const passInput = document.getElementById('passInput');
  const eyeBtn = document.getElementById('eyeBtn');
  
  if (isPasswordVisible) {
    passInput.type = 'text';
    eyeBtn.innerHTML = '<i class="ti ti-eye-off"></i>';
  } else {
    passInput.type = 'password';
    eyeBtn.innerHTML = '<i class="ti ti-eye"></i>';
  }
}

/**
 * Helper to update checklist item UI classes and icons
 */
function updateChecklistItem(id, isPassed) {
  const el = document.getElementById(id);
  if (!el) return;
  
  if (isPassed) {
    el.classList.add('pass');
    el.querySelector('.check-icon').innerHTML = '<i class="ti ti-circle-check"></i>';
  } else {
    el.classList.remove('pass');
    el.querySelector('.check-icon').innerHTML = '<i class="ti ti-circle"></i>';
  }
}

/**
 * Format the combination count to make it readable (e.g. billion, quadrillion)
 */
function formatCombinations(n) {
  if (n === 0) return '0';
  if (n < 1e6) return n.toLocaleString();
  if (n < 1e12) return (n / 1e9).toFixed(1) + ' billion';
  if (n < 1e18) return (n / 1e15).toFixed(1) + ' quadrillion';
  return '10^' + Math.round(Math.log10(n)) + '+';
}

/**
 * Estimate password cracking time based on a high-speed brute-force rate
 * (Assumes 10 billion guesses/second for modern GPU cracking rigs)
 */
function estimateCrackTime(charPool, length, isCommon) {
  if (isCommon) return 'Instantly (known common password)';
  if (length === 0) return 'Enter a password to see crack time estimate.';
  
  const combinations = Math.pow(charPool, length);
  // 10 billion attempts per second (1e10)
  const guessesPerSecond = 1e10; 
  // We divide by 2 because on average, brute-force succeeds at 50% search space coverage
  const secondsToCrack = combinations / guessesPerSecond / 2;
  
  if (secondsToCrack < 1) return '< 1 second';
  if (secondsToCrack < 60) return '~' + Math.round(secondsToCrack) + ' seconds';
  
  const minutes = secondsToCrack / 60;
  if (minutes < 60) return '~' + Math.round(minutes) + ' minutes';
  
  const hours = minutes / 60;
  if (hours < 24) return '~' + Math.round(hours) + ' hours';
  
  const days = hours / 24;
  if (days < 365) return '~' + Math.round(days) + ' days';
  
  const years = days / 365;
  if (years < 100) return '~' + Math.round(years) + ' years';
  if (years < 1e6) return '~' + Math.round(years / 1000) + 'k years';
  
  return 'Centuries+ (excellent security)';
}

/**
 * Create a small HTML span badge with custom levels
 */
function createStatusTag(text, className) {
  return `<span class="tag ${className}">${text}</span>`;
}

/**
 * Core Password Analyzer Function
 */
function analyze() {
  const password = document.getElementById('passInput').value;
  const length = password.length;
  const lowercaseVal = password.toLowerCase();

  // Basic Criteria Regex Checks
  const isCommon = COMMON_PASSWORDS.has(lowercaseVal);
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNum = /[0-9]/.test(password);
  const hasSym = /[^A-Za-z0-9]/.test(password);
  
  // Custom checks: 3+ repeats of same character (e.g. "aaa")
  const hasRepeats = /(.)\1{2,}/.test(password);
  
  // Custom checks: Common keyboard sequence runs (e.g., "abc", "123", "qwerty")
  const commonSequences = [
    "abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", "ijk", "jkl", "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst", "stu", "tuv", "uvw", "vwx", "wxy", "xyz",
    "012", "123", "234", "345", "456", "567", "678", "789", "890", "zyx", "987", "876", "qwe", "wer", "ert", "rty", "tyu", "yui", "uiop"
  ];
  let hasSequence = false;
  if (length >= 3) {
    for (const seq of commonSequences) {
      if (lowercaseVal.includes(seq)) {
        hasSequence = true;
        break;
      }
    }
  }

  // Show Alert if it's in the common list
  const alertEl = document.getElementById('commonAlert');
  if (isCommon && length > 0) {
    alertEl.className = 'alert danger';
    document.getElementById('alertMsg').textContent = `"${password}" is a widely known dictionary password and will be bypassed immediately.`;
  } else {
    alertEl.className = 'alert';
  }

  // Update visual criteria checklist
  updateChecklistItem('ck-len', length >= 8);
  updateChecklistItem('ck-12', length >= 12);
  updateChecklistItem('ck-upper', hasUpper);
  updateChecklistItem('ck-lower', hasLower);
  updateChecklistItem('ck-num', hasNum);
  updateChecklistItem('ck-sym', hasSym);
  updateChecklistItem('ck-norep', length > 0 && !hasRepeats);
  updateChecklistItem('ck-noseq', length > 0 && !hasSequence);

  // Compute character pool size based on active groups
  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasNum) poolSize += 10;
  if (hasSym) poolSize += 32; // Standard special characters pool
  if (poolSize === 0 && length > 0) poolSize = 26; // Default to lowercase alphabet length if typed only text

  // Shannon Entropy: H = L * log2(R)
  const entropy = length > 0 ? Math.round(length * Math.log2(poolSize || 1)) : 0;

  // Numerical Score Calculation (Maximum 100 points)
  let score = 0;
  if (length > 0) score += 5; // Base points for entering a character
  if (length >= 8) score += 15;
  if (length >= 12) score += 15;
  if (length >= 16) score += 10;
  if (hasUpper) score += 10;
  if (hasLower) score += 10;
  if (hasNum) score += 10;
  if (hasSym) score += 15;
  if (!hasRepeats && length > 0) score += 5;
  if (!hasSequence && length > 0) score += 5;
  
  // Drastically penalize known common passwords
  if (isCommon) score = Math.min(score, 10);
  score = Math.min(score, 100);

  // Determine qualitative strength details
  let strengthLabel, barColor;
  if (length === 0) {
    strengthLabel = '—';
    barColor = 'var(--border-color)';
  } else if (isCommon || score < 20) {
    strengthLabel = 'Very Weak';
    barColor = 'var(--color-red)';
  } else if (score < 40) {
    strengthLabel = 'Weak';
    barColor = 'var(--color-red)';
  } else if (score < 60) {
    strengthLabel = 'Fair';
    barColor = 'var(--color-amber)';
  } else if (score < 80) {
    strengthLabel = 'Strong';
    barColor = 'var(--color-green)';
  } else {
    strengthLabel = 'Very Strong';
    barColor = 'var(--color-purple)';
  }

  // Render score metric
  const scoreEl = document.getElementById('metScore');
  scoreEl.textContent = length > 0 ? score + '/100' : '—';
  scoreEl.className = 'metric-value ' + (score >= 60 ? 'good' : score >= 40 ? 'warn' : 'bad');

  // Render entropy metric
  const entEl = document.getElementById('metEntropy');
  entEl.textContent = length > 0 ? entropy + ' bits' : '—';
  entEl.className = 'metric-value ' + (entropy >= 60 ? 'good' : entropy >= 40 ? 'warn' : 'bad');

  // Render length metric
  const lenEl = document.getElementById('metLen');
  lenEl.textContent = length;
  lenEl.className = 'metric-value ' + (length >= 12 ? 'good' : length >= 8 ? 'warn' : 'bad');

  // Render Charset complexity classification
  let charsetLabel = '—';
  if (length > 0) {
    const typesCount = [hasLower, hasUpper, hasNum, hasSym].filter(Boolean).length;
    charsetLabel = typesCount === 4 ? 'Full' : typesCount === 3 ? 'Good' : typesCount === 2 ? 'Mixed' : 'Basic';
  }
  const csEl = document.getElementById('metCharset');
  csEl.textContent = charsetLabel;
  csEl.className = 'metric-value ' + (charsetLabel === 'Full' || charsetLabel === 'Good' ? 'good' : charsetLabel === 'Mixed' ? 'warn' : 'bad');

  // Render progress strength bar
  document.getElementById('barStatus').textContent = strengthLabel;
  document.getElementById('barStatus').style.color = barColor;
  document.getElementById('barFill').style.width = (length > 0 ? score : 0) + '%';
  document.getElementById('barFill').style.backgroundColor = barColor;

  // Render Entropy horizontal meter bars (10 individual ticks)
  const filledBars = length > 0 ? Math.min(10, Math.round(entropy / 10)) : 0;
  for (let i = 1; i <= 10; i++) {
    const el = document.getElementById('eb' + i);
    if (i <= filledBars) {
      el.className = 'ebar ' + (entropy < 40 ? 'lit-red' : entropy < 60 ? 'lit-amber' : 'lit-green');
    } else {
      el.className = 'ebar';
    }
  }

  // Render crack time estimation
  document.getElementById('crackTime').textContent = length > 0
    ? 'Estimate to Crack (10B guesses/sec): ' + estimateCrackTime(poolSize, length, isCommon)
    : 'Enter a password to see crack time estimate.';

  // Render details breakdown list
  document.getElementById('d-common').innerHTML = length === 0 ? '—' : isCommon ? createStatusTag('Yes (Dangerous)', 'red') : createStatusTag('No (Safe)', 'green');
  document.getElementById('d-pool').textContent = length > 0 ? poolSize + ' characters' : '—';
  document.getElementById('d-repeat').innerHTML = length === 0 ? '—' : hasRepeats ? createStatusTag('Yes', 'amber') : createStatusTag('No', 'green');
  document.getElementById('d-seq').innerHTML = length === 0 ? '—' : hasSequence ? createStatusTag('Yes', 'amber') : createStatusTag('No', 'green');
  document.getElementById('d-combo').textContent = length > 0 ? formatCombinations(Math.pow(poolSize, length)) : '—';

  // Render customized improvements tips
  const tips = [];
  if (length === 0) {
    document.getElementById('tipsList').innerHTML = '<p class="empty-tips-msg">Enter a password above to see personalized tips.</p>';
    return;
  }
  
  if (isCommon) {
    tips.push({ icon: '⚠️', text: 'This password is standard and highly insecure. Use unique, randomized characters.' });
  }
  if (length < 8) {
    tips.push({ icon: '📏', text: 'Length is too short. Use at least 8 characters (12+ recommended for strong defenses).' });
  } else if (length < 12) {
    tips.push({ icon: '📏', text: 'Great starting length. Expand it to 12+ characters to increase complexity exponentially.' });
  }
  if (!hasUpper) {
    tips.push({ icon: '🔠', text: 'Add uppercase letters (A–Z) to widen the complexity pool.' });
  }
  if (!hasLower) {
    tips.push({ icon: '🔡', text: 'Mix in lowercase letters (a–z) to help prevent basic attacks.' });
  }
  if (!hasNum) {
    tips.push({ icon: '🔢', text: 'Insert numerical digits (0–9) to make the combinations harder to guess.' });
  }
  if (!hasSym) {
    tips.push({ icon: '💠', text: 'Embed special symbols (!@#$...) to maximize combinations and entropy.' });
  }
  if (hasRepeats) {
    tips.push({ icon: '🔁', text: 'Avoid repeating identical characters consecutively (e.g. "aaa") which lowers variance.' });
  }
  if (hasSequence) {
    tips.push({ icon: '📈', text: 'Avoid predictable patterns or runs (like "abc", "123") that attack dictionaries try first.' });
  }
  
  if (score >= 80 && !isCommon) {
    tips.push({ icon: '✨', text: 'Excellent! This password is very secure. Keep it stored in a safe local password vault.' });
  }

  document.getElementById('tipsList').innerHTML = tips.map(t =>
    `<div class="tip-item"><span class="tip-item-icon">${t.icon}</span><span>${t.text}</span></div>`
  ).join('');
}


/**
 * Secure Password Generator Function
 * Uses window.crypto.getRandomValues for strong cryptographic security
 */
function generatePassword() {
  const length = parseInt(document.getElementById('genLengthRange').value, 10);
  const includeUpper = document.getElementById('genUpper').checked;
  const includeLower = document.getElementById('genLower').checked;
  const includeNumbers = document.getElementById('genNumbers').checked;
  const includeSymbols = document.getElementById('genSymbols').checked;

  const charSets = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  };

  let allowedPool = '';
  let guaranteedChars = [];

  // Build the active pool and ensure at least one character from each checked group is selected
  if (includeUpper) {
    allowedPool += charSets.upper;
    guaranteedChars.push(getRandomChar(charSets.upper));
  }
  if (includeLower) {
    allowedPool += charSets.lower;
    guaranteedChars.push(getRandomChar(charSets.lower));
  }
  if (includeNumbers) {
    allowedPool += charSets.numbers;
    guaranteedChars.push(getRandomChar(charSets.numbers));
  }
  if (includeSymbols) {
    allowedPool += charSets.symbols;
    guaranteedChars.push(getRandomChar(charSets.symbols));
  }

  // Handle the case where no checkboxes are checked
  if (allowedPool === '') {
    showToast('Please select at least one character type.', 'error');
    return;
  }

  // Fill the rest of the password length with random characters from the pool
  const fillLength = length - guaranteedChars.length;
  let resultPassword = [...guaranteedChars];

  for (let i = 0; i < fillLength; i++) {
    resultPassword.push(getRandomChar(allowedPool));
  }

  // Shuffle the result array to prevent guaranteed characters from always sitting at the beginning
  // Uses a cryptographically enhanced sorting algorithm (Fisher-Yates Shuffle)
  shuffleArray(resultPassword);

  const finalPassword = resultPassword.join('');
  
  // Render generated password in the UI
  const displayEl = document.getElementById('genDisplay');
  displayEl.value = finalPassword;
}

/**
 * Get a single random character from a character set using CSPRNG
 */
function getRandomChar(characterSet) {
  // Use Web Crypto API for secure random selections
  const randomBuffer = new Uint32Array(1);
  window.crypto.getRandomValues(randomBuffer);
  const randomIndex = randomBuffer[0] % characterSet.length;
  return characterSet.charAt(randomIndex);
}

/**
 * Shuffle array values using Fisher-Yates with crypto values
 */
function shuffleArray(array) {
  const cryptoBuffer = new Uint32Array(array.length);
  window.crypto.getRandomValues(cryptoBuffer);
  
  for (let i = array.length - 1; i > 0; i--) {
    const j = cryptoBuffer[i] % (i + 1);
    const temp = array[i];
    array[i] = array[j];
    array[j] = temp;
  }
}

/**
 * Copy generated password to the system clipboard
 */
function copyToClipboard() {
  const displayEl = document.getElementById('genDisplay');
  const password = displayEl.value;
  
  if (!password || password === 'Click Generate...') {
    showToast('Please generate a password first.', 'warning');
    return;
  }
  
  navigator.clipboard.writeText(password)
    .then(() => {
      showToast('Password copied to clipboard!');
      
      // Temporary button state visual feedback
      const copyBtn = document.getElementById('copyBtn');
      const originalText = copyBtn.innerHTML;
      copyBtn.innerHTML = '<i class="ti ti-check"></i> Copied!';
      setTimeout(() => {
        copyBtn.innerHTML = originalText;
      }, 2000);
    })
    .catch(err => {
      showToast('Failed to copy password.', 'error');
      console.error('Copy failed:', err);
    });
}

/**
 * Send the generated password to the analyzer input to view its strengths/metrics
 */
function sendToAnalyzer() {
  const password = document.getElementById('genDisplay').value;
  if (!password || password === 'Click Generate...') {
    showToast('Please generate a password first.', 'warning');
    return;
  }
  
  const passInput = document.getElementById('passInput');
  passInput.value = password;
  
  // Make sure it is visible so the user sees the filled values
  if (!isPasswordVisible) {
    toggleVis();
  }
  
  // Run the analysis automatically
  analyze();
  
  showToast('Password loaded into Analyzer!');
}

/**
 * Display a temporary message toast on the screen
 */
function showToast(message) {
  const toast = document.getElementById('toastNotification');
  document.getElementById('toastMsg').textContent = message;
  
  toast.classList.add('show');
  
  setTimeout(() => {
    toast.classList.remove('show');
  }, 2.5 * 1000);
}

// Attach event listeners when DOM loads
window.addEventListener('DOMContentLoaded', () => {
  // Sync the generator range slider values
  const slider = document.getElementById('genLengthRange');
  const sliderLabel = document.getElementById('sliderValLabel');
  
  slider.addEventListener('input', (e) => {
    sliderLabel.textContent = e.target.value;
  });
  
  // Initialize with a blank analyzer state
  analyze();
});
