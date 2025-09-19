async function initWASM() {
    console.log('Loading WASM module...');
    const go = new Go();
    const result = await WebAssembly.instantiateStreaming(fetch("fingerprint.wasm"), go.importObject);
    go.run(result.instance);
    console.log('WASM module loaded successfully');
    
    console.log('collectFingerprint available:', typeof collectFingerprint !== 'undefined');
    console.log('encryptData available:', typeof encryptData !== 'undefined');
    
    return true;
}

class CaptchaSystem {
    constructor() {
        this.challenge = null;
        this.solving = false;
    }

    async getChallenge() {
        const response = await fetch('/api/v1/challenge');
        if (!response.ok) {
            throw new Error('Failed to get challenge');
        }
        const data = await response.json();
        this.challenge = data.challenge;
        return data;
    }

    async solveChallenge() {
        if (!this.challenge) {
            throw new Error('No challenge available');
        }

        this.solving = true;
        this.updateStatus('Solving...', 'working');
        
        let nonce = 0;
        const startTime = Date.now();
        
        while (this.solving) {
            const nonceStr = nonce.toString();
            const input = this.challenge.salt + nonceStr;
            
            try {
                const saltBytes = this.base64ToUint8Array(this.challenge.salt);
                
                const result = await argon2.hash({
                    pass: input,
                    salt: saltBytes,
                    time: this.challenge.difficulty || 3,
                    mem: this.challenge.memory || 65536,
                    parallelism: this.challenge.threads || 1,
                    hashLen: this.challenge.keyLen || 32,
                    type: argon2.ArgonType.Argon2id
                });
                
                const hashStr = this.uint8ArrayToHex(result.hash);
                
                if (this.hasValidPrefix(hashStr, this.challenge.target)) {
                    const elapsed = (Date.now() - startTime) / 1000;
                    this.updateStatus(`✅ Captcha completed`, 'success');
                    
                    return {
                        challenge: this.challenge,
                        nonce: nonceStr,
                        hash: hashStr,
                        input: input
                    };
                }
                
                nonce++;
                
                if (nonce % 10 === 0) {
                    await this.sleep(1);
                }
                
            } catch (error) {
                console.error('Hash computation error:', error);
                nonce++;
                continue;
            }
        }
        
        throw new Error('Solving was aborted');
    }

    async verifySolution(solution) {
        console.log('Collecting fingerprint...');
        const fingerprintResult = collectFingerprint();
        console.log('Fingerprint result:', fingerprintResult);
        if (!fingerprintResult.success) {
            throw new Error('Failed to collect fingerprint: ' + fingerprintResult.error);
        }

        const response = await fetch('/api/v1/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                challengeId: solution.challenge.id,
                nonce: solution.nonce,
                hash: solution.hash,
                fingerprint: fingerprintResult.fingerprint
            })
        });
        
        if (!response.ok) {
            throw new Error('Verification request failed');
        }
        
        const result = await response.json();
        return result.valid;
    }

    base64ToUint8Array(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    uint8ArrayToHex(uint8Array) {
        return Array.from(uint8Array)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    hasValidPrefix(hash, prefix) {
        return hash.startsWith(prefix);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    updateStatus(message, type = '') {
        const statusEl = document.getElementById('status');
        statusEl.textContent = message;
        statusEl.className = 'status ' + type;
    }

    updateProgress(message) {
        document.getElementById('progress').textContent = message;
    }

    stop() {
        this.solving = false;
    }
}

let captcha = null;

document.addEventListener('DOMContentLoaded', async () => {
    try {
        await initWASM();
        
        captcha = new CaptchaSystem();
        
        const button = document.getElementById('solve-captcha');

        button.addEventListener('click', async () => {
            button.disabled = true;
            button.innerHTML = '<span class="spinner"></span>Solving...';
            button.className = 'solve-button';

            try {
                await captcha.getChallenge();
                captcha.updateStatus('Computing solution...', 'working');

                const solution = await captcha.solveChallenge();
                
                captcha.updateStatus('🔍 Verifying solution...', 'working');
                const isValid = await captcha.verifySolution(solution);
                
                if (isValid) {
                    captcha.updateStatus('✅ Verification successful! You are human.', 'success');
                    button.textContent = '✓ Verified Human';
                    button.className = 'solve-button success';
                    captcha.updateProgress('Ready to proceed!');
                } else {
                    captcha.updateStatus('❌ Verification failed. Please try again.', 'error');
                    button.disabled = false;
                    button.textContent = 'Try Again';
                    button.className = 'solve-button error';
                    captcha.updateProgress('');
                }
                
            } catch (error) {
                console.error('CAPTCHA error:', error);
                captcha.updateStatus(`❌ Error: ${error.message}`, 'error');
                button.disabled = false;
                button.textContent = 'Try Again';
                button.className = 'solve-button error';
                captcha.updateProgress('');
            }
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && captcha && captcha.solving) {
                captcha.stop();
                captcha.updateStatus('⏹️ Solving aborted by user', 'error');
                button.disabled = false;
                button.textContent = 'Try Again';
                button.className = 'solve-button';
                captcha.updateProgress('');
            }
        });

    } catch (error) {
        console.error('Failed to initialize captcha:', error);
        document.getElementById('status').textContent = 'Failed to initialize captcha system';
        document.getElementById('status').className = 'status error';
    }
}); 