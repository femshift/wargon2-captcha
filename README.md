# Captcha System

A comprehensive proof-of-work captcha system with Argon2 hashing, WASM fingerprinting, and PostgreSQL storage.

## Features

- Argon2 Proof-of-Work with configurable difficulty targeting 3-8 second solve time
- WASM-based browser fingerprinting with AES-256 encryption
- PostgreSQL storage for persistent challenge and solution tracking
- Hardcoded AES keys for secure client-server communication
- Rate limiting
- Modular Go architecture with clean separation of code

## Architecture

```
captcha/
├── cmd/server/          # Main server application
├── internal/
│   ├── config/          # Configuration management
│   ├── database/        # PostgreSQL models and operations
│   ├── crypto/          # AES encryption utilities
│   ├── argon2/          # Argon2 proof-of-work service
│   ├── fingerprint/     # WASM fingerprint validation
│   └── handlers/        # HTTP request handlers
├── wasm/                # Go WASM fingerprinting module
├── web/                 # Frontend files (HTML, JS, WASM)
├── config.env           # Configuration file
├── generate-key.go      # AES key generation utility
├── convert-key.go       # Key format conversion utility
└── build-wasm.*         # WASM build scripts
```

## Setup

### Prerequisites

- Go 1.21 or higher
- PostgreSQL 12 or higher
- Modern web browser with WebAssembly support

### Step 1: Database Setup

Create a PostgreSQL database and user:

```sql
CREATE DATABASE captcha_db;
CREATE USER captcha_user WITH PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE captcha_db TO captcha_user;
```

### Step 2: Generate AES Key

Generate a secure AES-256 key for encryption:

```bash
cd captcha
go run generate-key.go
```

This will output something like:
```
Generated AES-256 key
===================

1. Add this to your config.env file:
AES_KEY=NjfhkzjZrMQ59/TtPRPuPxzoVyGfg9xScz2XMMEkvjM=

2. Replace the aesKey variable in wasm/main.go with:
var aesKey = []byte{
	0x36, 0x37, 0xe1, 0x93, 0x89, 0x36, 0xac, 0xc4,
	0x39, 0xf7, 0x4d, 0xec, 0x3d, 0x13, 0xee, 0x3f,
	0x1c, 0xe8, 0x57, 0x21, 0x9f, 0x83, 0xdc, 0x52,
	0x73, 0x3d, 0x97, 0x30, 0xc3, 0x24, 0xbe, 0x33,
}
```

### Step 3: Configure Environment

Update `config.env` with your database credentials and the generated AES key:

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=captcha_db
DB_USER=captcha_user
DB_PASSWORD=password

# Add the base64 AES key from step 2
AES_KEY=NjfhkzjZrMQ59/TtPRPuPxzoVyGfg9xScz2XMMEkvjM=
```

### Step 4: Update WASM Key

Replace the `aesKey` variable in `wasm/main.go` with the byte array from step 2.

### Step 5: Build WASM Module

Build the WebAssembly fingerprinting module:

```bash
# On Windows
build-wasm.bat

# On Linux/macOS
chmod +x build-wasm.sh
./build-wasm.sh
```

This creates:
- `web/fingerprint.wasm` - The compiled WASM module
- `web/wasm_exec.js` - Go WASM runtime support

### Step 6: Install Dependencies and Run

```bash
go mod tidy
go run cmd/server/main.go
```

The server will start on `http://localhost:8080`.

### Step 7: Test the System

Open your browser and navigate to `http://localhost:8080`. Click "Verify Humanity" to test the complete flow.

## Configuration

All settings are configurable through `config.env`:

### Database Settings
- `DB_HOST`: Database hostname
- `DB_PORT`: Database port
- `DB_NAME`: Database name
- `DB_USER`: Database username
- `DB_PASSWORD`: Database password
- `DB_SSL_MODE`: SSL connection mode

### Argon2 Proof-of-Work Settings
- `ARGON2_TIME`: Number of iterations (affects CPU time)
- `ARGON2_MEMORY`: Memory usage in KB (affects memory requirement)
- `ARGON2_THREADS`: Thread count for parallel processing
- `ARGON2_KEY_LENGTH`: Output hash length in bytes
- `ARGON2_SALT_LENGTH`: Salt length in bytes
- `ARGON2_TARGET_PREFIX`: Required hash prefix (difficulty level)
- `ARGON2_MAX_SOLVE_TIME`: Maximum expected solve time in seconds

### Security Settings
- `AES_KEY`: Base64-encoded AES-256 key for fingerprint encryption
- `AES_KEY_LENGTH`: AES key length (should be 32 for AES-256)
- `FINGERPRINT_VALIDATION_TIMEOUT`: Timeout for fingerprint validation

### API Settings
- `API_RATE_LIMIT_REQUESTS`: Maximum requests per time window
- `API_RATE_LIMIT_WINDOW_MINUTES`: Rate limit time window
- `API_CORS_ORIGINS`: Allowed CORS origins (comma-separated)

### Server Settings
- `SERVER_PORT`: HTTP server port
- `SERVER_HOST`: HTTP server bind address

## API Reference

### GET /api/v1/challenge

Generates a new captcha challenge.

Response:
```json
{
  "challenge": {
    "id": "unique_challenge_id",
    "salt": "base64_encoded_salt",
    "difficulty": 1,
    "memory": 16384,
    "threads": 1,
    "keyLen": 32,
    "target": "00",
    "createdAt": "2024-01-01T00:00:00Z",
    "expiresAt": "2024-01-01T00:05:00Z",
    "solved": false
  }
}
```

### POST /api/v1/verify

Verifies a completed captcha solution.

Request:
```json
{
  "challengeId": "unique_challenge_id",
  "nonce": "solution_nonce",
  "hash": "computed_argon2_hash",
  "fingerprint": "encrypted_browser_fingerprint"
}
```

Response:
```json
{
  "valid": true,
  "message": "Captcha solved successfully"
}
```

### GET /api/v1/health

Health check endpoint for monitoring.

Response:
```json
{
  "status": "healthy",
  "service": "captcha-service"
}
```

## Security Implementation

### Argon2 Proof-of-Work
- Uses Argon2id variant
- Memory-hard algorithm
- Configurable parameters allow tuning for desired solve time
- Target prefix system provides adjustable difficulty

### Browser Fingerprinting
- Collects 12+ unique browser and system attributes
- Data is JSON-encoded, base64-encoded, byte-reversed, and AES-256 encrypted
- Server validates all fingerprint fields for correct format and reasonable ranges
- Hardcoded AES keys

### Data Protection
- All sensitive data encrypted with AES-256-GCM
- Database stores hashed challenges and encrypted fingerprints
- Automatic cleanup of expired challenges and old solutions
- Rate limiting prevents brute force attacks

## Browser Fingerprint Data

The system collects and validates:

- **userAgent**: Browser identification string
- **language**: Browser language setting
- **platform**: Operating system platform
- **hardwareConcurrency**: Number of CPU cores
- **maxTouchPoints**: Touch input capability
- **colorDepth**: Display color depth
- **pixelRatio**: Device pixel ratio
- **timezone**: Timezone offset in minutes
- **cookieEnabled**: Cookie support status
- **doNotTrack**: Do Not Track preference
- **screenResolution**: Screen dimensions
- **availableScreenResolution**: Available screen area

## Database Schema

The system automatically creates these tables:

### challenges
- `id`: Unique challenge identifier
- `salt`: Base64-encoded random salt
- `difficulty`: Argon2 time parameter
- `memory`: Argon2 memory parameter
- `threads`: Argon2 parallelism parameter
- `key_len`: Argon2 output length
- `target`: Required hash prefix
- `created_at`: Challenge creation timestamp
- `expires_at`: Challenge expiration timestamp
- `solved`: Solution status flag
- `solved_at`: Solution timestamp

### solutions
- `id`: Unique solution identifier
- `challenge_id`: Reference to solved challenge
- `nonce`: Solution nonce value
- `hash`: Computed Argon2 hash
- `fingerprint`: Encrypted browser fingerprint
- `client_ip`: Client IP address
- `user_agent`: Client user agent
- `created_at`: Solution submission timestamp
- `valid`: Validation result

## Performance Tuning

### Argon2 Parameters

For faster solving (2-4 seconds):
```env
ARGON2_TIME=1
ARGON2_MEMORY=8192
ARGON2_TARGET_PREFIX=0
```

For slower solving (8-15 seconds):
```env
ARGON2_TIME=2
ARGON2_MEMORY=32768
ARGON2_TARGET_PREFIX=000
```

### Rate Limiting

Adjust based on expected traffic:
```env
API_RATE_LIMIT_REQUESTS=50
API_RATE_LIMIT_WINDOW_MINUTES=5
```


### Debug Mode

Enable detailed logging:
```env
DEBUG_MODE=true
LOG_LEVEL=debug

```
