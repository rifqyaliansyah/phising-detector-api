# 🛡️ Phishing Detector API (Beta Version)

Express.js API untuk mendeteksi website phishing dengan pendekatan multi-layer analysis.

## ✨ Features

- ✅ **URL & Domain Analysis** - Parse dan validasi struktur URL
- ✅ **Typosquatting Detection** - Deteksi brand impersonation (50+ brands)
- ✅ **SSL Certificate Check** - Validasi HTTPS dan certificate
- ✅ **Domain Age Check** - Deteksi domain baru (WHOIS)
- ✅ **Content Analysis** - Analisis HTML untuk phishing indicators
- ✅ **IP Reputation** - Check IP abuse score (optional)
- ✅ **Whitelist Protection** - False positive prevention
- ✅ **In-Memory Caching** - Performa optimal
- ✅ **Comprehensive Scoring** - Multi-factor risk assessment

## 🚀 Quick Start

### 1. Installation

```bash
# Clone atau copy project
cd phishing-detector

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Edit .env sesuai kebutuhan
nano .env
```

### 2. Configuration

Edit `.env`:

```env
PORT=3000
NODE_ENV=development

# Optional API Keys (untuk IP reputation check)
ABUSEIPDB_API_KEY=your_key_here
```

### 3. Run

```bash
# Development mode (dengan auto-reload)
npm run dev

# Production mode
npm start
```

## 📡 API Usage

### Check URL

**Endpoint:** `POST /api/check`

**Request Body:**
```json
{
  "url": "https://tok0pedia-login.vercel.app"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "url": "https://tok0pedia-login.vercel.app",
    "verdict": "HIGH_RISK",
    "riskScore": 85,
    "level": "danger",
    "summary": "Critical phishing indicators detected.",
    "recommendation": "DO NOT ENTER CREDENTIALS - Likely phishing attempt.",
    "flags": [
      "HOSTED_PLATFORM",
      "CHAR_SUBSTITUTION",
      "PASSWORD_FORM",
      "SUSPICIOUS_KEYWORDS"
    ],
    "analysis": {
      "domain": {
        "hostname": "tok0pedia-login.vercel.app",
        "rootDomain": "vercel.app",
        "isHostedPlatform": true
      },
      "typosquatting": {
        "matchedBrand": "tokopedia",
        "matchType": "CHAR_SUBSTITUTION",
        "confidence": "HIGH"
      }
    },
    "scores": {
      "typosquatting": 50,
      "heuristic": 15,
      "ssl": 0,
      "content": 20,
      "total": 85
    }
  }
}
```

### Health Check

**Endpoint:** `GET /api/health`

**Response:**
```json
{
  "success": true,
  "status": "healthy",
  "cache": {
    "keys": 15,
    "hits": 127,
    "misses": 48
  }
}
```

## 📊 Verdict Levels

| Score | Verdict | Level | Artinya |
|-------|---------|-------|---------|
| 0-19 | SAFE | success | Aman |
| 20-39 | LOW_RISK | info | Perhatian minor |
| 40-69 | SUSPICIOUS | warning | Mencurigakan |
| 70+ | HIGH_RISK | danger | Sangat berbahaya |

## 🎯 Detection Methods

### 1. URL Heuristics
- Panjang hostname (>50 chars)
- Excessive dashes/digits
- Suspicious keywords
- IP address sebagai hostname
- @ symbol dalam URL

### 2. Typosquatting Detection
- Character substitution (0→o, 1→l)
- Levenshtein distance
- Brand name di subdomain
- Brand + keyword combinations

### 3. SSL/Certificate Check
- HTTPS presence
- Certificate validity
- Expiration date
- Self-signed detection

### 4. Domain Age (WHOIS)
- Creation date
- Age < 30 days = high risk
- Age < 90 days = medium risk

### 5. Content Analysis
- Password form detection
- External form actions
- Sensitive keywords
- Iframe abuse
- Redirect chains

### 6. IP Reputation (Optional)
- AbuseIPDB integration
- Abuse confidence score

## 🔧 Testing

### Contoh Request (cURL)

```bash
# Test legitimate site
curl -X POST http://localhost:3000/api/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://tokopedia.com"}'

# Test phishing site
curl -X POST http://localhost:3000/api/check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://tok0pedia-login.vercel.app"}'

# Health check
curl http://localhost:3000/api/health
```

### Contoh Request (JavaScript)

```javascript
const response = await fetch('http://localhost:3000/api/check', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    url: 'https://example.com'
  })
});

const result = await response.json();
console.log(result.data.verdict);
```

## 🛠️ Customization

### Tambah Brand (Typosquatting)

Edit `src/config/brands.js`:
```javascript
const BRANDS = [
  // ... existing brands
  'yourbrand',
  'anothercompany'
];
```

Atau via `.env`:
```env
CUSTOM_BRANDS=yourbrand,anothercompany,thirdone
```

### Tambah Whitelist

Edit `src/config/whitelist.js`:
```javascript
const WHITELIST_DOMAINS = [
  // ... existing domains
  'yourcompany.com',
  'trusted-site.com'
];
```

## ⚙️ Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | Server port |
| `TIMEOUT_CONTENT` | 8000 | Content fetch timeout (ms) |
| `TIMEOUT_SSL` | 5000 | SSL check timeout (ms) |
| `TIMEOUT_WHOIS` | 5000 | WHOIS timeout (ms) |
| `CACHE_TTL` | 3600 | Cache duration (seconds) |
| `ABUSEIPDB_API_KEY` | - | AbuseIPDB API key (optional) |

## 📈 Performance

- **Average response time:** 2-5 detik
- **Cache hit rate:** ~80% untuk repeated checks
- **Concurrent requests:** Support multiple requests
- **Memory usage:** ~50-100MB

## ⚠️ Limitations

1. **WHOIS Check:** Memerlukan `whois` command di system (Linux/Mac)
   - Windows: Install via WSL atau skip WHOIS check
   
2. **Content Analysis:** HTML only (no JavaScript execution)
   - Trade-off: Fast tapi bisa miss phishing modern yang heavy JS
   
3. **Rate Limits:** External APIs (AbuseIPDB, WHOIS servers) ada rate limit

4. **False Positives:** Bisa terjadi pada:
   - Domain baru tapi legitimate
   - Branded subdomain yang sah
   
5. **False Negatives:** Bisa miss:
   - Phishing yang sangat sophisticated
   - Zero-day phishing campaigns
   - Compromised legitimate domains

### Port Already in Use
```bash
# Change PORT in .env
PORT=3001
```

### Slow Response Time
- Enable caching (already default)
- Reduce timeouts in `.env`
- Disable optional checks (WHOIS, Reputation)

## 📝 License

MIT

## 🤝 Contributing

Feel free to submit issues or PRs!

## 📧 Support

Untuk pertanyaan atau issue, buka GitHub Issues.

---

**⚡ Made with ❤️ using Express.js**
