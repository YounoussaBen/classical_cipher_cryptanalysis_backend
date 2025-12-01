# API Reference

Base URL: `/api/v1`

## Overview

The Cryptanalysis Platform API provides endpoints for analyzing, detecting, encrypting, and decrypting classical ciphers. All responses are JSON.

---

## Endpoints

### POST /analyze

**Purpose**: Comprehensive ciphertext analysis pipeline.

**Use Case**: When you have ciphertext and want to automatically identify the cipher type and attempt decryption.

**Request Body**:
```json
{
  "ciphertext": "KHOOR ZRUOG",
  "options": {}
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ciphertext` | string | Yes | The encrypted text to analyze (1-100,000 chars) |
| `options` | object | No | Additional analysis options |

**Response**:
```json
{
  "statistics": {
    "length": 10,
    "unique_chars": 8,
    "character_frequencies": [...],
    "bigram_frequencies": [...],
    "trigram_frequencies": [...],
    "index_of_coincidence": 0.0667,
    "entropy": 3.92,
    "chi_squared": 45.2,
    "repeated_sequences": [...],
    "kasiski_distances": [...]
  },
  "suspected_ciphers": [
    {
      "cipher_family": "monoalphabetic",
      "cipher_type": "caesar",
      "confidence": 0.85,
      "reasoning": ["IOC close to English", "..."]
    }
  ],
  "plaintext_candidates": [
    {
      "plaintext": "HELLO WORLD",
      "score": 23.5,
      "confidence": 0.92,
      "cipher_type": "caesar",
      "key": "3",
      "method": "brute_force"
    }
  ],
  "explanations": [
    "The ciphertext contains 10 characters using 8 unique letters.",
    "Index of Coincidence: 0.0667. Close to English."
  ],
  "visual_data": {
    "frequency_chart": [...],
    "ioc_comparison": {...}
  }
}
```

**Frontend Integration**:
- Display statistics in charts/graphs
- Show cipher hypotheses ranked by confidence
- Present plaintext candidates for user selection
- Render explanations in a step-by-step format

---

### POST /decrypt

**Purpose**: Decrypt ciphertext with a specified cipher type.

**Use Case**: When you know (or suspect) the cipher type and want to decrypt directly.

**Request Body**:
```json
{
  "ciphertext": "KHOOR ZRUOG",
  "cipher_type": "caesar",
  "key": "3",
  "options": {}
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ciphertext` | string | Yes | The encrypted text |
| `cipher_type` | string | Yes | The cipher type (see [Supported Ciphers](#supported-ciphers)) |
| `key` | string/object | No | The decryption key. If omitted, the system will attempt to find it |
| `options` | object | No | Additional options |

**Response**:
```json
{
  "plaintext": "HELLO WORLD",
  "confidence": 0.95,
  "key_used": "3",
  "explanation": "Caesar cipher with shift of 3. Each letter was shifted back 3 positions."
}
```

**Frontend Integration**:
- Provide cipher type dropdown/selector
- Optional key input field
- Display result with confidence indicator
- Show explanation for educational value

---

### POST /encrypt

**Purpose**: Encrypt plaintext using a specified cipher.

**Use Case**: Educational tool for generating test ciphertexts, demonstrating how ciphers work.

**Request Body**:
```json
{
  "plaintext": "HELLO WORLD",
  "cipher_type": "caesar",
  "key": "3",
  "options": {}
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `plaintext` | string | Yes | The text to encrypt |
| `cipher_type` | string | Yes | The cipher type to use |
| `key` | string/object | No | The encryption key. If omitted, a random key is generated |
| `options` | object | No | Additional options |

**Response**:
```json
{
  "ciphertext": "KHOOR ZRUOG",
  "cipher_type": "caesar",
  "key_used": "3"
}
```

**Frontend Integration**:
- Interactive cipher demonstration
- "Try it yourself" feature
- Generate practice ciphertexts

---

### GET /history

**Purpose**: Retrieve paginated history of previous analyses.

**Use Case**: Allow users to review past analyses, track progress, replay results.

**Query Parameters**:
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | int | 1 | Page number (1-indexed) |
| `page_size` | int | 20 | Items per page (1-100) |

**Response**:
```json
{
  "items": [
    {
      "id": 1,
      "ciphertext_hash": "abc123...",
      "ciphertext_preview": "KHOOR ZRUOG...",
      "best_cipher": "caesar",
      "best_confidence": 0.92,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 42,
  "page": 1,
  "page_size": 20
}
```

**Frontend Integration**:
- History list/table with pagination
- Click to view full analysis details
- Search/filter capabilities

---

### GET /history/{analysis_id}

**Purpose**: Retrieve full details of a specific analysis.

**Use Case**: View complete results of a past analysis.

**Response**:
```json
{
  "id": 1,
  "ciphertext_hash": "abc123...",
  "ciphertext": "KHOOR ZRUOG",
  "statistics": {...},
  "detected_language": "en",
  "suspected_ciphers": [...],
  "plaintext_candidates": [...],
  "best_plaintext": "HELLO WORLD",
  "best_confidence": 0.92,
  "parameters_used": {},
  "explanations": [...],
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

---

## Supported Ciphers

### Currently Implemented

| Cipher Type | Family | Key Format | Description |
|-------------|--------|------------|-------------|
| `caesar` | monoalphabetic | Integer (0-25) | Shifts each letter by a fixed amount |

### Planned (Not Yet Implemented)

| Cipher Type | Family | Key Format | Description |
|-------------|--------|------------|-------------|
| `rot13` | monoalphabetic | None (fixed) | Caesar with shift=13 |
| `atbash` | monoalphabetic | None (fixed) | Reverses alphabet (A↔Z) |
| `simple_substitution` | monoalphabetic | 26-letter permutation | Random letter mapping |
| `affine` | monoalphabetic | Two integers (a, b) | ax + b mod 26 |
| `vigenere` | polyalphabetic | Keyword string | Repeating key Caesar |
| `beaufort` | polyalphabetic | Keyword string | Variant of Vigenère |
| `autokey` | polyalphabetic | Keyword + plaintext | Self-keying cipher |
| `columnar` | transposition | Keyword/number sequence | Column rearrangement |
| `rail_fence` | transposition | Integer (rails) | Zigzag pattern |
| `playfair` | polygraphic | 5x5 key square | Digraph substitution |
| `hill` | polygraphic | Matrix | Linear algebra cipher |
| `four_square` | polygraphic | Two 5x5 key squares | Four-square cipher |

---

## Cipher Families

### Monoalphabetic
- Single alphabet substitution
- Each letter always maps to the same ciphertext letter
- **Detection**: High Index of Coincidence (~0.067)
- **Attack**: Frequency analysis, pattern matching

### Polyalphabetic
- Multiple alphabet substitution
- Same letter can map to different ciphertext letters
- **Detection**: Lower IOC, repeated sequences (Kasiski)
- **Attack**: Kasiski examination, frequency analysis per position

### Transposition
- Letters rearranged, not substituted
- Preserves letter frequencies exactly
- **Detection**: IOC matches plaintext language
- **Attack**: Anagramming, pattern analysis

### Polygraphic
- Operates on groups of letters (digraphs, trigraphs)
- More complex substitution patterns
- **Detection**: Disrupted bigram frequencies
- **Attack**: Known plaintext, frequency of letter groups

---

## Statistics Explained

### Index of Coincidence (IOC)
Probability that two random letters from the text are the same.
- **English**: ~0.0667
- **Random**: ~0.0385 (1/26)
- **High IOC**: Suggests monoalphabetic or transposition
- **Low IOC**: Suggests polyalphabetic

### Entropy
Measures randomness/information content (in bits).
- **English text**: ~4.1 bits
- **Maximum (26 letters)**: ~4.7 bits
- **Higher entropy**: More random/encrypted

### Chi-Squared
Measures deviation from expected English frequencies.
- **Lower**: Better match to English
- **< 50**: Excellent match
- **50-100**: Good match
- **> 200**: Significant deviation

### Kasiski Distances
Distances between repeated sequences in ciphertext.
- Used to find polyalphabetic key length
- GCD of distances often reveals key length

---

## Error Responses

All errors follow this format:
```json
{
  "error": "error_type",
  "message": "Human-readable description",
  "details": {}
}
```

| Status Code | Description |
|-------------|-------------|
| 400 | Invalid input (ciphertext too long, invalid parameters) |
| 404 | Resource not found (cipher type, analysis ID) |
| 500 | Internal server error |

---

## Frontend Implementation Guide

### Recommended Flow

1. **Main Analysis Page**
   - Large text input for ciphertext
   - "Analyze" button → calls `POST /analyze`
   - Display results in tabs: Statistics, Detection, Candidates, Explanation

2. **Manual Decrypt Page**
   - Cipher type selector
   - Optional key input
   - Ciphertext input
   - "Decrypt" button → calls `POST /decrypt`

3. **Encrypt/Learn Page**
   - Educational tool
   - Cipher type selector with descriptions
   - Plaintext input
   - Shows encryption step-by-step

4. **History Page**
   - Paginated list of past analyses
   - Click to view full details
   - Re-analyze or export options

### Visualization Suggestions

- **Frequency Chart**: Bar chart of letter frequencies
- **IOC Gauge**: Visual comparison to English/random baselines
- **Cipher Confidence**: Horizontal bar chart or pie chart
- **Decryption Steps**: Animated or step-through visualization
