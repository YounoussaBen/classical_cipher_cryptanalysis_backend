import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry


@EngineRegistry.register
class HillEngine(CipherEngine):
    """
    Hill cipher engine.

    The Hill cipher uses matrix multiplication for encryption.
    Plaintext is divided into vectors of length n, and each vector
    is multiplied by an n x n key matrix modulo 26.

    For a 2x2 matrix:
    [a b]   [p1]   [a*p1 + b*p2]
    [c d] x [p2] = [c*p1 + d*p2] (mod 26)

    The key matrix must be invertible modulo 26.
    """

    name = "Hill Cipher"
    cipher_type = CipherType.HILL
    cipher_family = CipherFamily.POLYGRAPHIC
    description = (
        "A polygraphic cipher using linear algebra. "
        "Blocks of letters are encrypted by multiplying with a key matrix. "
        "The key matrix must be invertible modulo 26."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase

    # Common 2x2 key matrices that are invertible mod 26
    COMMON_KEYS_2X2: ClassVar[list[list[list[int]]]] = [
        [[3, 3], [2, 5]],   # "DDCF"
        [[6, 24], [1, 13]], # "GYBN"
        [[5, 8], [17, 3]],  # "FIRD"
        [[2, 3], [1, 4]],   # "CDBE"
        [[9, 4], [5, 7]],   # "JEFH"
    ]

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this could be Hill-encrypted.

        Hill cipher has distinctive properties:
        - Block-based (length often divisible by block size)
        - Disrupts normal frequency patterns
        """
        ioc = statistics.index_of_coincidence
        length = statistics.length

        # Block sizes are typically 2 or 3
        block_bonus = 0.05 if length % 2 == 0 or length % 3 == 0 else 0

        # Hill disrupts frequency more than most ciphers
        if 0.04 < ioc < 0.055:
            base = 0.3
        elif ioc > 0.055:
            base = 0.1
        else:
            base = 0.2

        return min(1.0, base + block_bonus)

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Try common key matrices.

        Full Hill cryptanalysis typically requires known-plaintext attack.
        """
        analyzer = StatisticalAnalyzer()
        candidates = []

        filtered = "".join(c for c in ciphertext.upper() if c in self.ALPHABET)

        if len(filtered) < 2:
            return []

        # Try common 2x2 keys
        for key_matrix in self.COMMON_KEYS_2X2:
            try:
                inverse = self._matrix_inverse_mod26(key_matrix)
                if inverse is None:
                    continue

                plaintext = self._decrypt_with_matrix(ciphertext, inverse)
                score = analyzer.english_score(plaintext)
                confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

                key_str = self._matrix_to_string(key_matrix)
                candidates.append(PlaintextCandidate(
                    plaintext=plaintext,
                    score=score,
                    confidence=confidence,
                    cipher_type=self.cipher_type,
                    key=key_str,
                    method="dictionary",
                ))
            except ValueError:
                continue

        candidates.sort(key=lambda x: x.score)
        return candidates[:5]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt with a known key matrix."""
        matrix = self._parse_key(key)
        inverse = self._matrix_inverse_mod26(matrix)

        if inverse is None:
            raise ValueError("Key matrix is not invertible mod 26")

        plaintext = self._decrypt_with_matrix(ciphertext, inverse)
        key_str = self._matrix_to_string(matrix)

        return DecryptionResult(
            plaintext=plaintext,
            key=key_str,
            confidence=1.0,
            explanation=self.explain(ciphertext, plaintext, matrix),
        )

    def find_key_and_decrypt(
        self,
        ciphertext: str,
        options: dict[str, Any],
    ) -> DecryptionResult:
        """Find the key and decrypt."""
        analyzer = StatisticalAnalyzer()
        statistics = analyzer.analyze(ciphertext)

        candidates = self.attempt_decrypt(ciphertext, statistics, options)

        if not candidates:
            raise ValueError("Could not decrypt ciphertext")

        best = candidates[0]
        return DecryptionResult(
            plaintext=best.plaintext,
            key=best.key,
            confidence=best.confidence,
            explanation=self.explain(ciphertext, best.plaintext, self._parse_key(best.key)),
        )

    def encrypt(
        self,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Encrypt using the key matrix."""
        matrix = self._parse_key(key)
        return self._encrypt_with_matrix(plaintext, matrix)

    def generate_random_key(self) -> str:
        """Generate a random invertible 2x2 key matrix."""
        while True:
            matrix = [
                [random.randint(0, 25), random.randint(0, 25)],
                [random.randint(0, 25), random.randint(0, 25)],
            ]
            if self._matrix_inverse_mod26(matrix) is not None:
                return self._matrix_to_string(matrix)

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """Validate that key is an invertible matrix."""
        try:
            matrix = self._parse_key(key)
            return self._matrix_inverse_mod26(matrix) is not None
        except (ValueError, TypeError):
            return False

    def explain(
        self,
        ciphertext: str,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Generate human-readable explanation."""
        if isinstance(key, list):
            matrix = key
        else:
            matrix = self._parse_key(key)

        n = len(matrix)
        matrix_str = "\n".join(
            "[" + " ".join(f"{x:2d}" for x in row) + "]"
            for row in matrix
        )

        return (
            f"Hill cipher with {n}x{n} key matrix:\n{matrix_str}\n"
            f"Each group of {n} letters is multiplied by this matrix modulo 26. "
            f"Decryption uses the matrix inverse."
        )

    def _parse_key(self, key: str | dict[str, Any]) -> list[list[int]]:
        """Parse key to matrix."""
        if isinstance(key, list):
            return key

        if isinstance(key, dict):
            if "matrix" in key:
                return key["matrix"]
            key = key.get("key", "")

        key_str = str(key).upper()

        # If it's a 4-letter string like "DCFD", convert to 2x2 matrix
        if len(key_str) == 4:
            return [
                [self.ALPHABET.index(key_str[0]), self.ALPHABET.index(key_str[1])],
                [self.ALPHABET.index(key_str[2]), self.ALPHABET.index(key_str[3])],
            ]
        elif len(key_str) == 9:
            return [
                [self.ALPHABET.index(key_str[0]), self.ALPHABET.index(key_str[1]), self.ALPHABET.index(key_str[2])],
                [self.ALPHABET.index(key_str[3]), self.ALPHABET.index(key_str[4]), self.ALPHABET.index(key_str[5])],
                [self.ALPHABET.index(key_str[6]), self.ALPHABET.index(key_str[7]), self.ALPHABET.index(key_str[8])],
            ]
        else:
            raise ValueError(f"Invalid key format: expected 4 or 9 characters")

    def _matrix_to_string(self, matrix: list[list[int]]) -> str:
        """Convert matrix to string representation."""
        return "".join(
            self.ALPHABET[x % 26]
            for row in matrix
            for x in row
        )

    def _mod_inverse(self, a: int, m: int = 26) -> int | None:
        """Calculate modular multiplicative inverse."""
        from math import gcd
        if gcd(a % m, m) != 1:
            return None

        def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        _, x, _ = extended_gcd(a % m, m)
        return (x % m + m) % m

    def _matrix_inverse_mod26(self, matrix: list[list[int]]) -> list[list[int]] | None:
        """Calculate matrix inverse modulo 26."""
        n = len(matrix)

        if n == 2:
            a, b = matrix[0]
            c, d = matrix[1]

            det = (a * d - b * c) % 26
            det_inv = self._mod_inverse(det)

            if det_inv is None:
                return None

            return [
                [(d * det_inv) % 26, (-b * det_inv) % 26],
                [(-c * det_inv) % 26, (a * det_inv) % 26],
            ]
        elif n == 3:
            # For 3x3 matrix, use adjugate method
            det = self._det_3x3(matrix)
            det_inv = self._mod_inverse(det % 26)

            if det_inv is None:
                return None

            adj = self._adjugate_3x3(matrix)
            return [
                [(adj[i][j] * det_inv) % 26 for j in range(3)]
                for i in range(3)
            ]
        else:
            raise ValueError("Only 2x2 and 3x3 matrices supported")

    def _det_3x3(self, m: list[list[int]]) -> int:
        """Calculate determinant of 3x3 matrix."""
        return (
            m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) -
            m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0]) +
            m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
        )

    def _adjugate_3x3(self, m: list[list[int]]) -> list[list[int]]:
        """Calculate adjugate of 3x3 matrix."""
        return [
            [
                (m[1][1] * m[2][2] - m[1][2] * m[2][1]),
                -(m[0][1] * m[2][2] - m[0][2] * m[2][1]),
                (m[0][1] * m[1][2] - m[0][2] * m[1][1]),
            ],
            [
                -(m[1][0] * m[2][2] - m[1][2] * m[2][0]),
                (m[0][0] * m[2][2] - m[0][2] * m[2][0]),
                -(m[0][0] * m[1][2] - m[0][2] * m[1][0]),
            ],
            [
                (m[1][0] * m[2][1] - m[1][1] * m[2][0]),
                -(m[0][0] * m[2][1] - m[0][1] * m[2][0]),
                (m[0][0] * m[1][1] - m[0][1] * m[1][0]),
            ],
        ]

    def _encrypt_with_matrix(self, plaintext: str, matrix: list[list[int]]) -> str:
        """Encrypt using matrix multiplication."""
        plaintext = plaintext.upper()
        plaintext = "".join(c for c in plaintext if c in self.ALPHABET)

        n = len(matrix)

        # Pad to multiple of block size
        while len(plaintext) % n != 0:
            plaintext += "X"

        result = []
        for i in range(0, len(plaintext), n):
            block = [self.ALPHABET.index(c) for c in plaintext[i:i + n]]

            # Matrix multiplication
            encrypted = []
            for row in matrix:
                val = sum(row[j] * block[j] for j in range(n)) % 26
                encrypted.append(self.ALPHABET[val])

            result.extend(encrypted)

        return "".join(result)

    def _decrypt_with_matrix(self, ciphertext: str, inverse: list[list[int]]) -> str:
        """Decrypt using inverse matrix multiplication."""
        return self._encrypt_with_matrix(ciphertext, inverse)
