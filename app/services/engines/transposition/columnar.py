import random
import string
from typing import Any, ClassVar

from app.models.schemas import CipherFamily, CipherType, PlaintextCandidate, StatisticsProfile
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.base import CipherEngine, DecryptionResult
from app.services.engines.registry import EngineRegistry
from app.services.optimization.scoring import LanguageScorer


@EngineRegistry.register
class ColumnarEngine(CipherEngine):
    """
    Columnar Transposition cipher engine.

    The plaintext is written into a grid row by row, then the columns
    are read out in an order determined by a keyword.

    Example with keyword "ZEBRAS" (sorted: B=1, E=2, R=4, S=5, Z=6, A=3):

    Key:    Z E B R A S
    Order:  6 2 1 4 3 5
            ─────────────
            W E A R E D
            I S C O V E
            R E D F L E
            E A T O N C
            E X X X X X  (padded)

    Read columns in sorted order: ACX, ESE, EEX, OFO, VLN, DECE, WIRE
    """

    name = "Columnar Transposition Cipher"
    cipher_type = CipherType.COLUMNAR
    cipher_family = CipherFamily.TRANSPOSITION
    description = (
        "A transposition cipher where plaintext is written into a grid "
        "by rows, then read out by columns in an order determined by "
        "a keyword. The keyword's alphabetical order determines column sequence."
    )

    ALPHABET: ClassVar[str] = string.ascii_uppercase
    COMMON_KEYS: ClassVar[list[str]] = [
        "KEY", "SECRET", "CIPHER", "CODE", "ZEBRAS", "GERMAN",
        "CRYPTO", "HIDDEN", "COLUMN", "SECURE", "TRANS",
    ]

    def detect(self, statistics: StatisticsProfile) -> float:
        """
        Determine if this could be Columnar Transposition.

        Transposition preserves letter frequencies, so IOC should match English.
        """
        ioc = statistics.index_of_coincidence

        if ioc > 0.065:
            return 0.6  # High IOC = likely transposition
        elif ioc > 0.06:
            return 0.4
        else:
            return 0.1

    def attempt_decrypt(
        self,
        ciphertext: str,
        statistics: StatisticsProfile,
        options: dict[str, Any],
    ) -> list[PlaintextCandidate]:
        """
        Try different key lengths and orderings.
        """
        analyzer = StatisticalAnalyzer()
        scorer = LanguageScorer()
        candidates = []

        filtered = "".join(c for c in ciphertext.upper() if c in self.ALPHABET)
        n = len(filtered)

        if n < 4:
            return []

        # Try common keywords
        for keyword in self.COMMON_KEYS:
            plaintext = self._decrypt(ciphertext, keyword)
            score = analyzer.english_score(plaintext)
            confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

            candidates.append(PlaintextCandidate(
                plaintext=plaintext,
                score=score,
                confidence=confidence,
                cipher_type=self.cipher_type,
                key=keyword,
                method="dictionary",
            ))

        # Try numeric keys (column orderings) for different key lengths
        max_key_length = min(options.get("max_key_length", 8), n // 2)

        for key_length in range(2, max_key_length + 1):
            # Try to find best ordering using frequency analysis
            best_key = self._find_best_ordering(filtered, key_length)
            if best_key:
                plaintext = self._decrypt_with_order(ciphertext, best_key)
                score = analyzer.english_score(plaintext)
                confidence = max(0.0, min(1.0, 1.0 - (score / 500)))

                candidates.append(PlaintextCandidate(
                    plaintext=plaintext,
                    score=score,
                    confidence=confidence,
                    cipher_type=self.cipher_type,
                    key=",".join(map(str, best_key)),
                    method="frequency_analysis",
                ))

        candidates.sort(key=lambda x: x.score)
        return candidates[:5]

    def decrypt_with_key(
        self,
        ciphertext: str,
        key: str | dict[str, Any],
    ) -> DecryptionResult:
        """Decrypt with a known keyword or column ordering."""
        key_parsed = self._parse_key(key)

        if isinstance(key_parsed, str):
            plaintext = self._decrypt(ciphertext, key_parsed)
            key_display = key_parsed
        else:
            plaintext = self._decrypt_with_order(ciphertext, key_parsed)
            key_display = ",".join(map(str, key_parsed))

        return DecryptionResult(
            plaintext=plaintext,
            key=key_display,
            confidence=1.0,
            explanation=self.explain(ciphertext, plaintext, key_display),
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
            explanation=self.explain(ciphertext, best.plaintext, best.key),
        )

    def encrypt(
        self,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Encrypt using the keyword."""
        key_parsed = self._parse_key(key)

        if isinstance(key_parsed, str):
            return self._encrypt(plaintext, key_parsed)
        else:
            return self._encrypt_with_order(plaintext, key_parsed)

    def generate_random_key(self) -> str:
        """Generate a random keyword."""
        length = random.randint(4, 8)
        return "".join(random.choice(self.ALPHABET) for _ in range(length))

    def validate_key(self, key: str | dict[str, Any]) -> bool:
        """Validate that key is valid."""
        try:
            key_parsed = self._parse_key(key)
            if isinstance(key_parsed, str):
                return len(key_parsed) >= 2
            else:
                return len(key_parsed) >= 2 and len(set(key_parsed)) == len(key_parsed)
        except (ValueError, TypeError):
            return False

    def explain(
        self,
        ciphertext: str,
        plaintext: str,
        key: str | dict[str, Any],
    ) -> str:
        """Generate human-readable explanation."""
        if isinstance(key, str) and not key[0].isdigit():
            # Keyword
            order = self._keyword_to_order(key)
            return (
                f"Columnar transposition with keyword '{key}'. "
                f"Column order: {order}. "
                f"The plaintext was written in rows, then columns were "
                f"read in the order determined by sorting the keyword alphabetically."
            )
        else:
            return (
                f"Columnar transposition with column order {key}. "
                f"The ciphertext was written column by column in this order, "
                f"then read row by row to recover the plaintext."
            )

    def _parse_key(self, key: str | dict[str, Any]) -> str | list[int]:
        """Parse key to keyword string or numeric ordering."""
        if isinstance(key, dict):
            key = key.get("key", key.get("keyword", key.get("order", "")))

        if isinstance(key, list):
            return [int(x) for x in key]

        key_str = str(key)

        # Check if it's a numeric ordering like "3,1,4,2"
        if "," in key_str or key_str[0].isdigit():
            return [int(x) for x in key_str.replace(" ", "").split(",")]

        return key_str.upper()

    def _keyword_to_order(self, keyword: str) -> list[int]:
        """Convert keyword to column ordering."""
        keyword = keyword.upper()
        # Sort by character, keeping original indices
        sorted_chars = sorted(enumerate(keyword), key=lambda x: x[1])
        order = [0] * len(keyword)
        for new_pos, (orig_pos, _) in enumerate(sorted_chars):
            order[orig_pos] = new_pos + 1  # 1-indexed
        return order

    def _order_to_positions(self, order: list[int]) -> list[int]:
        """Convert column order to read positions."""
        # order[i] tells which column position i should be read
        # We need the inverse: which original position should be read at each step
        positions = [0] * len(order)
        for i, o in enumerate(order):
            positions[o - 1] = i  # o is 1-indexed
        return positions

    def _find_best_ordering(self, ciphertext: str, key_length: int) -> list[int] | None:
        """
        Find the best column ordering using a greedy approach.

        This is a simplified heuristic - full solution would require
        trying all permutations or using more sophisticated optimization.
        """
        from itertools import permutations

        n = len(ciphertext)
        num_rows = (n + key_length - 1) // key_length

        # For small key lengths, try all permutations
        if key_length <= 6:
            best_order = None
            best_score = float("inf")

            for perm in permutations(range(1, key_length + 1)):
                order = list(perm)
                plaintext = self._decrypt_with_order(ciphertext, order)

                from app.services.analysis.statistics import StatisticalAnalyzer
                analyzer = StatisticalAnalyzer()
                score = analyzer.english_score(plaintext)

                if score < best_score:
                    best_score = score
                    best_order = order

            return best_order

        # For larger key lengths, use random sampling
        best_order = None
        best_score = float("inf")

        for _ in range(1000):  # Try 1000 random orderings
            order = list(range(1, key_length + 1))
            random.shuffle(order)

            plaintext = self._decrypt_with_order(ciphertext, order)

            from app.services.analysis.statistics import StatisticalAnalyzer
            analyzer = StatisticalAnalyzer()
            score = analyzer.english_score(plaintext)

            if score < best_score:
                best_score = score
                best_order = order

        return best_order

    def _encrypt(self, plaintext: str, keyword: str) -> str:
        """Encrypt using keyword."""
        order = self._keyword_to_order(keyword)
        return self._encrypt_with_order(plaintext, order)

    def _encrypt_with_order(self, plaintext: str, order: list[int]) -> str:
        """Encrypt using column ordering."""
        plaintext = plaintext.upper()
        key_length = len(order)

        # Pad plaintext to fill grid
        while len(plaintext) % key_length != 0:
            plaintext += "X"

        num_rows = len(plaintext) // key_length

        # Build grid row by row
        grid = []
        for i in range(num_rows):
            grid.append(list(plaintext[i * key_length:(i + 1) * key_length]))

        # Read columns in order
        result = []
        for col_idx in range(1, key_length + 1):
            # Find which column has this order number
            col_pos = order.index(col_idx)
            for row in grid:
                result.append(row[col_pos])

        return "".join(result)

    def _decrypt(self, ciphertext: str, keyword: str) -> str:
        """Decrypt using keyword."""
        order = self._keyword_to_order(keyword)
        return self._decrypt_with_order(ciphertext, order)

    def _decrypt_with_order(self, ciphertext: str, order: list[int]) -> str:
        """Decrypt using column ordering."""
        ciphertext = ciphertext.upper()
        key_length = len(order)
        n = len(ciphertext)
        num_rows = (n + key_length - 1) // key_length

        # Calculate column lengths (some might be shorter due to padding)
        num_long_cols = n % key_length
        if num_long_cols == 0:
            num_long_cols = key_length

        col_lengths = []
        for i in range(key_length):
            # Columns with lower order numbers get read first
            # So if we have short columns, they're the ones with higher orders
            col_order = order[i]
            if col_order <= num_long_cols:
                col_lengths.append(num_rows)
            else:
                col_lengths.append(num_rows - 1)

        # Split ciphertext into columns based on reading order
        columns = [[] for _ in range(key_length)]
        idx = 0
        for col_order in range(1, key_length + 1):
            col_pos = order.index(col_order)
            length = col_lengths[col_pos]
            columns[col_pos] = list(ciphertext[idx:idx + length])
            idx += length

        # Read row by row
        result = []
        for row in range(num_rows):
            for col in range(key_length):
                if row < len(columns[col]):
                    result.append(columns[col][row])

        return "".join(result)
