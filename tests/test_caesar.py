"""Tests for Caesar cipher engine."""

import pytest

from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.engines.monoalphabetic.caesar import CaesarEngine


class TestCaesarEngine:
    """Test suite for Caesar cipher engine."""

    @pytest.fixture
    def engine(self):
        return CaesarEngine()

    @pytest.fixture
    def sample_plaintext(self):
        return "HELLO WORLD"

    @pytest.fixture
    def long_plaintext(self):
        """Longer text with natural English letter distribution for IOC testing."""
        return (
            "CRYPTOGRAPHY IS THE STUDY OF SECURE COMMUNICATION IN THE PRESENCE "
            "OF ADVERSARIES. LONG BEFORE COMPUTERS EXISTED PEOPLE INVENTED CIPHERS "
            "TO HIDE MEANING FROM UNAUTHORIZED READERS. SOME METHODS RELIED ON SIMPLE "
            "SUBSTITUTION WHILE OTHERS USED TRANSPOSITION OR PERIODIC KEYS."
        )

    def test_encrypt_decrypt_roundtrip(self, engine, sample_plaintext):
        """Test that encrypt followed by decrypt returns original."""
        for shift in range(26):
            ciphertext = engine.encrypt(sample_plaintext, str(shift))
            result = engine.decrypt_with_key(ciphertext, str(shift))
            # Engine preserves spaces and non-alphabetic chars
            assert result.plaintext == sample_plaintext.upper()

    def test_encrypt_shift_7(self, engine):
        """Test specific encryption with shift 7."""
        plaintext = "HELLO"
        expected = "OLSSV"
        result = engine.encrypt(plaintext, "7")
        assert result == expected

    def test_decrypt_shift_7(self, engine):
        """Test specific decryption with shift 7."""
        ciphertext = "OLSSV"
        expected = "HELLO"
        result = engine.decrypt_with_key(ciphertext, "7")
        assert result.plaintext == expected

    def test_find_key_and_decrypt(self, engine, long_plaintext):
        """Test automatic key finding."""
        shift = 13
        ciphertext = engine.encrypt(long_plaintext, str(shift))

        result = engine.find_key_and_decrypt(ciphertext, {})

        # Should find the correct shift
        assert int(result.key) == shift
        assert result.plaintext == long_plaintext.upper()

    def test_attempt_decrypt_returns_candidates(self, engine, long_plaintext):
        """Test that attempt_decrypt returns multiple candidates."""
        shift = 5
        ciphertext = engine.encrypt(long_plaintext, str(shift))

        analyzer = StatisticalAnalyzer()
        statistics = analyzer.analyze(ciphertext)

        candidates = engine.attempt_decrypt(ciphertext, statistics, {})

        assert len(candidates) > 0
        assert len(candidates) <= 5  # Returns top 5

        # Best candidate should have the correct shift
        best = candidates[0]
        assert int(best.key) == shift

    def test_generate_random_key(self, engine):
        """Test random key generation."""
        keys = [engine.generate_random_key() for _ in range(100)]

        # All keys should be valid shifts
        for key in keys:
            assert engine.validate_key(key)
            shift = int(key)
            assert 1 <= shift <= 25  # Excludes 0 (no encryption)

    def test_validate_key(self, engine):
        """Test key validation."""
        # Valid keys
        for i in range(26):
            assert engine.validate_key(str(i)) is True

        # Invalid keys
        assert engine.validate_key("abc") is False
        assert engine.validate_key("-1") is True  # -1 % 26 = 25
        assert engine.validate_key("100") is True  # 100 % 26 = 22

    def test_detect_monoalphabetic(self, engine, long_plaintext):
        """Test cipher detection on known Caesar text."""
        ciphertext = engine.encrypt(long_plaintext, "7")

        analyzer = StatisticalAnalyzer()
        statistics = analyzer.analyze(ciphertext)

        confidence = engine.detect(statistics)

        # Should detect as likely monoalphabetic (IOC close to English)
        assert confidence > 0.5

    def test_explain(self, engine):
        """Test explanation generation."""
        explanation = engine.explain("OLSSV", "HELLO", 7)

        assert "7" in explanation
        assert "shift" in explanation.lower()


class TestStatisticalAnalyzer:
    """Test suite for statistical analyzer."""

    @pytest.fixture
    def analyzer(self):
        return StatisticalAnalyzer()

    @pytest.fixture
    def english_text(self):
        """Natural English text with typical letter distribution."""
        return (
            "CRYPTOGRAPHY IS THE STUDY OF SECURE COMMUNICATION IN THE PRESENCE "
            "OF ADVERSARIES. LONG BEFORE COMPUTERS EXISTED PEOPLE INVENTED CIPHERS "
            "TO HIDE MEANING FROM UNAUTHORIZED READERS. SOME METHODS RELIED ON SIMPLE "
            "SUBSTITUTION WHILE OTHERS USED TRANSPOSITION OR PERIODIC KEYS."
        )

    def test_analyze_english_text(self, analyzer, english_text):
        """Test analysis of English text."""
        stats = analyzer.analyze(english_text)

        # IOC should be close to English (~0.0667)
        assert 0.05 < stats.index_of_coincidence < 0.08

        # Length should match letters only
        letters_only = "".join(c for c in english_text if c.isalpha())
        assert stats.length == len(letters_only)

    def test_index_of_coincidence_random(self, analyzer):
        """Test IOC on random-like text."""
        # Text with uniform distribution should have lower IOC
        text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 10
        stats = analyzer.analyze(text)

        # IOC should be close to random (1/26 ≈ 0.0385)
        assert stats.index_of_coincidence < 0.05

    def test_character_frequencies(self, analyzer):
        """Test character frequency calculation."""
        text = "AAABBC"
        stats = analyzer.analyze(text)

        # Find frequencies
        freq_dict = {f.character: f.frequency for f in stats.character_frequencies}

        assert freq_dict["A"] == pytest.approx(3 / 6)
        assert freq_dict["B"] == pytest.approx(2 / 6)
        assert freq_dict["C"] == pytest.approx(1 / 6)

    def test_english_score(self, analyzer):
        """Test English scoring."""
        english_text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        random_text = "XQZJKVWPFGMYBCL"

        english_score = analyzer.english_score(english_text)
        random_score = analyzer.english_score(random_text)

        # English text should have lower (better) score
        assert english_score < random_score
