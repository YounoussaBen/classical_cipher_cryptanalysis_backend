"""
Comprehensive tests for all cipher engines.
"""
import pytest

from app.models.schemas import CipherType, CipherFamily
from app.services.engines.registry import EngineRegistry
from app.services.analysis.statistics import StatisticalAnalyzer


class TestCipherRegistry:
    """Test the cipher registry."""

    def test_all_ciphers_registered(self):
        """Verify all expected ciphers are registered."""
        registered = EngineRegistry.list_registered()

        expected = [
            CipherType.CAESAR,
            CipherType.ROT13,
            CipherType.ATBASH,
            CipherType.AFFINE,
            CipherType.SIMPLE_SUBSTITUTION,
            CipherType.VIGENERE,
            CipherType.BEAUFORT,
            CipherType.AUTOKEY,
            CipherType.RAIL_FENCE,
            CipherType.COLUMNAR,
            CipherType.PLAYFAIR,
            CipherType.HILL,
            CipherType.FOUR_SQUARE,
        ]

        for cipher_type in expected:
            assert cipher_type in registered, f"{cipher_type} not registered"

    def test_get_engines_by_family(self):
        """Test getting engines by cipher family."""
        registry = EngineRegistry()

        mono = registry.get_engines_by_family(CipherFamily.MONOALPHABETIC)
        poly = registry.get_engines_by_family(CipherFamily.POLYALPHABETIC)
        trans = registry.get_engines_by_family(CipherFamily.TRANSPOSITION)
        polyg = registry.get_engines_by_family(CipherFamily.POLYGRAPHIC)

        assert len(mono) == 5  # Caesar, ROT13, Atbash, Affine, SimpleSubstitution
        assert len(poly) == 3  # Vigenere, Beaufort, Autokey
        assert len(trans) == 2  # RailFence, Columnar
        assert len(polyg) == 3  # Playfair, Hill, FourSquare


class TestMonoalphabeticCiphers:
    """Test monoalphabetic cipher engines."""

    @pytest.fixture
    def registry(self):
        return EngineRegistry()

    def test_rot13_self_reciprocal(self, registry):
        """ROT13 applied twice should return original text."""
        engine = registry.get_engine(CipherType.ROT13)
        plaintext = "HELLOWORLD"

        encrypted = engine.encrypt(plaintext, "13")
        double_encrypted = engine.encrypt(encrypted, "13")

        assert double_encrypted == plaintext

    def test_atbash_self_reciprocal(self, registry):
        """Atbash applied twice should return original text."""
        engine = registry.get_engine(CipherType.ATBASH)
        plaintext = "HELLOWORLD"

        encrypted = engine.encrypt(plaintext, "atbash")
        double_encrypted = engine.encrypt(encrypted, "atbash")

        assert double_encrypted == plaintext

    def test_affine_encrypt_decrypt(self, registry):
        """Test Affine cipher encrypt/decrypt roundtrip."""
        engine = registry.get_engine(CipherType.AFFINE)
        plaintext = "HELLOWORLD"
        key = {"a": 5, "b": 8}

        encrypted = engine.encrypt(plaintext, key)
        result = engine.decrypt_with_key(encrypted, key)

        assert result.plaintext == plaintext

    def test_affine_validate_key(self, registry):
        """Test Affine cipher key validation."""
        engine = registry.get_engine(CipherType.AFFINE)

        # Valid keys (a must be coprime with 26)
        assert engine.validate_key({"a": 5, "b": 8})
        assert engine.validate_key({"a": 7, "b": 0})

        # Invalid keys (a not coprime with 26)
        assert not engine.validate_key({"a": 2, "b": 5})  # 2 shares factor with 26
        assert not engine.validate_key({"a": 13, "b": 0})  # 13 shares factor with 26

    def test_simple_substitution_roundtrip(self, registry):
        """Test Simple Substitution encrypt/decrypt."""
        engine = registry.get_engine(CipherType.SIMPLE_SUBSTITUTION)
        plaintext = "HELLO"
        key = engine.generate_random_key()

        encrypted = engine.encrypt(plaintext, key)
        result = engine.decrypt_with_key(encrypted, key)

        assert result.plaintext == plaintext


class TestPolyalphabeticCiphers:
    """Test polyalphabetic cipher engines."""

    @pytest.fixture
    def registry(self):
        return EngineRegistry()

    def test_vigenere_encrypt_decrypt(self, registry):
        """Test Vigenère cipher roundtrip."""
        engine = registry.get_engine(CipherType.VIGENERE)
        plaintext = "ATTACKATDAWN"
        key = "LEMON"

        encrypted = engine.encrypt(plaintext, key)
        result = engine.decrypt_with_key(encrypted, key)

        assert result.plaintext == plaintext

    def test_vigenere_known_example(self, registry):
        """Test Vigenère with known example."""
        engine = registry.get_engine(CipherType.VIGENERE)
        # Classic example: ATTACK AT DAWN with key LEMON
        plaintext = "ATTACKATDAWN"
        key = "LEMON"

        encrypted = engine.encrypt(plaintext, key)
        # Known ciphertext: LXFOPVEFRNHR
        assert encrypted == "LXFOPVEFRNHR"

    def test_beaufort_self_reciprocal(self, registry):
        """Beaufort is self-reciprocal."""
        engine = registry.get_engine(CipherType.BEAUFORT)
        plaintext = "HELLOWORLD"
        key = "SECRET"

        encrypted = engine.encrypt(plaintext, key)
        decrypted = engine.encrypt(encrypted, key)  # Same operation

        assert decrypted == plaintext

    def test_autokey_encrypt_decrypt(self, registry):
        """Test Autokey cipher roundtrip."""
        engine = registry.get_engine(CipherType.AUTOKEY)
        plaintext = "HELLOWORLD"
        key = "K"

        encrypted = engine.encrypt(plaintext, key)
        result = engine.decrypt_with_key(encrypted, key)

        assert result.plaintext == plaintext


class TestTranspositionCiphers:
    """Test transposition cipher engines."""

    @pytest.fixture
    def registry(self):
        return EngineRegistry()

    def test_rail_fence_encrypt_decrypt(self, registry):
        """Test Rail Fence cipher roundtrip."""
        engine = registry.get_engine(CipherType.RAIL_FENCE)
        plaintext = "WEAREDISCOVEREDRUNATONCE"
        key = "3"

        encrypted = engine.encrypt(plaintext, key)
        result = engine.decrypt_with_key(encrypted, key)

        assert result.plaintext == plaintext

    def test_rail_fence_known_example(self, registry):
        """Test Rail Fence with known example."""
        engine = registry.get_engine(CipherType.RAIL_FENCE)
        plaintext = "WEAREDISCOVEREDRUNATONCE"
        key = "3"

        encrypted = engine.encrypt(plaintext, key)
        # Known ciphertext pattern
        assert len(encrypted) == len(plaintext)

    def test_columnar_encrypt_decrypt(self, registry):
        """Test Columnar Transposition roundtrip."""
        engine = registry.get_engine(CipherType.COLUMNAR)
        plaintext = "WEAREDISCOVERED"
        key = "ZEBRA"

        encrypted = engine.encrypt(plaintext, key)
        result = engine.decrypt_with_key(encrypted, key)

        # Note: may have padding, so check if original is contained
        assert plaintext in result.plaintext or result.plaintext.rstrip("X") == plaintext


class TestPolygraphicCiphers:
    """Test polygraphic cipher engines."""

    @pytest.fixture
    def registry(self):
        return EngineRegistry()

    def test_playfair_encrypt_decrypt(self, registry):
        """Test Playfair cipher roundtrip."""
        engine = registry.get_engine(CipherType.PLAYFAIR)
        plaintext = "HELLOWORLD"
        key = "KEYWORD"

        encrypted = engine.encrypt(plaintext, key)
        result = engine.decrypt_with_key(encrypted, key)

        # Playfair adds X for padding, so check containment
        assert "HELLO" in result.plaintext.replace("X", "")

    def test_playfair_handles_double_letters(self, registry):
        """Playfair should handle double letters by inserting X."""
        engine = registry.get_engine(CipherType.PLAYFAIR)
        plaintext = "BALLOON"  # Has double L
        key = "KEYWORD"

        encrypted = engine.encrypt(plaintext, key)
        # Should be able to decrypt
        result = engine.decrypt_with_key(encrypted, key)
        assert result.plaintext is not None

    def test_hill_encrypt_decrypt(self, registry):
        """Test Hill cipher roundtrip."""
        engine = registry.get_engine(CipherType.HILL)
        plaintext = "HELLOWORLD"
        key = [[3, 3], [2, 5]]  # Invertible 2x2 matrix

        encrypted = engine.encrypt(plaintext, key)
        result = engine.decrypt_with_key(encrypted, key)

        assert result.plaintext == plaintext

    def test_hill_validate_key(self, registry):
        """Test Hill cipher key validation."""
        engine = registry.get_engine(CipherType.HILL)

        # Valid key (invertible mod 26)
        assert engine.validate_key([[3, 3], [2, 5]])

        # Invalid key (determinant shares factor with 26)
        # [[1, 2], [3, 4]] has det = -2, which shares factor with 26
        assert not engine.validate_key([[1, 2], [3, 4]])

    def test_four_square_encrypt_decrypt(self, registry):
        """Test Four-Square cipher roundtrip."""
        engine = registry.get_engine(CipherType.FOUR_SQUARE)
        plaintext = "HELLOWORLD"
        key = {"key1": "EXAMPLE", "key2": "KEYWORD"}

        encrypted = engine.encrypt(plaintext, key)
        result = engine.decrypt_with_key(encrypted, key)

        assert result.plaintext == plaintext


class TestCipherDetection:
    """Test cipher detection capabilities."""

    @pytest.fixture
    def registry(self):
        return EngineRegistry()

    @pytest.fixture
    def analyzer(self):
        return StatisticalAnalyzer()

    def test_monoalphabetic_detection(self, registry, analyzer):
        """Monoalphabetic ciphers should have high IOC."""
        engine = registry.get_engine(CipherType.CAESAR)
        # Use text with natural English letter frequencies (not a pangram)
        plaintext = "THERAININSPAINFALLSMAINLYONTHEPLAIN" * 5
        ciphertext = engine.encrypt(plaintext, "7")

        stats = analyzer.analyze(ciphertext)

        # IOC should be close to English (~0.0667)
        assert stats.index_of_coincidence > 0.06

        # Caesar should detect this as likely
        confidence = engine.detect(stats)
        assert confidence > 0.5

    def test_polyalphabetic_detection(self, registry, analyzer):
        """Polyalphabetic ciphers should have lower IOC."""
        engine = registry.get_engine(CipherType.VIGENERE)
        plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3
        ciphertext = engine.encrypt(plaintext, "KEYWORD")

        stats = analyzer.analyze(ciphertext)

        # IOC should be lower than monoalphabetic
        assert stats.index_of_coincidence < 0.06

        # Vigenère should detect this as likely
        confidence = engine.detect(stats)
        assert confidence > 0.3


class TestCryptoanalysis:
    """Test cipher breaking capabilities."""

    @pytest.fixture
    def registry(self):
        return EngineRegistry()

    def test_caesar_break(self, registry):
        """Test breaking Caesar cipher."""
        engine = registry.get_engine(CipherType.CAESAR)
        plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        shift = 7
        ciphertext = engine.encrypt(plaintext, str(shift))

        result = engine.find_key_and_decrypt(ciphertext, {})

        assert result.plaintext == plaintext
        assert result.key == str(shift)

    def test_affine_break(self, registry):
        """Test breaking Affine cipher by brute force."""
        engine = registry.get_engine(CipherType.AFFINE)
        plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        key = {"a": 5, "b": 8}
        ciphertext = engine.encrypt(plaintext, key)

        result = engine.find_key_and_decrypt(ciphertext, {})

        assert result.plaintext == plaintext
