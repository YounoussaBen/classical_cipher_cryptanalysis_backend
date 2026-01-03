"""
Decryption orchestrator - the brain of the cryptanalysis pipeline.

This module implements the core decryption logic:
1. Run targeted decryption by cost tier (Phase 1)
2. Early exit on dominant candidates
3. Coordinate scoring and filtering
"""

import string
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.models.schemas import CipherType
from app.services.engines.registry import EngineRegistry
from app.services.pipeline.classifier import CipherClassifier, CipherFamilyProbabilities
from app.services.pipeline.scorer import CandidateScorer, ScoredCandidate
from app.services.pipeline.filter import CandidateFilter


@dataclass
class DecryptionCandidate:
    """Raw decryption candidate before scoring."""
    
    plaintext: str
    cipher_type: str
    key: str | dict
    method: str


@dataclass
class OrchestrationResult:
    """Result of the decryption orchestration."""
    
    # Best candidate after all processing
    best_candidate: ScoredCandidate | None
    
    # All candidates that passed filtering (sorted by score)
    candidates: list[ScoredCandidate]
    
    # Classification that guided the search
    classification: CipherFamilyProbabilities
    
    # Performance metrics
    total_candidates_generated: int
    candidates_after_filter: int
    early_exit: bool
    early_exit_reason: str | None
    
    # Tiers executed
    tiers_executed: list[str]


class DecryptionOrchestrator:
    """
    Orchestrates the decryption process across all cipher engines.
    
    Implements a tiered approach:
    - Tier 1 (INSTANT): Caesar, ROT13, Atbash, Affine, Rail Fence
    - Tier 2 (MODERATE): Vigenère, Beaufort, Autokey, Columnar
    - Tier 3 (EXPENSIVE): Simple Substitution (hill-climbing)
    
    Early exit when a dominant candidate is found (chi² < 40).
    """
    
    ALPHABET: ClassVar[str] = string.ascii_uppercase
    
    # Thresholds for early exit
    EARLY_EXIT_CHI_SQUARED: ClassVar[float] = 40.0  # Almost certainly correct
    GOOD_CANDIDATE_CHI_SQUARED: ClassVar[float] = 80.0  # Worth stopping Tier 3
    
    # Cipher tiers by cost
    TIER_1_CIPHERS: ClassVar[list[CipherType]] = [
        CipherType.CAESAR,
        CipherType.ROT13,
        CipherType.ATBASH,
        CipherType.AFFINE,
        CipherType.RAIL_FENCE,
    ]
    
    TIER_2_CIPHERS: ClassVar[list[CipherType]] = [
        CipherType.VIGENERE,
        CipherType.BEAUFORT,
        CipherType.AUTOKEY,
        CipherType.COLUMNAR,
    ]
    
    TIER_3_CIPHERS: ClassVar[list[CipherType]] = [
        CipherType.SIMPLE_SUBSTITUTION,
    ]
    
    # Mapping from cipher type to family
    CIPHER_FAMILIES: ClassVar[dict[CipherType, str]] = {
        CipherType.CAESAR: "monoalphabetic",
        CipherType.ROT13: "monoalphabetic",
        CipherType.ATBASH: "monoalphabetic",
        CipherType.AFFINE: "monoalphabetic",
        CipherType.SIMPLE_SUBSTITUTION: "monoalphabetic",
        CipherType.VIGENERE: "polyalphabetic",
        CipherType.BEAUFORT: "polyalphabetic",
        CipherType.AUTOKEY: "polyalphabetic",
        CipherType.RAIL_FENCE: "transposition",
        CipherType.COLUMNAR: "transposition",
    }
    
    def __init__(self):
        self.classifier = CipherClassifier()
        self.scorer = CandidateScorer()
        self.filter = CandidateFilter()
        self.registry = EngineRegistry()
    
    def orchestrate(
        self,
        ciphertext: str,
        options: dict[str, Any] | None = None,
    ) -> OrchestrationResult:
        """
        Run the full decryption orchestration.
        
        Args:
            ciphertext: The ciphertext to decrypt
            options: Additional options for engines
            
        Returns:
            OrchestrationResult with best candidate and metadata
        """
        options = options or {}
        
        # Normalize ciphertext
        normalized = "".join(c for c in ciphertext.upper() if c in self.ALPHABET)
        
        if len(normalized) < 3:
            return OrchestrationResult(
                best_candidate=None,
                candidates=[],
                classification=CipherFamilyProbabilities(),
                total_candidates_generated=0,
                candidates_after_filter=0,
                early_exit=True,
                early_exit_reason="Ciphertext too short",
                tiers_executed=[],
            )
        
        # Phase 0: Classify cipher family
        classification = self.classifier.classify(normalized)
        
        # Determine which ciphers to try based on classification
        ciphers_to_try = self._select_ciphers(classification)
        
        # Track results
        all_raw_candidates: list[DecryptionCandidate] = []
        tiers_executed: list[str] = []
        early_exit = False
        early_exit_reason = None
        
        # === TIER 1: Instant ciphers ===
        tier1_ciphers = [c for c in ciphers_to_try if c in self.TIER_1_CIPHERS]
        if tier1_ciphers:
            tiers_executed.append("tier1")
            tier1_candidates = self._run_tier(normalized, tier1_ciphers, options)
            all_raw_candidates.extend(tier1_candidates)
            
            # Check for early exit
            best_so_far = self._find_best_candidate(all_raw_candidates)
            if best_so_far and best_so_far.best_score < self.EARLY_EXIT_CHI_SQUARED:
                early_exit = True
                early_exit_reason = f"Dominant candidate found in Tier 1 (score={best_so_far.best_score:.1f})"
        
        # === TIER 2: Moderate ciphers ===
        if not early_exit:
            tier2_ciphers = [c for c in ciphers_to_try if c in self.TIER_2_CIPHERS]
            if tier2_ciphers:
                tiers_executed.append("tier2")
                tier2_candidates = self._run_tier(normalized, tier2_ciphers, options)
                all_raw_candidates.extend(tier2_candidates)
                
                # Check for early exit
                best_so_far = self._find_best_candidate(all_raw_candidates)
                if best_so_far and best_so_far.best_score < self.EARLY_EXIT_CHI_SQUARED:
                    early_exit = True
                    early_exit_reason = f"Dominant candidate found in Tier 2 (score={best_so_far.best_score:.1f})"
        
        # === TIER 3: Expensive ciphers ===
        if not early_exit:
            # Only run Tier 3 if we don't have a good candidate yet
            best_so_far = self._find_best_candidate(all_raw_candidates)
            should_run_tier3 = (
                best_so_far is None or 
                best_so_far.best_score > self.GOOD_CANDIDATE_CHI_SQUARED
            )
            
            if should_run_tier3:
                tier3_ciphers = [c for c in ciphers_to_try if c in self.TIER_3_CIPHERS]
                if tier3_ciphers:
                    tiers_executed.append("tier3")
                    tier3_candidates = self._run_tier(normalized, tier3_ciphers, options)
                    all_raw_candidates.extend(tier3_candidates)
            else:
                early_exit = True
                early_exit_reason = f"Good candidate found, skipping Tier 3 (score={best_so_far.best_score:.1f})"
        
        # Score all candidates
        scored_candidates = [
            self.scorer.score_candidate(
                c.plaintext, c.cipher_type, c.key, c.method
            )
            for c in all_raw_candidates
        ]
        
        # Filter candidates
        filter_result = self.filter.filter(scored_candidates, max_results=10)
        
        # Get best candidate
        best_candidate = filter_result.passed[0] if filter_result.passed else None
        
        return OrchestrationResult(
            best_candidate=best_candidate,
            candidates=filter_result.passed,
            classification=classification,
            total_candidates_generated=len(all_raw_candidates),
            candidates_after_filter=len(filter_result.passed),
            early_exit=early_exit,
            early_exit_reason=early_exit_reason,
            tiers_executed=tiers_executed,
        )
    
    def _select_ciphers(
        self,
        classification: CipherFamilyProbabilities,
    ) -> list[CipherType]:
        """
        Select which ciphers to try based on classification.
        
        Includes ciphers from families with probability > 0.2,
        but always includes at least one cipher from each family
        if classification confidence is low.
        """
        ciphers = []
        
        # Threshold for including a family
        threshold = 0.2
        
        # If classification confidence is low, lower the threshold
        if classification.classification_confidence < 0.3:
            threshold = 0.1
        
        # Monoalphabetic ciphers
        if classification.monoalphabetic >= threshold:
            for cipher_name in classification.likely_monoalphabetic:
                try:
                    cipher_type = CipherType(cipher_name)
                    if cipher_type not in ciphers:
                        ciphers.append(cipher_type)
                except ValueError:
                    continue
            
            # Always include Caesar if monoalphabetic is likely
            if CipherType.CAESAR not in ciphers:
                ciphers.append(CipherType.CAESAR)
        
        # Polyalphabetic ciphers
        if classification.polyalphabetic >= threshold:
            for cipher_name in classification.likely_polyalphabetic:
                try:
                    cipher_type = CipherType(cipher_name)
                    if cipher_type not in ciphers:
                        ciphers.append(cipher_type)
                except ValueError:
                    continue
            
            # Always include Vigenère if polyalphabetic is likely
            if CipherType.VIGENERE not in ciphers:
                ciphers.append(CipherType.VIGENERE)
        
        # Transposition ciphers
        if classification.transposition >= threshold:
            for cipher_name in classification.likely_transposition:
                try:
                    cipher_type = CipherType(cipher_name)
                    if cipher_type not in ciphers:
                        ciphers.append(cipher_type)
                except ValueError:
                    continue
            
            # Always include Rail Fence if transposition is likely
            if CipherType.RAIL_FENCE not in ciphers:
                ciphers.append(CipherType.RAIL_FENCE)
        
        # If nothing selected (shouldn't happen), try common ones
        if not ciphers:
            ciphers = [
                CipherType.CAESAR,
                CipherType.VIGENERE,
                CipherType.RAIL_FENCE,
            ]
        
        return ciphers
    
    def _run_tier(
        self,
        ciphertext: str,
        cipher_types: list[CipherType],
        options: dict[str, Any],
    ) -> list[DecryptionCandidate]:
        """
        Run decryption for a list of cipher types.
        
        Returns raw candidates (not yet scored).
        """
        candidates = []
        
        for cipher_type in cipher_types:
            engine = self.registry.get_engine(cipher_type)
            if engine is None:
                continue
            
            try:
                # Use the engine's attempt_decrypt method
                from app.services.analysis.statistics import StatisticalAnalyzer
                analyzer = StatisticalAnalyzer()
                statistics = analyzer.analyze(ciphertext)
                
                engine_candidates = engine.attempt_decrypt(ciphertext, statistics, options)
                
                for ec in engine_candidates:
                    candidates.append(DecryptionCandidate(
                        plaintext=ec.plaintext,
                        cipher_type=cipher_type.value,
                        key=ec.key,
                        method=ec.method,
                    ))
            except Exception:
                # Engine failed, continue with others
                continue
        
        return candidates
    
    def _find_best_candidate(
        self,
        raw_candidates: list[DecryptionCandidate],
    ) -> ScoredCandidate | None:
        """
        Score candidates and find the best one.
        
        Used for early exit checking.
        """
        if not raw_candidates:
            return None
        
        scored = [
            self.scorer.score_candidate(
                c.plaintext, c.cipher_type, c.key, c.method
            )
            for c in raw_candidates
        ]
        
        # Filter out obvious garbage
        filtered = self.filter.filter(scored, max_results=1)
        
        return filtered.passed[0] if filtered.passed else None
