from app.models.schemas import CipherHypothesis, PlaintextCandidate, StatisticsProfile


class ExplanationGenerator:
    """
    Generates human-readable explanations for cryptanalysis results.

    All explanations are grounded in actual statistics and metrics.
    No hallucination - every claim references data.
    """

    # Reference values for comparisons
    ENGLISH_IOC = 0.0667
    RANDOM_IOC = 0.0385
    ENGLISH_ENTROPY = 4.1

    def generate(
        self,
        statistics: StatisticsProfile,
        hypotheses: list[CipherHypothesis],
        candidates: list[PlaintextCandidate],
    ) -> list[str]:
        """
        Generate explanations for the analysis.

        Args:
            statistics: Statistical profile of ciphertext
            hypotheses: Cipher family hypotheses
            candidates: Decryption candidates

        Returns:
            List of explanation strings
        """
        explanations = []

        # 1. Explain the statistical analysis
        explanations.extend(self._explain_statistics(statistics))

        # 2. Explain cipher detection reasoning
        explanations.extend(self._explain_detection(statistics, hypotheses))

        # 3. Explain decryption results
        if candidates:
            explanations.extend(self._explain_candidates(candidates))

        return explanations

    def _explain_statistics(self, statistics: StatisticsProfile) -> list[str]:
        """Explain the statistical analysis results."""
        explanations = []

        # Length and character analysis
        explanations.append(
            f"The ciphertext contains {statistics.length} characters "
            f"using {statistics.unique_chars} unique letters."
        )

        # Index of Coincidence
        ioc = statistics.index_of_coincidence
        ioc_explanation = self._interpret_ioc(ioc)
        explanations.append(
            f"Index of Coincidence: {ioc:.4f}. {ioc_explanation}"
        )

        # Entropy
        entropy = statistics.entropy
        entropy_explanation = self._interpret_entropy(entropy)
        explanations.append(
            f"Entropy: {entropy:.2f} bits. {entropy_explanation}"
        )

        # Chi-squared if available
        if statistics.chi_squared is not None:
            chi_explanation = self._interpret_chi_squared(statistics.chi_squared)
            explanations.append(
                f"Chi-squared against English: {statistics.chi_squared:.1f}. {chi_explanation}"
            )

        # Top frequencies
        if statistics.character_frequencies:
            top_chars = statistics.character_frequencies[:5]
            freq_str = ", ".join(
                f"{f.character} ({f.frequency*100:.1f}%)"
                for f in top_chars
            )
            explanations.append(f"Most frequent letters: {freq_str}.")

        # Repeated sequences (Kasiski)
        if statistics.repeated_sequences:
            seqs = statistics.repeated_sequences[:3]
            seq_info = [f"'{s['sequence']}' ({s['count']}x)" for s in seqs]
            explanations.append(
                f"Repeated sequences found: {', '.join(seq_info)}. "
                "This pattern can help determine key length for polyalphabetic ciphers."
            )

        return explanations

    def _interpret_ioc(self, ioc: float) -> str:
        """Interpret the Index of Coincidence value."""
        if ioc >= 0.065:
            return (
                f"This is close to English ({self.ENGLISH_IOC:.4f}), "
                "suggesting monoalphabetic substitution or transposition."
            )
        elif ioc >= 0.050:
            return (
                "This is between English and random, suggesting a "
                "polyalphabetic cipher with a short key, or mixed cipher."
            )
        elif ioc >= 0.040:
            return (
                f"This is closer to random ({self.RANDOM_IOC:.4f}), "
                "suggesting polyalphabetic encryption with a longer key."
            )
        else:
            return (
                "This is near random, suggesting either a very long key, "
                "one-time pad, or non-alphabetic encryption."
            )

    def _interpret_entropy(self, entropy: float) -> str:
        """Interpret the entropy value."""
        max_entropy = 4.7  # log2(26)

        if entropy < 3.5:
            return "Low entropy indicates highly structured text."
        elif entropy < 4.0:
            return "Moderate entropy, consistent with natural language."
        elif entropy < 4.5:
            return "Higher entropy suggests some randomization."
        else:
            return f"Near-maximum entropy ({max_entropy:.1f}) suggests high randomness."

    def _interpret_chi_squared(self, chi_sq: float) -> str:
        """Interpret chi-squared against English."""
        if chi_sq < 50:
            return "Excellent match to English letter frequencies."
        elif chi_sq < 100:
            return "Good match to English, likely real text."
        elif chi_sq < 200:
            return "Moderate deviation from English."
        elif chi_sq < 400:
            return "Significant deviation, possibly encrypted or non-English."
        else:
            return "Large deviation from English letter distribution."

    def _explain_detection(
        self,
        statistics: StatisticsProfile,
        hypotheses: list[CipherHypothesis],
    ) -> list[str]:
        """Explain cipher detection reasoning."""
        explanations = []

        if not hypotheses:
            explanations.append(
                "Could not determine cipher type from available statistics."
            )
            return explanations

        # Top hypothesis
        top = hypotheses[0]
        explanations.append(
            f"Most likely cipher: {top.cipher_family.value}"
            + (f" ({top.cipher_type.value})" if top.cipher_type else "")
            + f" with {top.confidence*100:.0f}% confidence."
        )

        # Reasoning for top hypothesis
        if top.reasoning:
            for reason in top.reasoning[:3]:
                explanations.append(f"  - {reason}")

        # Alternative hypotheses
        if len(hypotheses) > 1:
            alternatives = [
                f"{h.cipher_type.value if h.cipher_type else h.cipher_family.value} "
                f"({h.confidence*100:.0f}%)"
                for h in hypotheses[1:4]
            ]
            explanations.append(f"Alternative possibilities: {', '.join(alternatives)}.")

        return explanations

    def _explain_candidates(
        self,
        candidates: list[PlaintextCandidate],
    ) -> list[str]:
        """Explain decryption candidates."""
        explanations = []

        if not candidates:
            explanations.append("No viable plaintext candidates found.")
            return explanations

        best = candidates[0]
        explanations.append(
            f"Best decryption result ({best.confidence*100:.0f}% confidence):"
        )
        explanations.append(
            f"  Cipher: {best.cipher_type.value}, Key: {best.key}"
        )

        # Show preview of plaintext
        preview = best.plaintext[:100]
        if len(best.plaintext) > 100:
            preview += "..."
        explanations.append(f'  Plaintext preview: "{preview}"')

        # Explain scoring
        explanations.append(
            f"  Score: {best.score:.1f} (lower is better match to English)"
        )

        # Alternative candidates
        if len(candidates) > 1:
            alt_count = min(3, len(candidates) - 1)
            explanations.append(
                f"  {alt_count} alternative candidate(s) also found."
            )

        return explanations

    def explain_cipher_attack(
        self,
        cipher_type: str,
        method: str,
        key: str,
    ) -> str:
        """
        Generate explanation for a specific cipher attack.

        Args:
            cipher_type: Type of cipher attacked
            method: Method used (brute_force, hill_climbing, etc.)
            key: The key that was found

        Returns:
            Explanation string
        """
        method_explanations = {
            "brute_force": (
                "All possible keys were tried systematically, "
                "and each result was scored against English language patterns."
            ),
            "hill_climbing": (
                "Starting from a random key, the algorithm iteratively "
                "made small changes, keeping improvements until no better "
                "key could be found."
            ),
            "simulated_annealing": (
                "Similar to hill climbing, but occasionally accepts worse "
                "solutions to escape local optima, gradually reducing this "
                "randomness over time."
            ),
            "frequency_analysis": (
                "Letter frequencies in the ciphertext were matched against "
                "expected English frequencies to determine the key."
            ),
            "kasiski": (
                "Repeated sequences in the ciphertext revealed likely key "
                "lengths through their spacing distances."
            ),
        }

        base = method_explanations.get(
            method,
            "The key was determined through cryptanalysis."
        )

        return f"{cipher_type} decrypted with key '{key}'. {base}"
