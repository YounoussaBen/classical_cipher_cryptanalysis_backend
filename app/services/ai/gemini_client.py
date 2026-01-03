"""
Gemini AI client for text processing tasks.

Used for:
- Detecting language of decrypted text
- Adding proper spacing/formatting to make text human-readable
- Enhancing explanation generation
"""
import httpx
from typing import Any

from app.core.config import get_settings


class GeminiClient:
    """
    Client for Google's Gemini API.

    Provides text processing capabilities to enhance cryptanalysis output.
    """

    BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
    DEFAULT_MODEL = "gemini-2.5-flash-lite"

    def __init__(self, api_key: str | None = None, model: str | None = None):
        """
        Initialize Gemini client.

        Args:
            api_key: Gemini API key. Falls back to settings if not provided.
            model: Model to use. Defaults to gemini-2.5-flash-lite.
        """
        settings = get_settings()
        self.api_key = api_key or settings.GEMINI_API_KEY
        self.model = model or self.DEFAULT_MODEL
        self._client = httpx.AsyncClient(timeout=30.0)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def generate_content(self, prompt: str) -> str:
        """
        Generate content using Gemini.

        Args:
            prompt: The prompt to send to Gemini

        Returns:
            Generated text response
        """
        url = f"{self.BASE_URL}/{self.model}:generateContent"

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ]
        }

        headers = {
            "x-goog-api-key": self.api_key,
            "Content-Type": "application/json",
        }

        response = await self._client.post(url, json=payload, headers=headers)
        response.raise_for_status()

        data = response.json()

        # Extract text from response
        candidates = data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            if parts:
                return parts[0].get("text", "")

        return ""

    async def detect_language_and_format(self, text: str) -> dict[str, Any]:
        """
        Detect language and add proper spacing to text.

        This is particularly useful for decrypted text which often
        comes out as all uppercase without spaces.

        Args:
            text: The text to process (typically decrypted plaintext)

        Returns:
            Dictionary with:
            - language: Detected language
            - formatted_text: Text with proper spacing
            - confidence: Confidence in the detection
        """
        prompt = f"""Analyze the following text and perform two tasks:
1. Detect the language of the text
2. Rewrite it with proper spacing and capitalization so it is human-readable

Text to analyze:
{text}

Respond in this exact JSON format (no markdown, just raw JSON):
{{"language": "English", "formatted_text": "The formatted text here", "confidence": 0.95}}

If the text appears to be gibberish or not a real language, set language to "Unknown" and confidence to a low value."""

        try:
            response = await self.generate_content(prompt)

            # Try to parse JSON from response
            import json

            # Clean up response - remove markdown code blocks if present
            response = response.strip()
            if response.startswith("```"):
                # Remove markdown code block
                lines = response.split("\n")
                response = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

            result = json.loads(response)
            return {
                "language": result.get("language", "Unknown"),
                "formatted_text": result.get("formatted_text", text),
                "confidence": result.get("confidence", 0.5),
            }
        except Exception as e:
            # Fallback if parsing fails
            return {
                "language": "Unknown",
                "formatted_text": text,
                "confidence": 0.0,
                "error": str(e),
            }

    async def format_decrypted_text(self, text: str) -> str:
        """
        Add proper spacing and formatting to decrypted text.

        Args:
            text: Decrypted text (typically all caps, no spaces)

        Returns:
            Formatted, human-readable text
        """
        prompt = f"""Rewrite the following text with proper spacing, punctuation, and capitalization to make it human-readable. The text is a decrypted message that lost its spacing:

{text}

Return ONLY the formatted text, nothing else."""

        try:
            response = await self.generate_content(prompt)
            return response.strip()
        except Exception:
            return text

    async def detect_language(self, text: str) -> str:
        """
        Detect the language of text.

        Args:
            text: Text to analyze

        Returns:
            Detected language name
        """
        prompt = f"""What language is the following text written in? Respond with ONLY the language name (e.g., "English", "French", "German"):

{text}"""

        try:
            response = await self.generate_content(prompt)
            return response.strip()
        except Exception:
            return "Unknown"

    async def evaluate_and_format_candidates(
        self,
        plaintext_candidates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Evaluate plaintext candidates and identify the most sensible one.

        The AI only receives the plaintext strings and their scores - it does NOT
        see the ciphertext, keys, or algorithm details. Its job is purely to:
        1. Identify which plaintext looks like real, coherent language
        2. Format the best candidate for human readability

        Args:
            plaintext_candidates: List of dicts with 'plaintext', 'score', 'confidence'

        Returns:
            Dictionary with:
            - best_index: Index of the best candidate (0-based)
            - formatted_text: Human-readable version of the best candidate
            - language: Detected language
            - language_confidence: Confidence in language detection
            - reasoning: Brief explanation of why this candidate was chosen
        """
        if not plaintext_candidates:
            return {
                "best_index": None,
                "formatted_text": None,
                "language": None,
                "language_confidence": None,
                "reasoning": "No candidates provided",
            }

        # Only send plaintext strings to AI - no keys, algorithms, or ciphertext
        candidates_text = "\n".join(
            f"Candidate {i + 1}: {c.get('plaintext', '')[:200]}"
            for i, c in enumerate(plaintext_candidates[:5])  # Max 5 candidates
        )

        prompt = f"""You are analyzing decrypted text candidates. Your ONLY job is to identify which text looks like real, coherent language (not gibberish).

Here are the plaintext candidates:
{candidates_text}

Analyze each candidate and determine:
1. Which one appears to be real, coherent text in a natural language
2. What language it is written in
3. Rewrite the best candidate with proper spacing, punctuation, and capitalization

Respond in this exact JSON format (no markdown, just raw JSON):
{{"best_index": 1, "language": "French", "language_confidence": 0.95, "formatted_text": "The properly formatted text here", "reasoning": "Brief explanation"}}

Important rules:
- best_index is 1-based (1 for first candidate, 2 for second, etc.)
- If NO candidate looks like real language, set best_index to null and explain why
- Only format the text - do not add, remove, or change any words
- If the text has accented characters missing (common in cryptanalysis), add them appropriately"""

        try:
            response = await self.generate_content(prompt)
            import json

            # Clean up response
            response = response.strip()
            if response.startswith("```"):
                lines = response.split("\n")
                response = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

            result = json.loads(response)
            return {
                "best_index": result.get("best_index"),
                "formatted_text": result.get("formatted_text"),
                "language": result.get("language"),
                "language_confidence": result.get("language_confidence"),
                "reasoning": result.get("reasoning"),
            }
        except Exception as e:
            return {
                "best_index": 0,  # Default to first candidate
                "formatted_text": None,
                "language": None,
                "language_confidence": None,
                "reasoning": f"AI evaluation failed: {str(e)}",
            }

    async def enhance_explanation(
        self,
        cipher_type: str,
        ciphertext: str,
        plaintext: str,
        key: str,
        technical_explanation: str,
    ) -> str:
        """
        Generate an enhanced, educational explanation of the decryption.

        Args:
            cipher_type: Type of cipher used
            ciphertext: Original ciphertext
            plaintext: Decrypted plaintext
            key: Key used for decryption
            technical_explanation: Base technical explanation

        Returns:
            Enhanced educational explanation
        """
        prompt = f"""You are explaining cryptanalysis to a student. Given this decryption:

Cipher Type: {cipher_type}
Ciphertext: {ciphertext[:100]}{"..." if len(ciphertext) > 100 else ""}
Plaintext: {plaintext[:100]}{"..." if len(plaintext) > 100 else ""}
Key: {key}
Technical Details: {technical_explanation}

Write a clear, educational explanation (2-3 paragraphs) that:
1. Explains how this cipher works
2. Shows how the key transforms letters with a specific example
3. Mentions the historical context or common uses

Keep it concise and engaging."""

        try:
            response = await self.generate_content(prompt)
            return response.strip()
        except Exception:
            return technical_explanation


# Synchronous wrapper for non-async contexts
class GeminiClientSync:
    """Synchronous wrapper for GeminiClient."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key
        self.model = model

    def _run_async(self, coro):
        """Run async coroutine synchronously."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)

    def detect_language_and_format(self, text: str) -> dict[str, Any]:
        """Synchronous version of detect_language_and_format."""
        async def _run():
            client = GeminiClient(self.api_key, self.model)
            try:
                return await client.detect_language_and_format(text)
            finally:
                await client.close()
        return self._run_async(_run())

    def format_decrypted_text(self, text: str) -> str:
        """Synchronous version of format_decrypted_text."""
        async def _run():
            client = GeminiClient(self.api_key, self.model)
            try:
                return await client.format_decrypted_text(text)
            finally:
                await client.close()
        return self._run_async(_run())

    def detect_language(self, text: str) -> str:
        """Synchronous version of detect_language."""
        async def _run():
            client = GeminiClient(self.api_key, self.model)
            try:
                return await client.detect_language(text)
            finally:
                await client.close()
        return self._run_async(_run())
