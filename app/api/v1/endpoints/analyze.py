"""
Analyze endpoint - AI-powered cryptanalysis.

This endpoint implements the signal-driven cryptanalysis pipeline:
1. Phase 0: Statistical fingerprinting (cipher family classification)
2. Phase 1: Targeted decryption by cost tier with early exit
3. Phase 2: Multi-language scoring
4. Phase 3: Statistical filtering
5. Phase 4: AI validation and formatting
6. Phase 5: Response assembly
"""

import hashlib
from typing import Any

from fastapi import APIRouter, HTTPException, status

from app.dependencies import DbSessionDep, SettingsDep
from app.models.database import Analysis
from app.models.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    ClassificationResult,
    CipherType,
    DecryptionResultSchema,
    ErrorResponse,
)
from app.services.ai.gemini_client import GeminiClient
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.pipeline.orchestrator import DecryptionOrchestrator

router = APIRouter()


@router.post(
    "",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid input"},
        500: {"model": ErrorResponse, "description": "Analysis failed"},
    },
    summary="Analyze and decrypt ciphertext",
    description=(
        "Perform AI-powered cryptanalysis: classify cipher family, "
        "run targeted decryption, and return the decrypted result "
        "with statistical analysis for visualization."
    ),
)
async def analyze_ciphertext(
    request: AnalyzeRequest,
    settings: SettingsDep,
    db: DbSessionDep,
) -> AnalyzeResponse:
    """
    Analyze ciphertext and decrypt it.

    The pipeline:
    1. Compute statistics for visualization
    2. Classify cipher family using statistical invariants
    3. Run targeted decryption (cheap engines first, early exit on success)
    4. Score candidates against all supported languages
    5. Filter garbage candidates
    6. Use AI to validate winner and format output
    7. Return the answer with statistics for frontend
    """
    # Validate ciphertext length
    if len(request.ciphertext) > settings.max_ciphertext_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ciphertext exceeds maximum length of {settings.max_ciphertext_length}",
        )

    try:
        # === PHASE 1: Statistical Profile (for frontend visualization) ===
        analyzer = StatisticalAnalyzer()
        statistics = analyzer.analyze(request.ciphertext)

        # === PHASE 0-3: Orchestrated Decryption ===
        orchestrator = DecryptionOrchestrator()
        orchestration_result = orchestrator.orchestrate(
            request.ciphertext,
            request.options,
        )

        # === Prepare Classification Result ===
        classification = ClassificationResult(
            monoalphabetic_probability=orchestration_result.classification.monoalphabetic,
            polyalphabetic_probability=orchestration_result.classification.polyalphabetic,
            transposition_probability=orchestration_result.classification.transposition,
            classification_confidence=orchestration_result.classification.classification_confidence,
            reasoning=orchestration_result.classification.reasoning,
        )

        # === PHASE 4: AI Validation and Formatting ===
        result: DecryptionResultSchema | None = None
        
        if orchestration_result.best_candidate:
            best = orchestration_result.best_candidate
            
            # Prepare the raw result
            formatted_plaintext = None
            detected_language = best.best_language.capitalize()
            
            # Use AI to validate and format if enabled
            if settings.enable_ai_formatting and len(best.plaintext) > 5:
                try:
                    gemini = GeminiClient(settings.GEMINI_API_KEY, settings.gemini_model)
                    
                    # Step 1: Send truncated candidates to AI for validation/selection
                    candidates_for_ai = [
                        {"plaintext": c.plaintext[:300], "score": c.best_score}
                        for c in orchestration_result.candidates[:5]
                    ]
                    
                    ai_result = await gemini.evaluate_and_format_candidates(candidates_for_ai)
                    
                    # Use AI's selection if it makes sense
                    ai_index = ai_result.get("best_index")
                    if ai_index is not None:
                        # AI returns 1-based index
                        ai_index = ai_index - 1 if ai_index > 0 else 0
                        if 0 <= ai_index < len(orchestration_result.candidates):
                            # AI picked a different candidate - use it if reasonable
                            ai_pick = orchestration_result.candidates[ai_index]
                            # Only switch if AI's pick isn't much worse
                            if ai_pick.best_score < best.best_score * 2:
                                best = ai_pick
                    
                    if ai_result.get("language"):
                        detected_language = ai_result.get("language")
                    
                    # Step 2: Format the FULL winning plaintext
                    # Use the same method as decrypt endpoint
                    format_result = await gemini.detect_language_and_format(best.plaintext)
                    await gemini.close()
                    
                    formatted_plaintext = format_result.get("formatted_text")
                    if format_result.get("language"):
                        detected_language = format_result.get("language")
                        
                except Exception:
                    # AI failed, continue without formatting
                    pass
            
            # Generate explanation
            explanation = _generate_explanation(best.cipher_type, best.key, best.best_language)
            
            result = DecryptionResultSchema(
                plaintext=best.plaintext,
                formatted_plaintext=formatted_plaintext,
                cipher_type=CipherType(best.cipher_type),
                key=best.key,
                detected_language=detected_language,
                confidence=best.confidence,
                explanation=explanation,
            )

        # === PHASE 5: Visual Data for Frontend ===
        visual_data = _prepare_visual_data(statistics, classification)

        # === Analysis Info (debug/performance) ===
        analysis_info = {
            "total_candidates_generated": orchestration_result.total_candidates_generated,
            "candidates_after_filter": orchestration_result.candidates_after_filter,
            "early_exit": orchestration_result.early_exit,
            "early_exit_reason": orchestration_result.early_exit_reason,
            "tiers_executed": orchestration_result.tiers_executed,
        }

        # === Save to Database ===
        ciphertext_hash = hashlib.sha256(request.ciphertext.encode()).hexdigest()
        
        analysis = Analysis(
            ciphertext_hash=ciphertext_hash,
            ciphertext=request.ciphertext,
            statistics=statistics.model_dump(),
            detected_language=result.detected_language if result else None,
            # New classification field
            classification=classification.model_dump(),
            # Legacy field for backward compatibility
            suspected_ciphers=[{
                "family": "monoalphabetic" if classification.monoalphabetic_probability > 0.5 
                         else "polyalphabetic" if classification.polyalphabetic_probability > 0.5
                         else "transposition",
                "confidence": classification.classification_confidence,
            }],
            plaintext_candidates=[{
                "plaintext": c.plaintext[:200],
                "cipher_type": c.cipher_type,
                "key": str(c.key),
                "score": c.best_score,
                "language": c.best_language,
            } for c in orchestration_result.candidates[:5]],
            # Full result fields
            best_plaintext=result.plaintext if result else None,
            best_formatted_plaintext=result.formatted_plaintext if result else None,
            best_cipher_type=result.cipher_type.value if result else None,
            best_key=str(result.key) if result else None,
            best_confidence=result.confidence if result else None,
            best_explanation=result.explanation if result else None,
            # Visual data and analysis info
            visual_data=visual_data,
            analysis_info=analysis_info,
            parameters_used=request.options,
            explanations=[result.explanation] if result and result.explanation else [],
        )
        db.add(analysis)
        await db.commit()

        return AnalyzeResponse(
            statistics=statistics,
            classification=classification,
            result=result,
            visual_data=visual_data,
            analysis_info=analysis_info,
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
        )


def _generate_explanation(cipher_type: str, key: Any, language: str) -> str:
    """Generate a human-readable explanation of the decryption."""
    
    explanations = {
        "caesar": lambda k: (
            f"Caesar cipher with shift of {k}. "
            f"Each letter was shifted back {k} positions in the alphabet."
        ),
        "rot13": lambda k: (
            "ROT13 cipher (Caesar with shift 13). "
            "Each letter was shifted back 13 positions."
        ),
        "atbash": lambda k: (
            "Atbash cipher. The alphabet was reversed (A↔Z, B↔Y, etc.)."
        ),
        "affine": lambda k: (
            f"Affine cipher with a={k.get('a', '?')} and b={k.get('b', '?')}. "
            f"Decryption formula: D(y) = a⁻¹(y - b) mod 26."
        ),
        "simple_substitution": lambda k: (
            f"Simple substitution cipher. Each letter was mapped to a different letter "
            f"using a random permutation of the alphabet."
        ),
        "vigenere": lambda k: (
            f"Vigenère cipher with keyword '{k}'. "
            f"Each letter was shifted by the corresponding keyword letter."
        ),
        "beaufort": lambda k: (
            f"Beaufort cipher with keyword '{k}'. "
            f"Similar to Vigenère but with a different encryption formula."
        ),
        "autokey": lambda k: (
            f"Autokey cipher with primer '{k}'. "
            f"The keyword is extended using the plaintext itself."
        ),
        "rail_fence": lambda k: (
            f"Rail Fence cipher with {k} rails. "
            f"The text was written in a zigzag pattern and read off row by row."
        ),
        "columnar": lambda k: (
            f"Columnar transposition cipher with key '{k}'. "
            f"The text was written in columns and read in a shuffled order."
        ),
    }
    
    generator = explanations.get(cipher_type, lambda k: f"Decrypted using {cipher_type} cipher.")
    base_explanation = generator(key)
    
    return f"{base_explanation} The plaintext appears to be in {language}."


def _prepare_visual_data(statistics, classification: ClassificationResult) -> dict[str, Any]:
    """Prepare data for frontend visualization."""
    
    return {
        "frequency_chart": [
            {"char": f.character, "freq": f.frequency}
            for f in statistics.character_frequencies[:26]
        ],
        "ioc_comparison": {
            "observed": statistics.index_of_coincidence,
            "random": 0.0385,
            "languages": {
                "english": 0.0667,
                "french": 0.0778,
                "german": 0.0762,
                "spanish": 0.0775,
                "italian": 0.0738,
                "portuguese": 0.0745,
            },
        },
        "classification_chart": {
            "monoalphabetic": classification.monoalphabetic_probability,
            "polyalphabetic": classification.polyalphabetic_probability,
            "transposition": classification.transposition_probability,
        },
        "entropy": {
            "observed": statistics.entropy,
            "max_possible": 4.7,  # log2(26)
            "natural_language": 4.1,
        },
    }
