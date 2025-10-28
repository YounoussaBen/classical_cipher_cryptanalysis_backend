import hashlib

from fastapi import APIRouter, HTTPException, status

from app.dependencies import DbSessionDep, SettingsDep
from app.models.database import Analysis
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, ErrorResponse
from app.services.analysis.statistics import StatisticalAnalyzer
from app.services.detection.cipher_detector import CipherDetector
from app.services.engines.registry import EngineRegistry
from app.services.explanation.generator import ExplanationGenerator
from app.services.preprocessing.normalizer import TextNormalizer

router = APIRouter()


@router.post(
    "",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid input"},
        500: {"model": ErrorResponse, "description": "Analysis failed"},
    },
    summary="Analyze ciphertext",
    description=(
        "Perform comprehensive analysis on ciphertext: "
        "statistical analysis, cipher family detection, and attempted decryption."
    ),
)
async def analyze_ciphertext(
    request: AnalyzeRequest,
    settings: SettingsDep,
    db: DbSessionDep,
) -> AnalyzeResponse:
    """
    Analyze ciphertext and attempt to identify and decrypt it.

    The analysis pipeline:
    1. Normalize and preprocess the ciphertext
    2. Generate statistical profile (frequencies, IOC, entropy)
    3. Detect likely cipher families based on statistics
    4. Run appropriate decryption engines
    5. Generate human-readable explanations
    """
    # Validate ciphertext length
    if len(request.ciphertext) > settings.max_ciphertext_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ciphertext exceeds maximum length of {settings.max_ciphertext_length}",
        )

    try:
        # 1. Normalize text
        normalizer = TextNormalizer()
        normalized = normalizer.normalize(request.ciphertext)

        # 2. Statistical analysis
        analyzer = StatisticalAnalyzer()
        statistics = analyzer.analyze(normalized)

        # 3. Cipher detection
        detector = CipherDetector()
        suspected_ciphers = detector.detect(statistics)

        # 4. Attempt decryption with matching engines
        registry = EngineRegistry()
        plaintext_candidates = []

        for hypothesis in suspected_ciphers[:3]:  # Top 3 hypotheses
            if hypothesis.cipher_type:
                engine = registry.get_engine(hypothesis.cipher_type)
                if engine:
                    candidates = engine.attempt_decrypt(
                        normalized,
                        statistics,
                        request.options,
                    )
                    plaintext_candidates.extend(candidates)

        # Sort candidates by score
        plaintext_candidates.sort(key=lambda x: x.score)
        plaintext_candidates = plaintext_candidates[:10]  # Top 10

        # 5. Generate explanations
        explainer = ExplanationGenerator()
        explanations = explainer.generate(
            statistics=statistics,
            hypotheses=suspected_ciphers,
            candidates=plaintext_candidates,
        )

        # 6. Prepare visualization data
        visual_data = {
            "frequency_chart": [
                {"char": f.character, "freq": f.frequency}
                for f in statistics.character_frequencies[:26]
            ],
            "ioc_comparison": {
                "observed": statistics.index_of_coincidence,
                "english": 0.0667,
                "random": 0.0385,
            },
        }

        # 7. Save to database
        ciphertext_hash = hashlib.sha256(request.ciphertext.encode()).hexdigest()

        # Get best candidate info
        best_plaintext = None
        best_confidence = None
        if plaintext_candidates:
            best_plaintext = plaintext_candidates[0].plaintext
            best_confidence = plaintext_candidates[0].confidence

        analysis = Analysis(
            ciphertext_hash=ciphertext_hash,
            ciphertext=request.ciphertext,
            statistics=statistics.model_dump(),
            suspected_ciphers=[h.model_dump() for h in suspected_ciphers],
            plaintext_candidates=[c.model_dump() for c in plaintext_candidates],
            best_plaintext=best_plaintext,
            best_confidence=best_confidence,
            parameters_used=request.options,
            explanations=explanations,
        )
        db.add(analysis)
        await db.commit()

        return AnalyzeResponse(
            statistics=statistics,
            suspected_ciphers=suspected_ciphers,
            plaintext_candidates=plaintext_candidates,
            explanations=explanations,
            visual_data=visual_data,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
        )
