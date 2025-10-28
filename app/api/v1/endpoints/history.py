from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from app.dependencies import DbSessionDep
from app.models.database import Analysis
from app.models.schemas import (
    AnalysisDetailResponse,
    AnalysisHistoryItem,
    ErrorResponse,
    HistoryResponse,
)

router = APIRouter()


@router.get(
    "",
    response_model=HistoryResponse,
    responses={
        500: {"model": ErrorResponse, "description": "Failed to retrieve history"},
    },
    summary="Get analysis history",
    description="Retrieve paginated history of previous analyses.",
)
async def get_history(
    db: DbSessionDep,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
) -> HistoryResponse:
    """
    Get paginated analysis history.

    Results are ordered by creation date, most recent first.
    """
    try:
        # Get total count
        count_query = select(func.count()).select_from(Analysis)
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        # Get paginated items
        offset = (page - 1) * page_size
        query = (
            select(Analysis)
            .order_by(Analysis.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        result = await db.execute(query)
        analyses = result.scalars().all()

        # Convert to response items
        items = []
        for analysis in analyses:
            # Get best cipher from candidates
            best_cipher = None
            if analysis.plaintext_candidates:
                candidates = analysis.plaintext_candidates
                if candidates:
                    best_cipher = candidates[0].get("cipher_type")

            items.append(
                AnalysisHistoryItem(
                    id=analysis.id,
                    ciphertext_hash=analysis.ciphertext_hash,
                    ciphertext_preview=analysis.ciphertext[:100] + "..."
                    if len(analysis.ciphertext) > 100
                    else analysis.ciphertext,
                    best_cipher=best_cipher,
                    best_confidence=analysis.best_confidence,
                    created_at=analysis.created_at,
                )
            )

        return HistoryResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve history: {str(e)}",
        )


@router.get(
    "/{analysis_id}",
    response_model=AnalysisDetailResponse,
    responses={
        404: {"model": ErrorResponse, "description": "Analysis not found"},
        500: {"model": ErrorResponse, "description": "Failed to retrieve analysis"},
    },
    summary="Get specific analysis",
    description="Retrieve details of a specific analysis by ID.",
)
async def get_analysis(
    analysis_id: int,
    db: DbSessionDep,
) -> AnalysisDetailResponse:
    """Get a specific analysis by ID."""
    try:
        query = select(Analysis).where(Analysis.id == analysis_id)
        result = await db.execute(query)
        analysis = result.scalar_one_or_none()

        if analysis is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis with ID {analysis_id} not found",
            )

        return AnalysisDetailResponse.model_validate(analysis)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve analysis: {str(e)}",
        )
