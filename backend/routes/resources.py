from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Resource
from backend.schemas import ResourceResponse


router = APIRouter(
    prefix="/platform/resources",
    tags=["Platform - Resources"]
)


@router.get("/", response_model=list[ResourceResponse])
def get_resources(db: Session = Depends(get_db)):
    resources = (
        db.query(Resource)
        .order_by(Resource.created_at.desc())
        .all()
    )

    return resources