from sqlalchemy.orm import Session
from backend.database.models import Resource


def sync_resources(resources_or_findings: list, db: Session):
    """Persist the real AWS inventory, not just resources that produced findings."""
    for item in resources_or_findings:
        resource_id = item.get("resource_id")
        resource_type = item.get("resource_type")
        if not resource_id or not resource_type:
            continue
        existing = db.query(Resource).filter(Resource.resource_id == resource_id).first()
        if existing:
            existing.resource_type = resource_type
            existing.resource_name = item.get("resource_name") or existing.resource_name or resource_id
            existing.region = item.get("region")
            continue
        db.add(Resource(
            resource_id=resource_id,
            resource_type=resource_type,
            resource_name=item.get("resource_name") or resource_id,
            region=item.get("region"),
        ))
    db.commit()
