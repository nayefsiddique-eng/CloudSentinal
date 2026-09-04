from sqlalchemy.orm import Session

from backend.database.models import Resource


def sync_resources(findings: list, db: Session):
    unique_resources = {}

    for finding in findings:
        resource_id = finding.get("resource_id")
        resource_type = finding.get("resource_type")

        if not resource_id or not resource_type:
            continue

        unique_resources[resource_id] = {
            "resource_id": resource_id,
            "resource_type": resource_type,
            "resource_name": resource_id,
            "region": None
        }

    for resource_data in unique_resources.values():

        existing_resource = (
            db.query(Resource)
            .filter(Resource.resource_id == resource_data["resource_id"])
            .first()
        )

        if not existing_resource:
            new_resource = Resource(**resource_data)
            db.add(new_resource)

    db.commit()