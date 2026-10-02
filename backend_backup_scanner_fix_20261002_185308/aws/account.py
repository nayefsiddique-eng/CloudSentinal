from backend.services.aws.client import get_client

def get_account_id() -> str:
    sts = get_client("sts")
    identity = sts.get_caller_identity()
    return identity["Account"]
