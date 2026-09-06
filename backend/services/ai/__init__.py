"""
Masooma's module -- AI & Remediation Lead.

Finding (Nayef) -> Risk Engine -> AI Analysis Engine -> Remediation Planner
-> Safety Gate -> Executor (+ Backup/Rollback) -> Verification -> Audit Log

Every function here takes/returns plain dicts shaped like Nayef's
`Finding` (backend/models.py) so this module has zero coupling to how
Sireen's DB or frontend eventually store things.
"""
