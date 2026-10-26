from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db, AuditLog, User
from ..deps import get_current_user

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit(limit: int = 50, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    return db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
