from dataclasses import asdict

from fastapi import APIRouter, Depends

from ..adapters.registry import ADAPTERS
from ..db import User
from ..deps import get_current_user

router = APIRouter(prefix="/api/adapters", tags=["adapters"])


@router.get("")
def list_adapters(user: User = Depends(get_current_user)):
    # This is the ENTIRE driver of the frontend's operation buttons — see
    # 11-FRONTEND-IMPLEMENTATION.md "pure abstraction over the operation
    # catalog". Adding a new adapter here makes new buttons appear with
    # zero frontend changes.
    out = []
    for a in ADAPTERS.values():
        dep = a.dependency_status()
        out.append({
            "id": a.id,
            "display_name": a.display_name,
            "available": dep["available"],
            "dependency_detail": dep["detail"],
            "operations": [asdict(o) for o in a.list_operations()],
        })
    return out
