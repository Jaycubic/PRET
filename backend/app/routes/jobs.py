from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..adapters.registry import get_adapter
from ..db import get_db, Job, Result, User, Device
from ..deps import get_current_user, require_admin
from ..jobs import submit_job
from ..schemas import JobCreate, JobOut

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


@router.get("", response_model=list[JobOut])
def list_jobs(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Job).order_by(Job.id.desc()).limit(100).all()


@router.get("/{job_id}/results")
def job_results(job_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Result).filter(Result.job_id == job_id).all()


@router.post("", response_model=JobOut)
def create_job(body: JobCreate, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    device = db.get(Device, body.device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    adapter = get_adapter(body.adapter_id)
    if adapter is None:
        raise HTTPException(status_code=400, detail="Unknown adapter")

    op = next((o for o in adapter.list_operations() if o.id == body.operation_id), None)
    if op is None:
        raise HTTPException(status_code=400, detail="Unknown operation for this adapter")

    # This is the server-side half of 05-SECURITY-ARCHITECTURE.md §9: a
    # state-changing operation is REFUSED outright without explicit
    # confirm=true, regardless of what the UI did or didn't show.
    if not op.read_only and not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="This operation is state-changing and requires confirm=true.",
        )
    if not op.read_only and user.role != "admin":
        raise HTTPException(status_code=403, detail="State-changing operations require admin role")

    job = Job(
        device_id=device.id, adapter_id=body.adapter_id, operation_id=body.operation_id,
        is_state_changing=not op.read_only, confirmed=body.confirm,
        requested_by_user_id=user.id, params_json=body.params,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    submit_job(job.id)
    return job
