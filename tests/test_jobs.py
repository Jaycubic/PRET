import time
import pytest
from app.db import Device, Job, Result, AuditLog
from app.jobs import submit_job


def test_job_runner_blocked_out_of_scope(db, authorized_network):
    # Device out of scope (172.16.10.5 not in 192.168.1.0/24)
    dev = Device(
        ip_or_hostname="172.16.10.5",
        resolved_ip="172.16.10.5",
        port=9100,
        status="unknown",
    )
    db.add(dev)
    db.commit()
    db.refresh(dev)

    job = Job(
        device_id=dev.id,
        adapter_id="pjl",
        operation_id="pjl_identify",
        status="queued",
        is_state_changing=False,
        confirmed=False,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Run the job
    from app.jobs import _run_job
    _run_job(job.id, db=db)

    db.refresh(job)
    # The job must be marked as error/blocked, not running or succeeded
    assert job.status in ["error", "blocked"]

    # Verify result row was recorded
    result = db.query(Result).filter(Result.job_id == job.id).first()
    assert result is not None
    assert "not in any configured authorized network" in result.error_detail


def test_job_runner_unknown_adapter_failure(db, authorized_network):
    dev = Device(
        ip_or_hostname="192.168.1.50",
        resolved_ip="192.168.1.50",
        port=9100,
        status="unknown",
    )
    db.add(dev)
    db.commit()
    db.refresh(dev)

    job = Job(
        device_id=dev.id,
        adapter_id="non_existent_protocol",
        operation_id="fake_op",
        status="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    from app.jobs import _run_job
    _run_job(job.id, db=db)


    db.refresh(job)
    assert job.status == "error"
    result = db.query(Result).filter(Result.job_id == job.id).first()
    assert result is not None
    assert "Unknown adapter" in result.error_detail
