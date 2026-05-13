from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db.models import BountyProgram, Finding, ReconResult, Target
from core.db.session import SessionLocal


def seed_development_data(session: Session) -> None:
    existing_target = session.scalar(
        select(Target).where(Target.domain == "example.com")
    )
    if existing_target is not None:
        return

    target = Target(
        domain="example.com",
        scope_includes=["*.example.com"],
        platform="private",
        recon_depth=2,
    )
    program = BountyProgram(
        platform="private",
        program_handle="example-private",
        name="Example Private Program",
        scope=[{"asset": "*.example.com", "type": "domain"}],
        auto_recon_enabled=False,
    )
    recon_result = ReconResult(
        target=target,
        tool="subfinder",
        result_type="subdomain",
        data={"value": "api.example.com", "source": "seed"},
    )
    finding = Finding(
        target=target,
        type="exposure",
        title="Seed finding for dashboard development",
        description="Synthetic finding used to exercise dashboard tables.",
        url="https://api.example.com",
        severity="low",
        confidence="possible",
        auto_score=25,
        raw_evidence={"source": "seed"},
    )

    session.add_all([target, program, recon_result, finding])
    session.commit()


def main() -> None:
    with SessionLocal() as session:
        seed_development_data(session)


if __name__ == "__main__":
    main()
