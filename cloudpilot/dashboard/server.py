"""FastAPI server for the CloudPilot Dashboard.
Browser-based chat interface with inline Mermaid diagrams, IaC generation,
finding cards, and one-click remediation."""
import asyncio
import logging
import os
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from cloudpilot.core import SkillRegistry
from cloudpilot.aws_client import get_regions, get_account_id
from cloudpilot.dashboard.jobs import JobStore, ScanJobStatus
from cloudpilot.dashboard.remediation import has_remediation, execute_remediation
from cloudpilot.dashboard.security import (
    APIKeyMiddleware, RateLimiter, RateLimitMiddleware,
    SecurityHeadersMiddleware, AuditLogger,
    sanitize_chat_message, validate_findings_payload,
    MAX_CHAT_MESSAGE_LENGTH, MAX_FINDINGS_COUNT,
)
from cloudpilot.dashboard.guardrails import apply_guardrails, sanitize_output
import cloudpilot.skills  # auto-register skills

logger = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"


# --- Request/Response Models ---
class ScanRequest(BaseModel):
    regions: Optional[List[str]] = None
    profile: Optional[str] = None

class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None

class RemediateRequest(BaseModel):
    finding: dict
    profile: Optional[str] = None

class DiagramRequest(BaseModel):
    view_type: str = "default"
    resources: Optional[List[dict]] = None

class IaCRequest(BaseModel):
    format: str = "cloudformation"
    scope: str = "all"
    resources: Optional[List[dict]] = None

class DiscoverRequest(BaseModel):
    regions: Optional[List[str]] = None


def create_app(profile: Optional[str] = None, api_key: Optional[str] = None) -> FastAPI:
    app = FastAPI(title="CloudPilot Dashboard", version="0.1.0")
    job_store = JobStore()
    app.state.profile = profile
    app.state.job_store = job_store

    # Lazy-init agent (created on first chat request)
    app.state.agent = None

    def _get_agent():
        if app.state.agent is None:
            from cloudpilot.agent.loop import CloudPilotAgent
            app.state.agent = CloudPilotAgent(profile=app.state.profile)
        return app.state.agent

    # --- Security ---
    effective_api_key = api_key or os.environ.get("CLOUDPILOT_API_KEY")
    audit = AuditLogger()

    allowed_origins = os.environ.get(
        "CLOUDPILOT_CORS_ORIGINS",
        "http://127.0.0.1:8080,http://localhost:8080"
    ).split(",")
    app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in allowed_origins],
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-API-Key"])
    app.add_middleware(SecurityHeadersMiddleware)
    rate_limiter = RateLimiter(
        requests_per_minute=int(os.environ.get("CLOUDPILOT_RATE_LIMIT", "60")),
        burst=int(os.environ.get("CLOUDPILOT_RATE_BURST", "15")),
    )
    app.add_middleware(RateLimitMiddleware, limiter=rate_limiter)
    app.add_middleware(APIKeyMiddleware, api_key=effective_api_key)

    # --- Static files ---
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # --- Health ---
    @app.get("/api/health")
    async def health():
        return {"status": "healthy", "version": "0.1.0", "skills": len(SkillRegistry.all())}

    @app.get("/", response_class=HTMLResponse)
    async def root():
        index = STATIC_DIR / "index.html"
        if index.exists():
            return HTMLResponse(content=index.read_text())
        return HTMLResponse(content="<h1>CloudPilot</h1><p>Dashboard loading...</p>")

    # --- Skills ---
    @app.get("/api/skills")
    async def list_skills():
        return [{"name": s.name, "description": s.description, "version": s.version}
                for s in SkillRegistry.all().values()]

    # --- Chat (Agent Loop) ---
    @app.post("/api/chat")
    async def chat(req: ChatRequest, request: Request):
        client_ip = request.client.host if request.client else "unknown"
        try:
            clean_message = sanitize_chat_message(req.message)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Guardrails check
        guard_result = apply_guardrails(clean_message)
        if not guard_result.allowed:
            audit.log_chat(client_ip, len(clean_message))
            return {"response": guard_result.filtered_message}

        audit.log_chat(client_ip, len(clean_message))
        try:
            agent = _get_agent()
            logger.info(f"Chat: profile={agent.profile}, bedrock_region={agent.bedrock.meta.region_name}")
            if req.session_id:
                agent.session_id = req.session_id
            response = await asyncio.to_thread(agent.chat, clean_message)
            logger.info(f"Chat response length: {len(response)}, first 100: {response[:100]}")
            response = sanitize_output(response)
            return {"response": response}
        except Exception as e:
            logger.error(f"Chat error: {type(e).__name__}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Something went wrong processing your request.")

    # --- Scan ---
    @app.post("/api/scan/{skill_name}")
    async def scan_skill(skill_name: str, req: ScanRequest = ScanRequest()):
        skill = SkillRegistry.get(skill_name)
        if not skill:
            valid = ", ".join(SkillRegistry.names())
            raise HTTPException(status_code=400, detail=f"Unknown skill: {skill_name}. Valid: [{valid}]")
        p = req.profile or app.state.profile
        regions = req.regions or get_regions(profile=p)
        job = job_store.create([skill_name])

        async def _run():
            job_store.update(job.id, status=ScanJobStatus.RUNNING)
            try:
                result = await asyncio.to_thread(skill.scan, regions, p)
                job_store.update(job.id, status=ScanJobStatus.COMPLETED, results=[result])
            except Exception as e:
                job_store.update(job.id, status=ScanJobStatus.FAILED, error=str(e))
        asyncio.create_task(_run())
        return {"job_id": job.id, "status": job.status.value}

    @app.post("/api/scan-all")
    async def scan_all(req: ScanRequest = ScanRequest()):
        skills = list(SkillRegistry.all().values())
        p = req.profile or app.state.profile
        regions = req.regions or get_regions(profile=p)
        job = job_store.create([s.name for s in skills])

        async def _run():
            job_store.update(job.id, status=ScanJobStatus.RUNNING)
            try:
                import concurrent.futures
                results = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(skills)) as pool:
                    futures = {pool.submit(s.scan, regions, p): s.name for s in skills}
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            results.append(future.result())
                        except Exception as e:
                            from cloudpilot.core import SkillResult
                            results.append(SkillResult(skill_name=futures[future], errors=[str(e)]))
                job_store.update(job.id, status=ScanJobStatus.COMPLETED, results=results)
            except Exception as e:
                job_store.update(job.id, status=ScanJobStatus.FAILED, error=str(e))
        asyncio.create_task(_run())
        return {"job_id": job.id, "status": job.status.value}

    # --- Discover ---
    @app.post("/api/discover")
    async def discover(req: DiscoverRequest = DiscoverRequest()):
        p = app.state.profile
        regions = req.regions or get_regions(profile=p)
        from cloudpilot.skills.arch_mapper import ArchMapper
        mapper = ArchMapper()
        result = await asyncio.to_thread(mapper.discover, regions, p)
        # Store in agent for follow-up
        agent = _get_agent()
        agent.resources_store.clear()
        agent.resources_store.extend(result.get("resources", []))
        return result

    # --- Diagram ---
    @app.post("/api/diagram")
    async def diagram(req: DiagramRequest = DiagramRequest()):
        agent = _get_agent()
        resources = req.resources or agent.resources_store
        if not resources:
            p = app.state.profile
            regions = get_regions(profile=p)
            from cloudpilot.skills.arch_mapper import ArchMapper
            mapper = ArchMapper()
            disc = await asyncio.to_thread(mapper.discover, regions, p)
            resources = disc.get("resources", [])
            agent.resources_store.clear()
            agent.resources_store.extend(resources)
        from cloudpilot.skills.arch_mapper import ArchMapper
        mapper = ArchMapper()
        mermaid = mapper._generate_mermaid(resources)
        return {"diagram": mermaid, "view_type": req.view_type, "resource_count": len(resources)}

    # --- IaC ---
    @app.post("/api/iac")
    async def iac(req: IaCRequest):
        agent = _get_agent()
        resources = req.resources or agent.resources_store
        if not resources:
            raise HTTPException(status_code=400, detail="No resources. Run /api/discover first.")
        from cloudpilot.skills.iac_generator import IaCGenerator
        gen = IaCGenerator()
        result = await asyncio.to_thread(gen.generate, resources, req.format, req.scope)
        return result

    # --- Remediate ---
    @app.post("/api/remediate")
    async def remediate(req: RemediateRequest, request: Request):
        p = req.profile or app.state.profile
        if not has_remediation(req.finding):
            raise HTTPException(status_code=400, detail="No remediation available for this finding type")
        client_ip = request.client.host if request.client else "unknown"
        result = await asyncio.to_thread(execute_remediation, req.finding, p)
        audit.log_remediation(
            action=result.action, resource_id=result.finding_id,
            region=req.finding.get("region", "unknown"),
            skill=req.finding.get("skill", "unknown"),
            success=result.success, message=result.message, client_ip=client_ip,
        )
        return {"success": result.success, "action": result.action,
                "message": result.message, "timestamp": result.timestamp}

    # --- Jobs ---
    @app.get("/api/jobs/{job_id}")
    async def get_job(job_id: str):
        job = job_store.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        return {"job_id": job.id, "status": job.status.value,
                "skill_names": job.skill_names, "created_at": job.created_at,
                "completed_at": job.completed_at, "error": job.error}

    @app.get("/api/jobs/{job_id}/results")
    async def get_job_results(job_id: str):
        job = job_store.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        if job.status != ScanJobStatus.COMPLETED:
            raise HTTPException(status_code=400, detail=f"Job not completed. Status: {job.status.value}")
        if job.results:
            return [{"skill_name": r.skill_name, "findings": [f.to_dict() for f in r.findings],
                      "duration_seconds": r.duration_seconds, "total_impact": r.total_impact,
                      "critical_count": r.critical_count} for r in job.results]
        return []

    return app
