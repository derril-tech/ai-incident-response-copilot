from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from ..core.messaging import get_nats
from ..workers.collector import CollectorWorker
from ..workers.timeline import TimelineWorker
from ..workers.forensic import ForensicWorker
from ..workers.report import ReportWorker
from ..workers.export import ExportWorker
import json

router = APIRouter()

@router.post("/incidents/{incident_id}/collect")
async def trigger_collection(incident_id: str, nats_conn=Depends(get_nats)):
    """Trigger artifact collection for an incident"""
    try:
        message = {"incident_id": incident_id, "action": "collect"}
        await nats_conn.publish("incident.collect", json.dumps(message).encode())
        return {"status": "collection_triggered", "incident_id": incident_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/incidents/{incident_id}/timeline")
async def trigger_timeline(incident_id: str, nats_conn=Depends(get_nats)):
    """Trigger timeline correlation for an incident"""
    try:
        message = {"incident_id": incident_id, "action": "correlate"}
        await nats_conn.publish("timeline.build", json.dumps(message).encode())
        return {"status": "timeline_triggered", "incident_id": incident_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/incidents/{incident_id}/forensic")
async def trigger_forensic(incident_id: str, nats_conn=Depends(get_nats)):
    """Trigger forensic analysis for an incident"""
    try:
        message = {"incident_id": incident_id, "action": "analyze"}
        await nats_conn.publish("forensic.run", json.dumps(message).encode())
        return {"status": "forensic_triggered", "incident_id": incident_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/incidents/{incident_id}/report")
async def trigger_report(incident_id: str, nats_conn=Depends(get_nats)):
    """Trigger report generation for an incident"""
    try:
        message = {"incident_id": incident_id, "action": "generate"}
        await nats_conn.publish("report.draft", json.dumps(message).encode())
        return {"status": "report_triggered", "incident_id": incident_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reports/{report_id}/export")
async def trigger_export(report_id: str, export_format: str = "pdf", nats_conn=Depends(get_nats)):
    """Trigger report export"""
    try:
        message = {"report_id": report_id, "format": export_format, "action": "export"}
        await nats_conn.publish("export.make", json.dumps(message).encode())
        return {"status": "export_triggered", "report_id": report_id, "format": export_format}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status")
async def get_status():
    """Get orchestrator status"""
    return {
        "status": "running",
        "workers": {
            "collector": "active",
            "timeline": "active", 
            "forensic": "active",
            "report": "active",
            "export": "active"
        }
    }
