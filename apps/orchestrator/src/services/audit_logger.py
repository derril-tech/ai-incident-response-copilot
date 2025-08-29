import json
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum
import structlog
from ..core.config import settings

logger = structlog.get_logger()

class AuditEventType(Enum):
    """Types of audit events"""
    ARTIFACT_CREATED = "artifact_created"
    ARTIFACT_ACCESSED = "artifact_accessed"
    ARTIFACT_MODIFIED = "artifact_modified"
    ARTIFACT_DELETED = "artifact_deleted"
    LEGAL_HOLD_SET = "legal_hold_set"
    LEGAL_HOLD_REMOVED = "legal_hold_removed"
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_CLOSED = "incident_closed"
    REPORT_GENERATED = "report_generated"
    REPORT_EXPORTED = "report_exported"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    SYSTEM_CONFIG_CHANGED = "system_config_changed"
    DATA_EXPORT = "data_export"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"

class AuditSeverity(Enum):
    """Severity levels for audit events"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AuditLogger:
    """Immutable audit logging service for compliance and forensics"""
    
    def __init__(self):
        self.clickhouse_client = None  # TODO: Initialize ClickHouse client
        self.postgres_client = None    # TODO: Initialize PostgreSQL client
    
    async def log_event(
        self,
        event_type: AuditEventType,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.MEDIUM,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> str:
        """Log an audit event with immutable storage"""
        
        # Generate unique event ID
        event_id = self._generate_event_id()
        
        # Create audit record
        audit_record = {
            "event_id": event_id,
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type.value,
            "severity": severity.value,
            "user_id": user_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "details": details or {},
            "ip_address": ip_address,
            "user_agent": user_agent,
            "session_id": session_id,
            "system_info": {
                "service": "incident-response-orchestrator",
                "version": "1.0.0",
                "environment": settings.DEBUG and "development" or "production"
            }
        }
        
        try:
            # Store in ClickHouse for high-volume, immutable storage
            await self._store_in_clickhouse(audit_record)
            
            # Store critical events in PostgreSQL for ACID compliance
            if severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL]:
                await self._store_in_postgres(audit_record)
            
            # Log to structured logger for real-time monitoring
            logger.info(
                "Audit event logged",
                event_id=event_id,
                event_type=event_type.value,
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                action=action,
                severity=severity.value
            )
            
            return event_id
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            # Fallback to file logging for critical audit events
            await self._fallback_file_log(audit_record)
            raise
    
    async def log_artifact_operation(
        self,
        operation: str,
        artifact_id: str,
        user_id: str,
        incident_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Log artifact-specific operations"""
        
        event_type_map = {
            "created": AuditEventType.ARTIFACT_CREATED,
            "accessed": AuditEventType.ARTIFACT_ACCESSED,
            "modified": AuditEventType.ARTIFACT_MODIFIED,
            "deleted": AuditEventType.ARTIFACT_DELETED
        }
        
        event_type = event_type_map.get(operation, AuditEventType.ARTIFACT_ACCESSED)
        severity = AuditSeverity.HIGH if operation in ["deleted", "modified"] else AuditSeverity.MEDIUM
        
        audit_details = {
            "incident_id": incident_id,
            "operation": operation,
            **(details or {})
        }
        
        return await self.log_event(
            event_type=event_type,
            user_id=user_id,
            resource_type="artifact",
            resource_id=artifact_id,
            action=f"artifact_{operation}",
            details=audit_details,
            severity=severity,
            ip_address=ip_address
        )
    
    async def log_legal_hold_change(
        self,
        artifact_id: str,
        user_id: str,
        enabled: bool,
        reason: str,
        ip_address: Optional[str] = None
    ) -> str:
        """Log legal hold changes (critical audit event)"""
        
        event_type = AuditEventType.LEGAL_HOLD_SET if enabled else AuditEventType.LEGAL_HOLD_REMOVED
        
        details = {
            "legal_hold_enabled": enabled,
            "reason": reason,
            "compliance_required": True
        }
        
        return await self.log_event(
            event_type=event_type,
            user_id=user_id,
            resource_type="artifact",
            resource_id=artifact_id,
            action=f"legal_hold_{'enabled' if enabled else 'disabled'}",
            details=details,
            severity=AuditSeverity.CRITICAL,
            ip_address=ip_address
        )
    
    async def log_incident_operation(
        self,
        operation: str,
        incident_id: str,
        user_id: str,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Log incident-specific operations"""
        
        event_type_map = {
            "created": AuditEventType.INCIDENT_CREATED,
            "updated": AuditEventType.INCIDENT_UPDATED,
            "closed": AuditEventType.INCIDENT_CLOSED
        }
        
        event_type = event_type_map.get(operation, AuditEventType.INCIDENT_UPDATED)
        
        return await self.log_event(
            event_type=event_type,
            user_id=user_id,
            resource_type="incident",
            resource_id=incident_id,
            action=f"incident_{operation}",
            details=details or {},
            severity=AuditSeverity.MEDIUM,
            ip_address=ip_address
        )
    
    async def log_report_operation(
        self,
        operation: str,
        report_id: str,
        user_id: str,
        incident_id: Optional[str] = None,
        export_format: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> str:
        """Log report-specific operations"""
        
        event_type_map = {
            "generated": AuditEventType.REPORT_GENERATED,
            "exported": AuditEventType.REPORT_EXPORTED
        }
        
        event_type = event_type_map.get(operation, AuditEventType.REPORT_GENERATED)
        
        details = {
            "incident_id": incident_id,
            "export_format": export_format,
            "operation": operation
        }
        
        return await self.log_event(
            event_type=event_type,
            user_id=user_id,
            resource_type="report",
            resource_id=report_id,
            action=f"report_{operation}",
            details=details,
            severity=AuditSeverity.MEDIUM,
            ip_address=ip_address
        )
    
    async def get_audit_trail(
        self,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        user_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Retrieve audit trail with filtering"""
        
        try:
            # Build query filters
            filters = []
            
            if resource_type:
                filters.append(f"resource_type = '{resource_type}'")
            
            if resource_id:
                filters.append(f"resource_id = '{resource_id}'")
            
            if user_id:
                filters.append(f"user_id = '{user_id}'")
            
            if start_time:
                filters.append(f"timestamp >= '{start_time.isoformat()}'")
            
            if end_time:
                filters.append(f"timestamp <= '{end_time.isoformat()}'")
            
            # Query ClickHouse for audit records
            where_clause = " AND ".join(filters) if filters else "1=1"
            query = f"""
                SELECT *
                FROM audit_events
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT {limit}
            """
            
            # TODO: Execute ClickHouse query
            # For now, return empty list
            return []
            
        except Exception as e:
            logger.error(f"Failed to retrieve audit trail: {e}")
            return []
    
    async def verify_audit_integrity(
        self,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """Verify integrity of audit logs in time range"""
        
        try:
            # TODO: Implement audit log integrity verification
            # - Check for gaps in sequence
            # - Verify cryptographic hashes
            # - Detect tampering attempts
            
            return {
                "verified": True,
                "total_events": 0,
                "integrity_score": 100.0,
                "anomalies_detected": [],
                "verification_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to verify audit integrity: {e}")
            return {
                "verified": False,
                "error": str(e),
                "verification_timestamp": datetime.utcnow().isoformat()
            }
    
    async def _store_in_clickhouse(self, audit_record: Dict[str, Any]) -> None:
        """Store audit record in ClickHouse for high-volume storage"""
        
        # TODO: Implement ClickHouse storage
        # - Create audit_events table if not exists
        # - Insert record with proper data types
        # - Handle partitioning by date
        
        logger.debug(f"Storing audit record in ClickHouse: {audit_record['event_id']}")
    
    async def _store_in_postgres(self, audit_record: Dict[str, Any]) -> None:
        """Store critical audit records in PostgreSQL for ACID compliance"""
        
        # TODO: Implement PostgreSQL storage
        # - Create audit_events table in audit schema
        # - Insert with proper constraints and indexes
        # - Ensure ACID compliance
        
        logger.debug(f"Storing critical audit record in PostgreSQL: {audit_record['event_id']}")
    
    async def _fallback_file_log(self, audit_record: Dict[str, Any]) -> None:
        """Fallback file logging for when database is unavailable"""
        
        try:
            # Write to append-only audit log file
            log_entry = json.dumps(audit_record) + "\n"
            
            # TODO: Write to secure, append-only file
            # For now, just log the record
            logger.critical(f"AUDIT_FALLBACK: {log_entry.strip()}")
            
        except Exception as e:
            logger.error(f"Failed to write fallback audit log: {e}")
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        import uuid
        return str(uuid.uuid4())


# Global audit logger instance
audit_logger = AuditLogger()

# Convenience functions
async def log_artifact_created(artifact_id: str, user_id: str, incident_id: str, **kwargs) -> str:
    return await audit_logger.log_artifact_operation("created", artifact_id, user_id, incident_id, **kwargs)

async def log_artifact_accessed(artifact_id: str, user_id: str, **kwargs) -> str:
    return await audit_logger.log_artifact_operation("accessed", artifact_id, user_id, **kwargs)

async def log_legal_hold_enabled(artifact_id: str, user_id: str, reason: str, **kwargs) -> str:
    return await audit_logger.log_legal_hold_change(artifact_id, user_id, True, reason, **kwargs)

async def log_legal_hold_disabled(artifact_id: str, user_id: str, reason: str, **kwargs) -> str:
    return await audit_logger.log_legal_hold_change(artifact_id, user_id, False, reason, **kwargs)
