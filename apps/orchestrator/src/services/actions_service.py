from typing import Dict, Any, List, Optional
import structlog
import httpx
import json
from datetime import datetime
from ..core.config import settings

logger = structlog.get_logger()

class ActionsService:
    """Service for managing incident response actions and integrations"""
    
    def __init__(self):
        self.jira_client = JiraIntegration()
        self.servicenow_client = ServiceNowIntegration()
        self.soar_client = SOARIntegration()
    
    async def create_incident_actions(self, incident_id: str, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create actionable tasks from incident recommendations"""
        actions = []
        
        try:
            for recommendation in recommendations:
                # Create action based on recommendation
                action = await self._create_action_from_recommendation(incident_id, recommendation)
                actions.append(action)
                
                # Create tasks in external systems
                if recommendation.get('create_jira_ticket', True):
                    jira_ticket = await self.jira_client.create_ticket(action)
                    action['jira_ticket'] = jira_ticket
                
                if recommendation.get('create_servicenow_task', False):
                    snow_task = await self.servicenow_client.create_task(action)
                    action['servicenow_task'] = snow_task
                
                # Trigger SOAR playbook if applicable
                if recommendation.get('trigger_playbook'):
                    playbook_result = await self.soar_client.trigger_playbook(
                        recommendation['trigger_playbook'], 
                        action
                    )
                    action['playbook_execution'] = playbook_result
            
            logger.info(f"Created {len(actions)} actions for incident {incident_id}")
            return actions
            
        except Exception as e:
            logger.error(f"Failed to create incident actions: {e}")
            raise
    
    async def _create_action_from_recommendation(self, incident_id: str, recommendation: Dict[str, Any]) -> Dict[str, Any]:
        """Convert recommendation to actionable task"""
        return {
            "id": f"action_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "incident_id": incident_id,
            "title": recommendation.get('action', 'Implement Security Recommendation'),
            "description": recommendation.get('description', ''),
            "priority": self._map_priority(recommendation.get('priority', 'medium')),
            "category": recommendation.get('category', 'security'),
            "timeline": recommendation.get('timeline', 'TBD'),
            "owner": recommendation.get('owner', 'Security Team'),
            "status": "open",
            "created_at": datetime.utcnow().isoformat(),
            "metadata": {
                "source": "incident_analysis",
                "recommendation_type": recommendation.get('type', 'remediation')
            }
        }
    
    def _map_priority(self, priority: str) -> str:
        """Map priority levels to standard format"""
        priority_map = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low'
        }
        return priority_map.get(priority.lower(), 'Medium')
    
    async def execute_playbook(self, playbook_name: str, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute SOAR playbook for incident response"""
        return await self.soar_client.trigger_playbook(playbook_name, incident_data)
    
    async def update_action_status(self, action_id: str, status: str, notes: str = "") -> bool:
        """Update action status and sync with external systems"""
        try:
            # Update internal status
            # TODO: Update in database
            
            # Sync with external systems
            # TODO: Update Jira ticket status
            # TODO: Update ServiceNow task status
            
            logger.info(f"Updated action {action_id} status to {status}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update action status: {e}")
            return False


class JiraIntegration:
    """Integration with Jira for ticket management"""
    
    def __init__(self):
        self.base_url = settings.JIRA_URL
        self.username = settings.JIRA_USERNAME
        self.api_token = settings.JIRA_API_TOKEN
        self.client = None
    
    async def create_ticket(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Create Jira ticket for action"""
        try:
            if not self.client:
                self.client = httpx.AsyncClient(
                    auth=(self.username, self.api_token),
                    timeout=30.0
                )
            
            ticket_data = {
                "fields": {
                    "project": {"key": "SEC"},  # Security project
                    "summary": action['title'],
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": action['description']
                                    }
                                ]
                            },
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": f"Incident ID: {action['incident_id']}"
                                    }
                                ]
                            },
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": f"Timeline: {action['timeline']}"
                                    }
                                ]
                            }
                        ]
                    },
                    "issuetype": {"name": "Task"},
                    "priority": {"name": action['priority']},
                    "assignee": {"name": action.get('owner', 'unassigned')},
                    "labels": [
                        "incident-response",
                        action['category'],
                        f"incident-{action['incident_id']}"
                    ]
                }
            }
            
            response = await self.client.post(
                f"{self.base_url}/rest/api/3/issue",
                json=ticket_data
            )
            
            if response.status_code == 201:
                ticket = response.json()
                logger.info(f"Created Jira ticket {ticket['key']} for action {action['id']}")
                return {
                    "ticket_id": ticket['key'],
                    "ticket_url": f"{self.base_url}/browse/{ticket['key']}",
                    "status": "created"
                }
            else:
                logger.error(f"Failed to create Jira ticket: {response.status_code} - {response.text}")
                return {"status": "failed", "error": response.text}
                
        except Exception as e:
            logger.error(f"Jira integration error: {e}")
            return {"status": "error", "error": str(e)}
    
    async def update_ticket_status(self, ticket_id: str, status: str) -> bool:
        """Update Jira ticket status"""
        try:
            # Map internal status to Jira transitions
            status_map = {
                "in_progress": "In Progress",
                "completed": "Done",
                "blocked": "Blocked"
            }
            
            jira_status = status_map.get(status, status)
            
            # Get available transitions
            response = await self.client.get(
                f"{self.base_url}/rest/api/3/issue/{ticket_id}/transitions"
            )
            
            if response.status_code == 200:
                transitions = response.json()['transitions']
                
                # Find matching transition
                for transition in transitions:
                    if transition['to']['name'] == jira_status:
                        # Execute transition
                        transition_response = await self.client.post(
                            f"{self.base_url}/rest/api/3/issue/{ticket_id}/transitions",
                            json={"transition": {"id": transition['id']}}
                        )
                        
                        return transition_response.status_code == 204
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to update Jira ticket status: {e}")
            return False


class ServiceNowIntegration:
    """Integration with ServiceNow for task management"""
    
    def __init__(self):
        self.base_url = settings.SERVICENOW_URL
        self.username = settings.SERVICENOW_USERNAME
        self.password = settings.SERVICENOW_PASSWORD
        self.client = None
    
    async def create_task(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Create ServiceNow task for action"""
        try:
            if not self.client:
                self.client = httpx.AsyncClient(
                    auth=(self.username, self.password),
                    timeout=30.0
                )
            
            task_data = {
                "short_description": action['title'],
                "description": f"{action['description']}\n\nIncident ID: {action['incident_id']}\nTimeline: {action['timeline']}",
                "priority": self._map_servicenow_priority(action['priority']),
                "category": "Security",
                "subcategory": "Incident Response",
                "assigned_to": action.get('owner', ''),
                "work_notes": f"Created from incident response analysis for incident {action['incident_id']}"
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/now/table/sc_task",
                json=task_data,
                headers={"Content-Type": "application/json", "Accept": "application/json"}
            )
            
            if response.status_code == 201:
                task = response.json()['result']
                logger.info(f"Created ServiceNow task {task['number']} for action {action['id']}")
                return {
                    "task_id": task['sys_id'],
                    "task_number": task['number'],
                    "task_url": f"{self.base_url}/nav_to.do?uri=sc_task.do?sys_id={task['sys_id']}",
                    "status": "created"
                }
            else:
                logger.error(f"Failed to create ServiceNow task: {response.status_code} - {response.text}")
                return {"status": "failed", "error": response.text}
                
        except Exception as e:
            logger.error(f"ServiceNow integration error: {e}")
            return {"status": "error", "error": str(e)}
    
    def _map_servicenow_priority(self, priority: str) -> str:
        """Map priority to ServiceNow values"""
        priority_map = {
            'Critical': '1',
            'High': '2', 
            'Medium': '3',
            'Low': '4'
        }
        return priority_map.get(priority, '3')


class SOARIntegration:
    """Integration with SOAR platforms for playbook execution"""
    
    def __init__(self):
        self.playbooks = self._load_playbooks()
    
    def _load_playbooks(self) -> Dict[str, Dict[str, Any]]:
        """Load available SOAR playbooks"""
        return {
            "malware_containment": {
                "name": "Malware Containment Playbook",
                "description": "Automated containment actions for malware incidents",
                "steps": [
                    "Isolate affected systems",
                    "Block malicious IPs/domains",
                    "Update AV signatures",
                    "Scan related systems"
                ]
            },
            "phishing_response": {
                "name": "Phishing Response Playbook", 
                "description": "Automated response to phishing incidents",
                "steps": [
                    "Block sender email",
                    "Remove emails from mailboxes",
                    "Reset user credentials",
                    "Update email filters"
                ]
            },
            "data_breach_response": {
                "name": "Data Breach Response Playbook",
                "description": "Coordinated response to data breach incidents",
                "steps": [
                    "Assess data exposure",
                    "Notify stakeholders",
                    "Preserve evidence",
                    "Initiate legal review"
                ]
            },
            "network_intrusion": {
                "name": "Network Intrusion Response",
                "description": "Response to network-based attacks",
                "steps": [
                    "Network segmentation",
                    "Traffic analysis",
                    "Credential rotation",
                    "System hardening"
                ]
            }
        }
    
    async def trigger_playbook(self, playbook_name: str, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger SOAR playbook execution"""
        try:
            if playbook_name not in self.playbooks:
                raise ValueError(f"Unknown playbook: {playbook_name}")
            
            playbook = self.playbooks[playbook_name]
            
            # Simulate playbook execution
            execution_result = {
                "playbook_id": f"exec_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                "playbook_name": playbook_name,
                "status": "running",
                "started_at": datetime.utcnow().isoformat(),
                "steps_completed": 0,
                "total_steps": len(playbook['steps']),
                "results": []
            }
            
            # Execute playbook steps
            for i, step in enumerate(playbook['steps']):
                step_result = await self._execute_playbook_step(step, incident_data)
                execution_result['results'].append(step_result)
                execution_result['steps_completed'] = i + 1
                
                logger.info(f"Executed playbook step: {step}")
            
            execution_result['status'] = 'completed'
            execution_result['completed_at'] = datetime.utcnow().isoformat()
            
            logger.info(f"Completed playbook execution: {playbook_name}")
            return execution_result
            
        except Exception as e:
            logger.error(f"Playbook execution failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "playbook_name": playbook_name
            }
    
    async def _execute_playbook_step(self, step: str, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute individual playbook step"""
        # Simulate step execution
        import asyncio
        await asyncio.sleep(0.5)  # Simulate processing time
        
        return {
            "step": step,
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat(),
            "details": f"Successfully executed: {step}"
        }
    
    async def get_playbook_status(self, execution_id: str) -> Dict[str, Any]:
        """Get playbook execution status"""
        # TODO: Implement status tracking
        return {
            "execution_id": execution_id,
            "status": "completed",
            "progress": 100
        }


# Global actions service instance
actions_service = ActionsService()

# Convenience functions
async def create_incident_actions(incident_id: str, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return await actions_service.create_incident_actions(incident_id, recommendations)

async def execute_playbook(playbook_name: str, incident_data: Dict[str, Any]) -> Dict[str, Any]:
    return await actions_service.execute_playbook(playbook_name, incident_data)

async def update_action_status(action_id: str, status: str, notes: str = "") -> bool:
    return await actions_service.update_action_status(action_id, status, notes)
