from crud import get_alert_rules, create_incident
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class AlertEvaluator:
    @staticmethod
    def evaluate_metric(value: float, operator: str, threshold: float) -> bool:
        """Evaluate if a metric triggers an alert based on the rule"""
        operators = {
            '>': lambda v, t: v > t,
            '>=': lambda v, t: v >= t,
            '<': lambda v, t: v < t,
            '<=': lambda v, t: v <= t,
            '==': lambda v, t: v == t,
            '!=': lambda v, t: v != t
        }
        
        if operator not in operators:
            logger.warning(f"Unknown operator: {operator}")
            return False
            
        try:
            return operators[operator](value, threshold)
        except Exception as e:
            logger.error(f"Error evaluating metric: {e}")
            return False
    
    @staticmethod
    async def check_agent_data_for_alerts(agent_data: dict, agent_data_id: int) -> List[Dict[str, Any]]:
        """Check incoming agent data against all active alert rules"""
        try:
            active_rules = await get_alert_rules(active_only=True)
            triggered_incidents = []
            
            for rule in active_rules:
                rule_dict = dict(rule)
                metric_value = None
                
                # Map metric names to agent data fields
                metric_mapping = {
                    'cpu_usage': agent_data.get('cpu_usage'),
                    'memory_usage': agent_data.get('memory_usage'),
                    'disk_usage': agent_data.get('disk_usage'),
                    'bytes_sent': agent_data.get('network_activity', {}).get('bytes_sent'),
                    'bytes_received': agent_data.get('network_activity', {}).get('bytes_received')
                }
                
                metric_value = metric_mapping.get(rule_dict['metric'])
                
                if metric_value is not None:
                    if AlertEvaluator.evaluate_metric(metric_value, rule_dict['comparison_operator'], rule_dict['threshold_value']):
                        # Create incident using dictionary for database insertion
                        incident_data = {
                            "alert_rule_id": rule_dict['id'],
                            "agent_data_id": agent_data_id,
                            "incident_type": f"{rule_dict['metric']}_alert",
                            "message": f"{rule_dict['metric'].replace('_', ' ').title()} {rule_dict['comparison_operator']} {rule_dict['threshold_value']} (current: {metric_value:.2f})",
                            "severity": rule_dict['severity'],
                            "metadata": {
                                "hostname": agent_data.get('hostname', 'unknown'),
                                "metric_value": metric_value,
                                "threshold": rule_dict['threshold_value'],
                                "operator": rule_dict['comparison_operator'],
                                "metric": rule_dict['metric'],
                                "description": rule_dict.get('description', '')
                            }
                        }
                        
                        incident = await create_incident(incident_data)
                        if incident:
                            incident_dict = dict(incident)
                            triggered_incidents.append({
                                "incident": incident_dict,
                                "rule": rule_dict
                            })
                            
                            logger.info(f"Alert triggered: {rule_dict['metric']} = {metric_value:.2f} {rule_dict['comparison_operator']} {rule_dict['threshold_value']}")
            
            return triggered_incidents
            
        except Exception as e:
            logger.error(f"Error checking alerts: {e}")
            return []
    
    @staticmethod
    async def evaluate_suspicious_processes(processes: List[Dict], agent_data_id: int, hostname: str = "unknown") -> List[Dict[str, Any]]:
        """Evaluate processes for suspicious activity"""
        suspicious_keywords = ['miner', 'backdoor', 'malware', 'ransomware', 'keylogger', 'rootkit', 'trojan']
        triggered_incidents = []
        
        try:
            for process in processes:
                process_name = process.get('name', '').lower()
                for keyword in suspicious_keywords:
                    if keyword in process_name:
                        # Create security incident using dictionary for database insertion
                        incident_data = {
                            "alert_rule_id": None,  # Explicitly set to None for security incidents
                            "agent_data_id": agent_data_id,
                            "incident_type": "suspicious_process",
                            "message": f"Suspicious process detected: {process.get('name')}",
                            "severity": "critical",
                            "metadata": {
                                "hostname": hostname,
                                "process_name": process.get('name'),
                                "process_pid": process.get('pid'),
                                "cpu_usage": process.get('cpu'),
                                "memory_usage": process.get('memory'),
                                "suspicious_keyword": keyword
                            }
                        }
                        
                        incident = await create_incident(incident_data)
                        if incident:
                            incident_dict = dict(incident)
                            triggered_incidents.append({
                                "incident": incident_dict,
                                "process": process
                            })
                            
                            logger.warning(f"Suspicious process detected: {process.get('name')} (PID: {process.get('pid')})")
                        break
            
            return triggered_incidents
            
        except Exception as e:
            logger.error(f"Error evaluating suspicious processes: {e}")
            return []
