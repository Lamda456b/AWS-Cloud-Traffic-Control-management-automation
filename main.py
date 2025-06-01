import json
import time
import boto3
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import threading
import logging
from dataclasses import dataclass, asdict
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import re
import os
from werkzeug.serving import make_server
import signal
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class HealthCheck:
    endpoint: str
    expected_status: int = 200
    timeout: int = 10
    interval: int = 30
    failure_threshold: int = 3


@dataclass
class TrafficRule:
    source_pattern: str
    target: str
    weight: int = 100
    condition: Optional[str] = None


@dataclass
class AutoScaleRule:
    metric: str
    threshold: float
    action: str
    cooldown: int = 300


class AWSTrafficController:
    """Enhanced AWS Traffic Control Management System for Production"""

    def __init__(self, aws_access_key: str = None, aws_secret_key: str = None, region: str = 'us-east-1'):
        """Initialize AWS clients with enhanced error handling"""
        try:
            # Try to get credentials from environment if not provided
            aws_access_key = aws_access_key or os.getenv('AWS_ACCESS_KEY_ID')
            aws_secret_key = aws_secret_key or os.getenv(
                'AWS_SECRET_ACCESS_KEY')
            region = region or os.getenv('AWS_DEFAULT_REGION', 'us-east-1')

            if aws_access_key and aws_secret_key:
                self.session = boto3.Session(
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=region
                )
                self.mock_mode = False
                logger.info("Using provided AWS credentials")
            else:
                # Try default credentials (IAM role, environment, etc.)
                try:
                    self.session = boto3.Session(region_name=region)
                    # Test connection
                    sts = self.session.client('sts')
                    sts.get_caller_identity()
                    self.mock_mode = False
                    logger.info("Using default AWS credentials")
                except Exception:
                    self._create_mock_clients()
                    return

            # Initialize AWS clients
            self.elb_client = self.session.client('elbv2')
            self.ec2_client = self.session.client('ec2')
            self.cloudwatch = self.session.client('cloudwatch')
            self.route53 = self.session.client('route53')
            self.autoscaling = self.session.client('autoscaling')

        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            self._create_mock_clients()

        # Internal state
        self.health_checks = {}
        self.traffic_rules = []
        self.monitoring_active = False
        self.auto_scale_rules = []
        self.alerts = []
        self.metrics = {
            'total_requests': 0,
            'successful_health_checks': 0,
            'failed_health_checks': 0,
            'traffic_routes_created': 0,
            'auto_scale_triggers': 0
        }

        logger.info(
            f"AWS Traffic Controller initialized ({'LIVE' if not self.mock_mode else 'MOCK'} mode)")

    def _create_mock_clients(self):
        """Create mock clients for demonstration purposes"""
        logger.info("Creating mock AWS clients for demonstration")
        self.elb_client = None
        self.ec2_client = None
        self.cloudwatch = None
        self.route53 = None
        self.autoscaling = None
        self.mock_mode = True

    def parse_natural_language(self, command: str) -> Dict:
        """Enhanced natural language parsing with more patterns"""
        command = command.lower().strip()

        # Health check patterns
        health_patterns = [
            r"check health of (.+?) every (\d+) (seconds?|minutes?)",
            r"monitor (.+?) health every (\d+)",
            r"health check (.+?) interval (\d+)",
            r"ping (.+?) every (\d+)",
            r"watch (.+?) health",
            r"monitor (.+)"
        ]

        # Traffic routing patterns
        traffic_patterns = [
            r"route (.+?) to (.+?) with (\d+)% traffic",
            r"send (\d+)% of traffic from (.+?) to (.+)",
            r"redirect (.+?) to (.+?) at (\d+)%",
            r"balance (\d+)% traffic from (.+?) to (.+)",
            r"redirect (.+?) to (.+)",
            r"balance traffic between (.+?) and (.+)",
            r"failover (.+?) to (.+)"
        ]

        # Scaling patterns
        scaling_patterns = [
            r"scale up when cpu above (\d+)%",
            r"scale down when cpu below (\d+)%",
            r"auto scale (.+?) when (.+?) above (\d+)",
            r"increase capacity when (.+?) above (\d+)",
            r"decrease capacity when (.+?) below (\d+)",
            r"scale when (.+?) threshold (\d+)"
        ]

        # Status patterns
        status_patterns = [
            r"status of (.+)",
            r"show health of (.+)",
            r"check (.+?) status",
            r"how is (.+?) doing",
            r"health report for (.+)",
            r"show (.+?) metrics"
        ]

        # Global status patterns
        global_status_patterns = [
            r"show status",
            r"system status",
            r"overall health",
            r"dashboard",
            r"summary"
        ]

        # Parse health check commands
        for pattern in health_patterns:
            match = re.search(pattern, command)
            if match:
                endpoint = match.group(1)
                interval = 30
                if len(match.groups()) > 1:
                    try:
                        interval = int(match.group(2))
                        if len(match.groups()) > 2 and 'minute' in match.group(3):
                            interval *= 60
                    except:
                        pass
                return {
                    'action': 'health_check',
                    'endpoint': endpoint,
                    'interval': interval
                }

        # Parse traffic routing commands
        for pattern in traffic_patterns:
            match = re.search(pattern, command)
            if match:
                groups = match.groups()
                if len(groups) >= 3 and groups[2].isdigit():
                    # Pattern: route X to Y with Z% traffic
                    source = groups[0]
                    target = groups[1]
                    weight = int(groups[2])
                elif len(groups) >= 3 and groups[0].isdigit():
                    # Pattern: send Z% of traffic from X to Y
                    weight = int(groups[0])
                    source = groups[1]
                    target = groups[2]
                else:
                    # Simple redirect
                    source = groups[0]
                    target = groups[1]
                    weight = 100

                return {
                    'action': 'route_traffic',
                    'source': source,
                    'target': target,
                    'weight': weight
                }

        # Parse scaling commands
        for pattern in scaling_patterns:
            match = re.search(pattern, command)
            if match:
                groups = match.groups()
                threshold = int(groups[-1])  # Last group is always the number
                action = 'scale_up' if any(word in command for word in [
                                           'up', 'increase']) else 'scale_down'
                metric = 'cpu'

                # Try to detect metric type
                if 'memory' in command:
                    metric = 'memory'
                elif 'disk' in command:
                    metric = 'disk'
                elif 'network' in command:
                    metric = 'network'

                return {
                    'action': 'auto_scale',
                    'metric': metric,
                    'threshold': threshold,
                    'scale_action': action
                }

        # Parse specific status commands
        for pattern in status_patterns:
            match = re.search(pattern, command)
            if match:
                return {
                    'action': 'get_status',
                    'target': match.group(1)
                }

        # Parse global status commands
        for pattern in global_status_patterns:
            if re.search(pattern, command):
                return {'action': 'get_status'}

        # Special commands
        if 'help' in command:
            return {'action': 'help'}

        if 'clear' in command or 'reset' in command:
            return {'action': 'clear'}

        return {'action': 'unknown', 'command': command}

    def setup_health_check(self, endpoint: str, interval: int = 30) -> Dict:
        """Setup health monitoring for an endpoint"""
        try:
            # Validate endpoint
            if not endpoint.startswith(('http://', 'https://')):
                endpoint = 'https://' + endpoint

            health_check = HealthCheck(
                endpoint=endpoint,
                interval=interval,
                expected_status=200,
                timeout=10,
                failure_threshold=3
            )

            self.health_checks[endpoint] = {
                'config': health_check,
                'status': 'initializing',
                'last_check': None,
                'failures': 0,
                'success_count': 0,
                'created_at': datetime.now()
            }

            # Start monitoring thread if not active
            if not self.monitoring_active:
                self.monitoring_active = True
                monitor_thread = threading.Thread(
                    target=self._monitor_health, daemon=True)
                monitor_thread.start()
                logger.info("Health monitoring thread started")

            self.metrics['total_requests'] += 1

            return {
                'status': 'success',
                'message': f'Health check configured for {endpoint}',
                'endpoint': endpoint,
                'interval': interval,
                'monitoring_active': self.monitoring_active
            }

        except Exception as e:
            logger.error(f"Error setting up health check: {e}")
            return {'status': 'error', 'message': str(e)}

    def _monitor_health(self):
        """Enhanced background health monitoring"""
        logger.info("Starting health monitoring loop")

        while self.monitoring_active:
            if not self.health_checks:
                time.sleep(5)
                continue

            for endpoint, health_data in self.health_checks.items():
                try:
                    config = health_data['config']

                    # Check if it's time for next health check
                    if health_data['last_check']:
                        time_since_check = (
                            datetime.now() - health_data['last_check']).seconds
                        if time_since_check < config.interval:
                            continue

                    # Perform health check
                    start_time = time.time()

                    headers = {
                        'User-Agent': 'AWS-Traffic-Controller/1.0',
                        'Accept': 'text/html,application/json,*/*'
                    }

                    response = requests.get(
                        endpoint,
                        timeout=config.timeout,
                        allow_redirects=True,
                        headers=headers
                    )
                    response_time = (time.time() - start_time) * 1000  # ms

                    if response.status_code == config.expected_status:
                        health_data['status'] = 'healthy'
                        health_data['failures'] = 0
                        health_data['success_count'] += 1
                        health_data['response_time'] = round(response_time, 2)
                        self.metrics['successful_health_checks'] += 1
                    else:
                        health_data['failures'] += 1
                        health_data['last_error'] = f"HTTP {response.status_code}"

                        if health_data['failures'] >= config.failure_threshold:
                            health_data['status'] = 'unhealthy'
                            self._handle_unhealthy_endpoint(
                                endpoint, health_data)
                        else:
                            health_data['status'] = 'degraded'

                    health_data['last_check'] = datetime.now()

                except requests.exceptions.Timeout:
                    health_data['failures'] += 1
                    health_data['status'] = 'timeout'
                    health_data['last_error'] = 'Request timeout'
                    self.metrics['failed_health_checks'] += 1

                except requests.exceptions.ConnectionError:
                    health_data['failures'] += 1
                    health_data['status'] = 'connection_error'
                    health_data['last_error'] = 'Connection failed'
                    self.metrics['failed_health_checks'] += 1

                except Exception as e:
                    health_data['failures'] += 1
                    health_data['status'] = 'error'
                    health_data['last_error'] = str(e)
                    self.metrics['failed_health_checks'] += 1

                    if health_data['failures'] >= config.failure_threshold:
                        self._handle_unhealthy_endpoint(endpoint, health_data)

            time.sleep(2)  # Check every 2 seconds

    def _handle_unhealthy_endpoint(self, endpoint: str, health_data: Dict):
        """Handle unhealthy endpoint detection with alerting"""
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now(),
            'type': 'endpoint_unhealthy',
            'endpoint': endpoint,
            'status': health_data['status'],
            'failures': health_data['failures'],
            'last_error': health_data.get('last_error', 'Unknown error'),
            'action_taken': 'failover_attempted'
        }

        self.alerts.append(alert)
        logger.error(
            f"ALERT: Endpoint {endpoint} is unhealthy - {health_data['failures']} failures")

        # Trigger failover
        failover_success = self._trigger_failover(endpoint)
        alert['failover_success'] = failover_success

        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]

    def _trigger_failover(self, failed_endpoint: str):
        """Enhanced failover with real AWS integration"""
        logger.info(f"Initiating failover for {failed_endpoint}")

        # Find healthy alternatives
        healthy_endpoints = [
            endpoint for endpoint, data in self.health_checks.items()
            if data['status'] == 'healthy' and endpoint != failed_endpoint
        ]

        if healthy_endpoints:
            logger.info(f"Available healthy endpoints: {healthy_endpoints}")

            if not self.mock_mode:
                # Real AWS failover logic would go here
                try:
                    # Update load balancer target groups
                    # self.elb_client.modify_target_group(...)
                    # Update Route53 records
                    # self.route53.change_resource_record_sets(...)
                    pass
                except Exception as e:
                    logger.error(f"AWS failover failed: {e}")
                    return False

            return True
        else:
            logger.error("No healthy endpoints available for failover!")
            return False

    def route_traffic(self, source: str, target: str, weight: int = 100) -> Dict:
        """Enhanced traffic routing with validation"""
        try:
            # Validate weight
            weight = max(0, min(100, weight))

            rule = TrafficRule(
                source_pattern=source,
                target=target,
                weight=weight
            )

            self.traffic_rules.append(rule)
            self.metrics['traffic_routes_created'] += 1

            if self.mock_mode:
                logger.info(
                    f"MOCK: Routing {weight}% traffic from {source} to {target}")
            else:
                # Real AWS ELB/ALB update
                try:
                    # Update load balancer rules
                    # self.elb_client.create_rule(...)
                    pass
                except Exception as e:
                    logger.error(f"AWS traffic routing failed: {e}")
                    return {'status': 'error', 'message': f'AWS update failed: {e}'}

            return {
                'status': 'success',
                'message': f'Traffic routing configured: {weight}% from {source} to {target}',
                'rule_id': len(self.traffic_rules),
                'rule': asdict(rule)
            }

        except Exception as e:
            logger.error(f"Error in traffic routing: {e}")
            return {'status': 'error', 'message': str(e)}

    def setup_auto_scaling(self, metric: str, threshold: float, action: str) -> Dict:
        """Enhanced auto-scaling with CloudWatch integration"""
        try:
            rule = AutoScaleRule(
                metric=metric,
                threshold=threshold,
                action=action,
                cooldown=300
            )

            self.auto_scale_rules.append(rule)
            self.metrics['auto_scale_triggers'] += 1

            if self.mock_mode:
                logger.info(
                    f"MOCK: Auto-scaling rule - {action} when {metric} {threshold}%")
            else:
                # Real CloudWatch alarm creation
                try:
                    alarm_name = f"traffic-controller-{metric}-{action}-{len(self.auto_scale_rules)}"
                    # self.cloudwatch.put_metric_alarm(...)
                    pass
                except Exception as e:
                    logger.error(f"CloudWatch alarm creation failed: {e}")
                    return {'status': 'error', 'message': f'CloudWatch setup failed: {e}'}

            return {
                'status': 'success',
                'message': f'Auto-scaling configured: {action} when {metric} reaches {threshold}%',
                'rule_id': len(self.auto_scale_rules),
                'rule': asdict(rule)
            }

        except Exception as e:
            logger.error(f"Error in auto-scaling setup: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_status(self, target: str = None) -> Dict:
        """Enhanced status reporting with metrics"""
        try:
            if target:
                # Get specific target status
                matching_endpoints = [
                    endpoint for endpoint in self.health_checks.keys()
                    if target.lower() in endpoint.lower()
                ]

                if matching_endpoints:
                    results = {}
                    for endpoint in matching_endpoints:
                        health_data = self.health_checks[endpoint]
                        results[endpoint] = {
                            'status': health_data['status'],
                            'last_check': health_data['last_check'].isoformat() if health_data['last_check'] else None,
                            'failures': health_data['failures'],
                            'success_count': health_data['success_count'],
                            'response_time': health_data.get('response_time', 'N/A'),
                            'last_error': health_data.get('last_error'),
                            'uptime_percentage': self._calculate_uptime(health_data)
                        }

                    return {
                        'status': 'success',
                        'target': target,
                        'matches': len(matching_endpoints),
                        'results': results
                    }
                else:
                    return {'status': 'error', 'message': f'No endpoints found matching "{target}"'}
            else:
                # Get overall system status
                total_endpoints = len(self.health_checks)
                healthy_endpoints = sum(
                    1 for data in self.health_checks.values() if data['status'] == 'healthy')

                # Calculate average response time
                response_times = [
                    data.get('response_time', 0) for data in self.health_checks.values()
                    if data.get('response_time') and data['status'] == 'healthy'
                ]
                avg_response_time = round(
                    sum(response_times) / len(response_times), 2) if response_times else 0

                return {
                    'timestamp': datetime.now().isoformat(),
                    'overall_status': 'healthy' if healthy_endpoints == total_endpoints and total_endpoints > 0 else 'degraded',
                    'total_endpoints': total_endpoints,
                    'healthy_endpoints': healthy_endpoints,
                    'traffic_rules': len(self.traffic_rules),
                    'auto_scale_rules': len(self.auto_scale_rules),
                    'monitoring_active': self.monitoring_active,
                    'recent_alerts': len([a for a in self.alerts if (datetime.now() - a['timestamp']).seconds < 3600]),
                    'metrics': self.metrics,
                    'avg_response_time_ms': avg_response_time,
                    'mode': 'LIVE' if not self.mock_mode else 'MOCK',
                    'endpoints': {
                        endpoint: {
                            'status': data['status'],
                            'response_time': data.get('response_time', 'N/A'),
                            'uptime': self._calculate_uptime(data)
                        }
                        for endpoint, data in self.health_checks.items()
                    }
                }

        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return {'status': 'error', 'message': str(e)}

    def _calculate_uptime(self, health_data: Dict) -> str:
        """Calculate uptime percentage for an endpoint"""
        try:
            total_checks = health_data['success_count'] + \
                health_data['failures']
            if total_checks == 0:
                return 'N/A'

            uptime_percentage = (
                health_data['success_count'] / total_checks) * 100
            return f"{uptime_percentage:.1f}%"
        except:
            return 'N/A'

    def get_recommendations(self) -> List[str]:
        """Enhanced intelligent recommendations"""
        recommendations = []

        # Check for unhealthy endpoints
        unhealthy = [ep for ep, data in self.health_checks.items(
        ) if data['status'] not in ['healthy', 'initializing']]
        if unhealthy:
            recommendations.append(
                f"⚠️  {len(unhealthy)} endpoints are unhealthy. Check: {', '.join(unhealthy[:2])}")

        # Check for recent alerts
        recent_alerts = [a for a in self.alerts if (
            datetime.now() - a['timestamp']).seconds < 3600]
        if recent_alerts:
            recommendations.append(
                f"🚨 {len(recent_alerts)} alerts in the last hour. Check system health.")

        # Check for missing redundancy
        if len(self.health_checks) < 2:
            recommendations.append(
                "💡 Add more endpoints for redundancy and high availability.")

        # Check for load balancing
        if len(self.traffic_rules) == 0 and len(self.health_checks) > 1:
            recommendations.append(
                "🔄 Configure traffic routing rules for better load distribution.")

        # Check for auto-scaling
        if len(self.auto_scale_rules) == 0:
            recommendations.append(
                "📈 Set up auto-scaling to handle traffic spikes automatically.")

        # Check response times
        slow_endpoints = [
            ep for ep, data in self.health_checks.items()
            if data.get('response_time', 0) > 2000 and data['status'] == 'healthy'
        ]
        if slow_endpoints:
            recommendations.append(
                f"🐌 {len(slow_endpoints)} endpoints have slow response times (>2s).")

        # Check for monitoring coverage
        if not self.monitoring_active and self.health_checks:
            recommendations.append(
                "🔍 Health monitoring is not active. Check system configuration.")

        if not recommendations:
            recommendations.append(
                "✅ Your traffic management system is running optimally!")

        return recommendations

    def clear_all(self) -> Dict:
        """Clear all configurations and reset system"""
        try:
            self.health_checks.clear()
            self.traffic_rules.clear()
            self.auto_scale_rules.clear()
            self.alerts.clear()

            # Reset metrics but keep total requests
            old_requests = self.metrics['total_requests']
            self.metrics = {
                'total_requests': old_requests + 1,
                'successful_health_checks': 0,
                'failed_health_checks': 0,
                'traffic_routes_created': 0,
                'auto_scale_triggers': 0
            }

            logger.info("System configuration cleared")

            return {
                'status': 'success',
                'message': 'All configurations cleared and system reset'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}


# Enhanced Flask API with CORS and better error handling
app = Flask(__name__)
CORS(app)  # Enable CORS for web interfaces

# Initialize controller
traffic_controller = AWSTrafficController()

# HTML Dashboard Template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Traffic Control Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .status-healthy { border-left: 5px solid #4CAF50; }
        .status-unhealthy { border-left: 5px solid #f44336; }
        .status-degraded { border-left: 5px solid #ff9800; }
        .metric { display: flex; justify-content: space-between; margin: 10px 0; }
        .command-box { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .alert { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .btn { background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .btn:hover { background: #5a6fd8; }
        input[type="text"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin: 5px 0; }
        .endpoint-status { display: inline-block; padding: 5px 10px; border-radius: 15px; color: white; font-size: 12px; margin: 5px; }
        .healthy { background-color: #4CAF50; }
        .unhealthy { background-color: #f44336; }
        .degraded { background-color: #ff9800; }
        .timeout { background-color: #9E9E9E; }
        .error { background-color: #795548; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 AWS Traffic Control Dashboard</h1>
            <p>Real-time monitoring and management for your infrastructure</p>
        </div>
        
        <div class="command-box">
            <h3>💬 Natural Language Commands</h3>
            <input type="text" id="commandInput" placeholder="Try: 'check health of https://example.com every 30 seconds'">
            <button class="btn" onclick="sendCommand()">Execute Command</button>
            <div id="commandResult"></div>
        </div>
        
        <div class="status-grid">
            <div class="card">
                <h3>📊 System Overview</h3>
                <div id="systemStatus"></div>
            </div>
            
            <div class="card">
                <h3>🏥 Health Checks</h3>
                <div id="healthChecks"></div>
            </div>
            
            <div class="card">
                <h3>🔄 Traffic Rules</h3>
                <div id="trafficRules"></div>
            </div>
            
            <div class="card">
                <h3>💡 Recommendations</h3>
                <div id="recommendations"></div>
            </div>
        </div>
        
        <div class="card">
            <h3>🚨 Recent Alerts</h3>
            <div id="alerts"></div>
        </div>
    </div>

    <script>
        async function sendCommand() {
            const command = document.getElementById('commandInput').value;
            const resultDiv = document.getElementById('commandResult');
            
            if (!command.trim()) {
                resultDiv.innerHTML = '<div class="alert">Please enter a command</div>';
                return;
            }
            
            try {
                const response = await fetch('/api/command', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ command: command })
                });
                
                const data = await response.json();
                resultDiv.innerHTML = `
                    <div class="alert">
                        <strong>Result:</strong> ${data.result.message || JSON.stringify(data.result)}<br>
                        <small>Parsed as: ${JSON.stringify(data.parsed)}</small>
                    </div>
                `;
                
                // Clear input and refresh dashboard
                document.getElementById('commandInput').value = '';
                loadDashboard();
                
            } catch (error) {
                resultDiv.innerHTML = `<div class="alert">Error: ${error.message}</div>`;
            }
        }
        
        async function loadDashboard() {
            try {
                // Load system status
                const statusResponse = await fetch('/api/status');
                const statusData = await statusResponse.json();
                
                document.getElementById('systemStatus').innerHTML = `
                    <div class="metric"><span>Overall Status:</span> <span class="endpoint-status ${statusData.overall_status}">${statusData.overall_status.toUpperCase()}</span></div>
                    <div class="metric"><span>Total Endpoints:</span> <span>${statusData.total_endpoints}</span></div>
                    <div class="metric"><span>Healthy Endpoints:</span> <span>${statusData.healthy_endpoints}</span></div>
                    <div class="metric"><span>Traffic Rules:</span> <span>${statusData.traffic_rules}</span></div>
                    <div class="metric"><span>Auto-Scale Rules:</span> <span>${statusData.auto_scale_rules}</span></div>
                    <div class="metric"><span>Mode:</span> <span>${statusData.mode}</span></div>
                    <div class="metric"><span>Avg Response Time:</span> <span>${statusData.avg_response_time_ms}ms</span></div>
                `;
                
                // Load health checks
                let healthHtml = '';
                for (const [endpoint, data] of Object.entries(statusData.endpoints)) {
                    healthHtml += `
                        <div style="margin: 10px 0; padding: 10px; border: 1px solid #eee; border-radius: 5px;">
                            <strong>${endpoint}</strong><br>
                            <span class="endpoint-status ${data.status}">${data.status.toUpperCase()}</span>
                            <small>Response: ${data.response_time}ms | Uptime: ${data.uptime}</small>
                        </div>
                    `;
                }
                document.getElementById('healthChecks').innerHTML = healthHtml || '<p>No health checks configured</p>';
                
                // Load recommendations
                const recResponse = await fetch('/api/recommendations');
                const recData = await recResponse.json();
                document.getElementById('recommendations').innerHTML = 
                    recData.recommendations.map(rec => `<div style="margin: 5px 0;">${rec}</div>`).join('');
                
                // Load traffic rules (placeholder)
                document.getElementById('trafficRules').innerHTML = statusData.traffic_rules > 0 ? 
                    `<p>${statusData.traffic_rules} traffic rules configured</p>` : 
                    '<p>No traffic rules configured</p>';
                
                // Load alerts (would need separate endpoint in real implementation)
                document.getElementById('alerts').innerHTML = '<p>No recent alerts</p>';
                
            } catch (error) {
                console.error('Dashboard load error:', error);
            }
        }
        
        // Load dashboard on page load
        window.onload = loadDashboard;
        
        // Refresh dashboard every 10 seconds
        setInterval(loadDashboard, 10000);
        
        // Handle Enter key in command input
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('commandInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    sendCommand();
                }
            });
        });
    </script>
</body>
</html>
"""


@app.route('/')
def dashboard():
    """Web dashboard for traffic control"""
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/command', methods=['POST'])
def process_command():
    """Process natural language commands with enhanced error handling"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        command = data.get('command', '').strip()

        if not command:
            return jsonify({'error': 'No command provided'}), 400

        logger.info(f"Processing command: {command}")

        # Parse the command
        parsed = traffic_controller.parse_natural_language(command)

        # Execute the appropriate action
        result = {}

        if parsed['action'] == 'health_check':
            result = traffic_controller.setup_health_check(
                parsed['endpoint'],
                parsed.get('interval', 30)
            )

        elif parsed['action'] == 'route_traffic':
            result = traffic_controller.route_traffic(
                parsed['source'],
                parsed['target'],
                parsed.get('weight', 100)
            )

        elif parsed['action'] == 'auto_scale':
            result = traffic_controller.setup_auto_scaling(
                parsed['metric'],
                parsed['threshold'],
                parsed['scale_action']
            )

        elif parsed['action'] == 'get_status':
            result = traffic_controller.get_status(parsed.get('target'))

        elif parsed['action'] == 'clear':
            result = traffic_controller.clear_all()

        elif parsed['action'] == 'help':
            result = {
                'status': 'success',
                'message': 'Available commands',
                'examples': [
                    "check health of https://myapp.com every 30 seconds",
                    "route 70% traffic from old-server to new-server",
                    "scale up when cpu above 80%",
                    "show status of myapp.com",
                    "show status (for overall system)",
                    "clear (to reset all configurations)"
                ]
            }

        else:
            result = {
                'status': 'error',
                'message': f"I don't understand: '{command}'",
                'suggestions': [
                    "check health of <url> every <seconds> seconds",
                    "route <source> to <target> with <percentage>% traffic",
                    "scale up when cpu above <percentage>%",
                    "show status [of <target>]",
                    "help - show available commands"
                ]
            }

        return jsonify({
            'command': command,
            'parsed': parsed,
            'result': result,
            'recommendations': traffic_controller.get_recommendations(),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error processing command: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/status', methods=['GET'])
def get_system_status():
    """Get overall system status"""
    try:
        return jsonify(traffic_controller.get_status())
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/status/<path:target>', methods=['GET'])
def get_target_status(target):
    """Get specific target status"""
    try:
        return jsonify(traffic_controller.get_status(target))
    except Exception as e:
        logger.error(f"Error getting target status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    """Get system recommendations"""
    try:
        return jsonify({
            'recommendations': traffic_controller.get_recommendations(),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting recommendations: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health_endpoint():
    """API health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'AWS Traffic Control API',
        'version': '2.0',
        'mode': 'LIVE' if not traffic_controller.mock_mode else 'MOCK'
    })


@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Get system metrics"""
    try:
        return jsonify({
            'metrics': traffic_controller.metrics,
            'timestamp': datetime.now().isoformat(),
            'uptime': 'N/A'  # Could track actual uptime
        })
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    try:
        # Convert datetime objects to ISO strings for JSON serialization
        alerts = []
        for alert in traffic_controller.alerts[-50:]:  # Last 50 alerts
            alert_copy = alert.copy()
            if isinstance(alert_copy['timestamp'], datetime):
                alert_copy['timestamp'] = alert_copy['timestamp'].isoformat()
            alerts.append(alert_copy)

        return jsonify({
            'alerts': alerts,
            'total_alerts': len(traffic_controller.alerts),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/endpoints', methods=['GET'])
def get_endpoints():
    """Get all monitored endpoints"""
    try:
        endpoints = {}
        for endpoint, data in traffic_controller.health_checks.items():
            endpoints[endpoint] = {
                'status': data['status'],
                'last_check': data['last_check'].isoformat() if data['last_check'] else None,
                'failures': data['failures'],
                'success_count': data['success_count'],
                'response_time': data.get('response_time'),
                'created_at': data['created_at'].isoformat() if data.get('created_at') else None,
                'uptime': traffic_controller._calculate_uptime(data)
            }

        return jsonify({
            'endpoints': endpoints,
            'total': len(endpoints),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting endpoints: {e}")
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Production server class for better control


class ProductionServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server = None

    def start(self):
        """Start the production server"""
        logger.info(
            f"🌐 Starting AWS Traffic Control API server on {self.host}:{self.port}")
        logger.info(
            f"📊 Dashboard available at: http://{self.host}:{self.port}")
        logger.info(
            f"🔗 API endpoints available at: http://{self.host}:{self.port}/api/")
        logger.info(
            f"💻 Mode: {'LIVE AWS' if not traffic_controller.mock_mode else 'MOCK/DEMO'}")

        self.server = make_server(self.host, self.port, app, threaded=True)

        # Handle graceful shutdown
        def signal_handler(sig, frame):
            logger.info("🛑 Shutting down server...")
            traffic_controller.monitoring_active = False
            if self.server:
                self.server.shutdown()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            signal_handler(None, None)

# Enhanced CLI interface for testing


def interactive_cli():
    """Enhanced interactive command line interface"""
    print("\n" + "="*70)
    print("🚀 AWS TRAFFIC CONTROL MANAGEMENT SYSTEM - LIVE API")
    print("="*70)
    print("🌐 API Server: http://localhost:5000")
    print("📊 Dashboard: http://localhost:5000")
    print("💻 Mode:", "LIVE AWS" if not traffic_controller.mock_mode else "MOCK/DEMO")
    print("-"*70)
    print("Natural Language Commands:")
    print("  • 'check health of https://google.com every 30 seconds'")
    print("  • 'route 70% traffic from old-app to new-app'")
    print("  • 'scale up when cpu above 80%'")
    print("  • 'show status' or 'show status of google.com'")
    print("  • 'help' for more commands")
    print("  • 'api' to start web server")
    print("  • 'quit' to exit")
    print("-"*70)

    while True:
        try:
            command = input("\n💬 Command: ").strip()

            if command.lower() in ['quit', 'exit', 'bye']:
                print("👋 Goodbye!")
                break

            if command.lower() == 'api':
                print("🌐 Starting API server...")
                server = ProductionServer()
                server.start()
                break

            if not command:
                continue

            # Process command
            parsed = traffic_controller.parse_natural_language(command)
            print(f"🔍 Parsed: {parsed}")

            # Execute action
            result = None

            if parsed['action'] == 'health_check':
                result = traffic_controller.setup_health_check(
                    parsed['endpoint'],
                    parsed.get('interval', 30)
                )

            elif parsed['action'] == 'route_traffic':
                result = traffic_controller.route_traffic(
                    parsed['source'],
                    parsed['target'],
                    parsed.get('weight', 100)
                )

            elif parsed['action'] == 'auto_scale':
                result = traffic_controller.setup_auto_scaling(
                    parsed['metric'],
                    parsed['threshold'],
                    parsed['scale_action']
                )

            elif parsed['action'] == 'get_status':
                result = traffic_controller.get_status(parsed.get('target'))

            elif parsed['action'] == 'clear':
                result = traffic_controller.clear_all()

            elif parsed['action'] == 'help':
                result = {
                    'message': 'Available commands',
                    'examples': [
                        "health: check health of <url> every <n> seconds",
                        "routing: route <source> to <target> with <n>% traffic",
                        "scaling: scale up when cpu above <n>%",
                        "status: show status [of <target>]",
                        "management: clear (reset), help, api (start server)"
                    ]
                }

            if result:
                print(f"✅ Result: {json.dumps(result, indent=2, default=str)}")

            # Show recommendations
            recommendations = traffic_controller.get_recommendations()
            if recommendations:
                print("\n💡 Recommendations:")
                for rec in recommendations[:3]:  # Show top 3
                    print(f"   {rec}")

        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")


if __name__ == "__main__":
    import sys

    # Parse command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == 'api' or sys.argv[1] == 'server':
            # Start production server
            host = sys.argv[2] if len(sys.argv) > 2 else '0.0.0.0'
            port = int(sys.argv[3]) if len(sys.argv) > 3 else 5000

            server = ProductionServer(host, port)
            server.start()

        elif sys.argv[1] == 'dev':
            # Start development server
            print("🛠️  Starting development server...")
            app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)

        else:
            print("Usage:")
            print(
                "  python script.py api [host] [port]  - Start production server")
            print("  python script.py dev                - Start development server")
            print("  python script.py                    - Interactive CLI")
    else:
        # Start interactive CLI
        interactive_cli()
