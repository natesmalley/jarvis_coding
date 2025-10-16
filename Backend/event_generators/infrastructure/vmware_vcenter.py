#!/usr/bin/env python3
"""Generate synthetic VMware vCenter logs."""
import json
import random
from datetime import datetime, timezone, timedelta
import time

# VMware vCenter event types and components
COMPONENTS = ["vpxd", "vapi-endpoint", "eam", "sso-adminserver", "envoy", "content-library", "vpxd-svcs", "vsan-health"]
SEVERITIES = ["info", "warning", "error", "verbose", "trivia"]
EVENT_TYPES = ["VmPoweredOnEvent", "VmPoweredOffEvent", "VmMigratedEvent", "VmCreatedEvent", "VmRemovedEvent",
               "UserLoginSessionEvent", "UserLogoutSessionEvent", "TaskEvent", "AlarmStatusChangedEvent",
               "VmReconfiguredEvent", "VmClonedEvent", "VmDeployedEvent", "VmSnapshotCreatedEvent"]

USERS = ["Administrator@vsphere.local", "root", "service-account@vsphere.local", "backup@vsphere.local",
         "monitor@vsphere.local", "automation@vsphere.local"]

VM_NAMES = ["prod-web-01", "prod-db-01", "dev-app-01", "test-srv-01", "qa-web-01", "staging-db-01",
            "backup-srv-01", "monitoring-01", "infra-dns-01", "infra-ntp-01"]

ESX_HOSTS = ["esx01.corp.local", "esx02.corp.local", "esx03.corp.local", "esx04.corp.local"]

DATACENTERS = ["Datacenter01", "Datacenter02", "Production", "Development"]

OPERATIONS = ["com.vmware.vcenter.vm.power.on", "com.vmware.vcenter.vm.power.off",
              "com.vmware.vcenter.vm.create", "com.vmware.vcenter.vm.delete",
              "com.vmware.vcenter.vm.clone", "com.vmware.vcenter.vm.relocate",
              "com.vmware.vcenter.vm.snapshot.create", "com.vmware.vcenter.vm.snapshot.delete",
              "com.vmware.vcenter.vm.hardware.update", "com.vmware.vcenter.vm.guest.power"]

def get_random_ip():
    """Generate a random IP address."""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_event_id():
    """Generate a vCenter event ID."""
    return f"event-{random.randint(10000, 99999)}"

def generate_chain_id():
    """Generate a vCenter chain ID."""
    return f"{random.randint(1000000, 9999999)}"

def generate_vpxd_log():
    """Generate a vpxd (vCenter Server) log entry."""
    now = datetime.now(timezone.utc)
    event_type = random.choice(EVENT_TYPES)
    
    # Map event types to descriptions
    event_descriptions = {
        "VmPoweredOnEvent": "Virtual machine powered on",
        "VmPoweredOffEvent": "Virtual machine powered off",
        "VmMigratedEvent": "Virtual machine migrated",
        "VmCreatedEvent": "Virtual machine created",
        "VmRemovedEvent": "Virtual machine removed",
        "UserLoginSessionEvent": "User logged in",
        "UserLogoutSessionEvent": "User logged out",
        "TaskEvent": "Task completed",
        "AlarmStatusChangedEvent": "Alarm status changed",
        "VmReconfiguredEvent": "Virtual machine reconfigured",
        "VmClonedEvent": "Virtual machine cloned",
        "VmDeployedEvent": "Virtual machine deployed",
        "VmSnapshotCreatedEvent": "Virtual machine snapshot created"
    }
    
    vm_name = random.choice(VM_NAMES)
    user = random.choice(USERS)
    host = random.choice(ESX_HOSTS)
    
    # Format: [eventId] [partInfo] [createdTime] [eventType] [severity] [user] [target] [chainId] [desc]
    log_entry = (
        f"[{generate_event_id()}] "
        f"[1] "
        f"[{now.isoformat()}Z] "
        f"[{event_type}] "
        f"[{random.choice(SEVERITIES)}] "
        f"[{user}] "
        f"[{vm_name}] "
        f"[{generate_chain_id()}] "
        f"[{event_descriptions.get(event_type, 'Event occurred')} on host {host}]"
    )
    
    return log_entry

def generate_vapi_endpoint_log():
    """Generate a vAPI endpoint access log."""
    now = datetime.now(timezone.utc)
    
    # HTTP access log format
    ip = get_random_ip()
    user = random.choice(USERS)
    method = random.choice(["GET", "POST", "PUT", "DELETE", "PATCH"])
    status = random.choice([200, 200, 200, 201, 204, 400, 401, 403, 404, 500])
    
    paths = [
        "/api/vcenter/vm",
        "/api/vcenter/vm/vm-123/power/start",
        "/api/vcenter/vm/vm-456/power/stop",
        "/api/vcenter/host",
        "/api/vcenter/datastore",
        "/api/vcenter/network",
        "/api/content/library",
        "/api/vcenter/deployment/install"
    ]
    
    uri = random.choice(paths)
    bytes_sent = random.randint(200, 5000)
    process_time = random.randint(10, 500)
    
    log_entry = (
        f"{now.isoformat()}Z | vapi-endpoint | "
        f"{ip} {user} {user} [{now.strftime('%d/%b/%Y:%H:%M:%S +0000')}] "
        f'"{method} {uri} HTTP/1.1" {status} {bytes_sent} "-" '
        f'"python-requests/2.25.1" {process_time}'
    )
    
    return log_entry

def generate_sso_log():
    """Generate an SSO admin server log."""
    now = datetime.now(timezone.utc)
    
    messages = [
        "User authentication successful",
        "User authentication failed - invalid credentials",
        "Token issued successfully",
        "Token validation successful",
        "Session created",
        "Session terminated",
        "Password policy check passed",
        "Account locked due to multiple failed attempts",
        "LDAP connection established",
        "Certificate validation successful"
    ]
    
    severity = random.choice(["INFO", "WARN", "ERROR"])
    op_id = f"op-{random.randint(1000, 9999)}"
    
    log_entry = (
        f"{now.isoformat()}Z {severity} ssoAdminServer[{random.randint(1000, 9999)}:MainThread] "
        f"[opID={op_id}] [com.vmware.identity.auth] {random.choice(messages)}"
    )
    
    return log_entry

def generate_envoy_access_log():
    """Generate an Envoy proxy access log matching parser format."""
    now = datetime.now(timezone.utc)
    
    # Match parser format: envoy-access-1 format
    # .*$createdTime=tzPattern$ $severity$ $process_name$[$process_id$] [$originater_id$ sub=$sub$] $request_timestamp=tzPattern$ $method$ $uri{parse=uri}$ $protocol$ $status$ $code_details$ $flags$ $bytes_received$ $bytes_sent$ $duration$ $resp_upstream_service_time=number$ $x_forwarded_for$ $upstream_host$ $upstream_local_address$ $downstream_local_address$ $downstream_remote_address$ $req_server_name$ $route_name$
    
    paths = [
        "/ui/login",
        "/ui/logout", 
        "/ui/views/vm",
        "/ui/app/vm/list",
        "/ui/app/host/summary",
        "/sdk",
        "/sdk/vimService"
    ]
    
    method = random.choice(["GET", "POST", "PUT", "DELETE"])
    status = random.choice([200, 200, 200, 301, 302, 401, 403, 404, 500])
    duration = random.randint(1, 500)
    process_id = random.randint(1000, 9999)
    originator_id = generate_chain_id()
    sub = "trace"
    
    # Generate all required fields
    upstream_host = f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}:443"
    upstream_local = f"{get_random_ip()}:443"
    downstream_local = f"{get_random_ip()}:443" 
    downstream_remote = f"{get_random_ip()}:0"
    bytes_received = random.randint(100, 1000)
    bytes_sent = random.randint(200, 5000)
    upstream_service_time = random.randint(1, 100)
    x_forwarded_for = get_random_ip()
    req_server_name = "vcenter01.corp.local"
    route_name = "default"
    
    # Format matching parser expectation
    log_entry = (
        f"{now.isoformat()}Z info envoy[{process_id}] "
        f"[{originator_id} sub={sub}] "
        f"{now.isoformat()}Z {method} {random.choice(paths)} HTTP/1.1 {status} - - "
        f"{bytes_received} {bytes_sent} {duration} {upstream_service_time} "
        f"{x_forwarded_for} {upstream_host} {upstream_local} {downstream_local} "
        f"{downstream_remote} {req_server_name} {route_name}"
    )
    
    return log_entry

def vmware_vcenter_log(overrides: dict | None = None) -> str:
    """Generate a single VMware vCenter log entry."""
    now = datetime.now(timezone.utc)
    
    # Select component and generate appropriate log
    component = random.choices(
        ["vpxd", "vapi-endpoint", "sso-adminserver", "envoy"],
        weights=[40, 30, 20, 10]
    )[0]
    
    # Generate syslog header
    priority = 134  # local0.info
    timestamp = now.strftime("%b %d %H:%M:%S")
    hostname = "vcenter01.corp.local"
    process_id = random.randint(1000, 9999)
    
    # Generate component-specific log
    if component == "vpxd":
        message = generate_vpxd_log()
    elif component == "vapi-endpoint":
        message = generate_vapi_endpoint_log()
    elif component == "sso-adminserver":
        message = generate_sso_log()
    else:  # envoy
        message = generate_envoy_access_log()
    
    # Format as syslog
    log_line = f"<{priority}>1 {timestamp} {hostname} {component} {process_id} - - {message}"
    
    # Apply overrides if provided
    if overrides:
        # For text logs, overrides are limited
        if "severity" in overrides and overrides["severity"] in message:
            message = message.replace(random.choice(SEVERITIES), overrides["severity"])
            log_line = f"<{priority}>1 {timestamp} {hostname} {component} {process_id} - - {message}"
    
    return log_line

# OCSF-style attributes for HEC
if __name__ == "__main__":
    # Generate sample logs
    print("Sample VMware vCenter logs:")
    
    print("\nvpxd (vCenter Server) logs:")
    for _ in range(2):
        log = vmware_vcenter_log()
        if "vpxd" in log:
            print(log)
    
    print("\nvAPI endpoint logs:")
    for _ in range(2):
        log = vmware_vcenter_log()
        if "vapi-endpoint" in log:
            print(log)
    
    print("\nSSO logs:")
    for _ in range(2):
        log = vmware_vcenter_log()
        if "ssoAdminServer" in log:
            print(log)