from backend.services.aws.client import get_client

RISKY_PORTS = {
    22: "SSH",
    3389: "RDP",
}


def list_security_groups() -> list:
    ec2 = get_client("ec2")
    response = ec2.describe_security_groups()
    return response.get("SecurityGroups", [])


def find_open_risky_ports(security_group: dict) -> list:
    open_ports = []

    for permission in security_group.get("IpPermissions", []):
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        if from_port is None or to_port is None:
            continue

        for ip_range in permission.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr != "0.0.0.0/0":
                continue

            for port, name in RISKY_PORTS.items():
                if from_port <= port <= to_port:
                    open_ports.append({"port": port, "service": name})

    return open_ports


def has_unrestricted_inbound(security_group: dict) -> bool:
    for permission in security_group.get("IpPermissions", []):
        protocol = permission.get("IpProtocol")
        from_port = permission.get("FromPort")

        for ip_range in permission.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr != "0.0.0.0/0":
                continue

            if protocol == "-1" or from_port is None:
                return True

    return False


def scan_security_groups() -> list:
    findings = []
    groups = list_security_groups()

    for sg in groups:
        group_id = sg["GroupId"]
        group_name = sg.get("GroupName", "")
        open_ports = find_open_risky_ports(sg)

        if open_ports:
            services = ", ".join(p["service"] for p in open_ports)
            findings.append({
                "resource_id": group_id,
                "resource_type": "security_group",
                "finding": f"{services} exposed to the internet (0.0.0.0/0)",
                "severity": "CRITICAL",
                "category": "NETWORK_SECURITY",
                "evidence": {"group_name": group_name, "open_ports": open_ports},
                "status": "OPEN",
            })
        else:
            findings.append({
                "resource_id": group_id,
                "resource_type": "security_group",
                "finding": "No risky ports exposed to the internet",
                "severity": "INFO",
                "category": "NETWORK_SECURITY",
                "evidence": {"group_name": group_name, "open_ports": []},
                "status": "RESOLVED",
            })

        unrestricted = has_unrestricted_inbound(sg)
        findings.append({
            "resource_id": group_id,
            "resource_type": "security_group",
            "finding": "All ports/protocols open to the internet" if unrestricted else "No unrestricted inbound rule found",
            "severity": "CRITICAL" if unrestricted else "INFO",
            "category": "NETWORK_SECURITY",
            "evidence": {"group_name": group_name, "unrestricted_inbound": unrestricted},
            "status": "OPEN" if unrestricted else "RESOLVED",
        })

    return findings
