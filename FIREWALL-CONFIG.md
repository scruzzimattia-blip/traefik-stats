# CrowdSec Firewall Bouncer Configuration

## Overview

The CrowdSec firewall bouncer (`crowdsec-firewall-bouncer`) is configured to block traffic at multiple levels:
- **Host traffic** (INPUT chain)
- **Docker container traffic** (DOCKER-USER chain)
- **Forwarded traffic** (FORWARD chain)

## Configuration Details

### Current Setup
1. **CrowdSec LAPI**: Running in Docker container, exposed on host port 8082
2. **Firewall Bouncer**: Running on host, connects to LAPI on `localhost:8082`
3. **iptables Chains**: Rules added to INPUT, FORWARD, and DOCKER-USER chains
4. **ipset**: Uses `crowdsec-blacklists-0` ipset for efficient IP matching

### Configuration File
Location: `/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml`

Key settings:
```yaml
mode: iptables
api_url: http://localhost:8082/
api_key: y+RKcZmjLpKjJZ/AJwPjs/HweQytrLHWTOCCkolSZRE
deny_action: DROP
iptables_chains:
  - INPUT        # Blocks traffic to host
  - FORWARD      # Blocks forwarded traffic
  - DOCKER-USER  # Blocks traffic to Docker containers
```

### How It Works
1. When an IP is blocked (via web UI or automatic detection):
   - Decision created in CrowdSec LAPI
   - Firewall bouncer pulls decision every 10s
   - IP added to `crowdsec-blacklists-0` ipset
   - iptables rules drop packets from IPs in the ipset

2. Traffic blocking occurs at:
   - **Host level**: Any traffic to the host from blocked IPs
   - **Container level**: Any traffic to Docker containers from blocked IPs
   - **Network level**: Any forwarded traffic from blocked IPs

## Verification Commands

### Check Firewall Bouncer Status
```bash
sudo systemctl status crowdsec-firewall-bouncer
```

### Check iptables Rules
```bash
sudo iptables -L CROWDSEC_CHAIN -n -v
sudo iptables -L INPUT -n -v | grep CROWDSEC
sudo iptables -L DOCKER-USER -n -v | grep CROWDSEC
sudo iptables -L FORWARD -n -v | grep CROWDSEC
```

### Check ipset Contents
```bash
sudo ipset list crowdsec-blacklists-0
```

### Check CrowdSec Decisions
```bash
docker exec traefik-stats-crowdsec cscli decisions list
```

## Testing Blocking

### Manual Block via Web UI
1. Access the web interface at `http://localhost:8501`
2. Go to "🛡️ CrowdSec Integration" tab
3. Enter IP, duration, and reason in "Manual Decision" section
4. Click "🔨 Ban IP"

### Verify Block is Active
1. Check decisions: `docker exec traefik-stats-crowdsec cscli decisions list`
2. Check ipset: `sudo ipset list crowdsec-blacklists-0 | grep <IP>`
3. Check iptables counters: `sudo iptables -L CROWDSEC_CHAIN -n -v`

## Troubleshooting

### Firewall Bouncer Not Starting
Check logs: `sudo tail -f /var/log/crowdsec-firewall-bouncer.log`

### IP Not Being Blocked
1. Verify decision exists in CrowdSec
2. Check firewall bouncer is running and connected to LAPI
3. Verify iptables rules exist
4. Check ipset contains the IP

### Docker Traffic Not Blocked
Ensure DOCKER-USER chain is configured in bouncer config:
```yaml
iptables_chains:
  - INPUT
  - FORWARD
  - DOCKER-USER
```

## Notes
- The firewall bouncer syncs with CrowdSec every 10 seconds (configurable via `update_frequency`)
- Blocked IPs are automatically removed when decisions expire
- Manual unblocking is available via web UI "Remove Decision" button