#! /bin/bash

# ######################### qFirewall (qfw) 0.2 ########################
# This is a basic /sbin/iptables firewall script with Docker support.
# Version 0.2 - Fixed Docker networking issues
# #######################################################################

# #######################################################################
# ## Rules function -- edit this according to your needs

function qfw_rules {
  # IMPORTANT: For Docker compatibility, we need to handle FORWARD chain properly

  # Set default policies
  /sbin/iptables -t filter -P INPUT DROP
  /sbin/iptables -t filter -P OUTPUT DROP
  # CRITICAL: Don't set FORWARD to DROP yet - Docker needs to set up its rules first
  echo "     > Set INPUT/OUTPUT policies to DROP"

  # Apply the same rules to IPv6
  /sbin/ip6tables -t filter -P INPUT DROP
  /sbin/ip6tables -t filter -P FORWARD DROP
  /sbin/ip6tables -t filter -P OUTPUT DROP
  echo "     > Block everything for IPv6"

  # DOCKER COMPATIBILITY - Allow Docker to manage its chains
  # Check if Docker chains exist
  if /sbin/iptables -L DOCKER -n >/dev/null 2>&1; then
    echo "     > Docker chains detected, preserving Docker rules"
    # Allow Docker's FORWARD rules to work
    /sbin/iptables -I FORWARD -j DOCKER-USER
    if /sbin/iptables -L DOCKER-ISOLATION-STAGE-1 -n >/dev/null 2>&1; then
      /sbin/iptables -I FORWARD -j DOCKER-ISOLATION-STAGE-1
    fi
    /sbin/iptables -I FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    /sbin/iptables -I FORWARD -o docker0 -j DOCKER
    /sbin/iptables -I FORWARD -i docker0 ! -o docker0 -j ACCEPT
    /sbin/iptables -I FORWARD -i docker0 -o docker0 -j ACCEPT

    # Allow all Docker bridge networks
    for bridge in $(ls /sys/class/net/ | grep -E '^br-'); do
      /sbin/iptables -I FORWARD -o $bridge -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
      /sbin/iptables -I FORWARD -o $bridge -j DOCKER
      /sbin/iptables -I FORWARD -i $bridge ! -o $bridge -j ACCEPT
      /sbin/iptables -I FORWARD -i $bridge -o $bridge -j ACCEPT
      # Priority DNS rules for this bridge
      /sbin/iptables -I FORWARD 1 -i $bridge -p tcp --dport 53 -j ACCEPT
      /sbin/iptables -I FORWARD 1 -i $bridge -p udp --dport 53 -j ACCEPT
      /sbin/iptables -I FORWARD 1 -o $bridge -p tcp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
      /sbin/iptables -I FORWARD 1 -o $bridge -p udp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
      echo "     > Authorized Docker bridge: $bridge"
    done
  fi

  # NOW set FORWARD policy to DROP (after Docker rules)
  /sbin/iptables -t filter -P FORWARD DROP
  echo "     > Set FORWARD policy to DROP (Docker rules preserved)"

  # Block admin ports by default (for Portainer and NGINXPM)
  /sbin/iptables -t filter -A INPUT -p tcp --dport 81 -j DROP
  /sbin/iptables -t filter -A INPUT -p tcp --dport 9334 -j DROP
  /sbin/iptables -t filter -A INPUT -p tcp --dport 8000 -j DROP
  echo "     > Block admin ports by default"

  # Allow specific IPs to admin ports (uncomment and add your IPs)
  # /sbin/iptables -t filter -I INPUT -p tcp --dport 81 -s 10.10.10.10/32 -j ACCEPT
  # /sbin/iptables -t filter -I INPUT -p tcp --dport 9334 -s 10.10.10.10/32 -j ACCEPT
  # echo "     > Allow specific IPs to admin ports"

  # Don't break established connections
  /sbin/iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  /sbin/iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  echo "     > Don't break established connections"

  # Authorize loopback (127.0.0.1)
  /sbin/iptables -t filter -A INPUT -i lo -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -o lo -j ACCEPT
  echo "     > Authorize Loopback"

  # ICMP (ping)
  /sbin/iptables -t filter -A INPUT -p icmp -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p icmp -j ACCEPT
  echo "     > Authorize ICMP (ping)"

  # SSH in/out
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 22 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 22 -j ACCEPT
  /sbin/iptables -t filter -A INPUT -p tcp --dport 37389 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --dport 37389 -j ACCEPT
  echo "     > Authorize SSH"

  # DNS in/out - System level (high priority for Docker daemon)
  /sbin/iptables -t filter -I OUTPUT 1 -p tcp --dport 53 -j ACCEPT
  /sbin/iptables -t filter -I OUTPUT 1 -p udp --dport 53 -j ACCEPT
  /sbin/iptables -t filter -I INPUT 1 -p tcp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
  /sbin/iptables -t filter -I INPUT 1 -p udp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --dport 53 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT
  /sbin/iptables -t filter -A INPUT -p tcp --dport 53 -j ACCEPT
  /sbin/iptables -t filter -A INPUT -p udp --dport 53 -j ACCEPT
  echo "     > Authorize DNS"

  # DNS for Docker containers - Allow DNS queries from Docker networks
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --dport 53 -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p udp --dport 53 -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p udp --sport 53 -m state --state ESTABLISHED,RELATED -j ACCEPT
  echo "     > Authorize DNS for Docker containers"

  # HTTP/HTTPS for Docker containers - Allow outbound web traffic from containers
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --dport 80 -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --dport 443 -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --sport 80 -m state --state ESTABLISHED,RELATED -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --sport 443 -m state --state ESTABLISHED,RELATED -j ACCEPT
  echo "     > Authorize HTTP/HTTPS for Docker containers"

  # Streaming ports for Docker containers (digitalclip-recording)
  # Range 7000-12000 covers Icecast, Shoutcast, and similar streaming servers
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --dport 7000:12000 -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --sport 7000:12000 -m state --state ESTABLISHED,RELATED -j ACCEPT
  echo "     > Authorize streaming ports 7000-12000 for Docker containers"

  # Allow established/related connections in FORWARD (for all container traffic)
  /sbin/iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
  echo "     > Allow established connections in FORWARD"

  # NTP Out
  /sbin/iptables -t filter -A OUTPUT -p udp --dport 123 -j ACCEPT
  echo "     > Authorize NTP outbound"

  # HTTP + HTTPS Out - Priority for feed processing
  /sbin/iptables -t filter -I OUTPUT 1 -p tcp --dport 80 -j ACCEPT
  /sbin/iptables -t filter -I OUTPUT 1 -p tcp --dport 443 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 8000 -j ACCEPT # docker
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 9443 -j ACCEPT # docker

  # HTTP + HTTPS In
  /sbin/iptables -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
  /sbin/iptables -t filter -A INPUT -p tcp --dport 443 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 8000 -j ACCEPT # docker
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 9443 -j ACCEPT # docker
  echo "     > Authorize http and https"

  # DigitalClip App (porta 8083)
  /sbin/iptables -t filter -A INPUT -p tcp --dport 8083 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --sport 8083 -j ACCEPT
  echo "     > Authorize DigitalClip app (8083)"

  # DigitalClip App (porta 8084)
  /sbin/iptables -t filter -A INPUT -p tcp --dport 8084 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --sport 8084 -j ACCEPT
  echo "     > Authorize DigitalClip Staging (8084)"


  # PhpMyAdmin Staging (porta 8082)
  /sbin/iptables -t filter -A INPUT -p tcp --dport 8082 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --sport 8082 -j ACCEPT
  echo "     > Authorize PhpMyAdmin Staging (8082)"

  # DigitalClip App (porta 8087)
  /sbin/iptables -t filter -A INPUT -p tcp --dport 8087 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --sport 8087 -j ACCEPT
  echo "     > Authorize DigitalClip Revert (8087)"


  # filestash  (porta 8089)
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 8089 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --sport 8089 -j ACCEPT
  # echo "     > Authorize filestash (8089)"

  # FTP Out
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 21 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 20 -j ACCEPT

  # FTP In
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 20 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 21 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  # echo "     > Authorize FTP"

  # Mail SMTP
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 25 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT

  # Mail SMTP - TLS (porta 587) - Primary method
  /sbin/iptables -t filter -I OUTPUT 1 -p tcp --dport 587 -j ACCEPT
  /sbin/iptables -t filter -I INPUT 1 -p tcp --sport 587 -m state --state ESTABLISHED,RELATED -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --dport 587 -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --sport 587 -m state --state ESTABLISHED,RELATED -j ACCEPT
  echo "     > Authorize SMTP TLS (587)"

  # Mail SMTP - Mailgun SSL (porta 465) - High priority for containers
  /sbin/iptables -t filter -I OUTPUT 1 -p tcp --dport 465 -j ACCEPT
  /sbin/iptables -t filter -I INPUT 1 -p tcp --sport 465 -m state --state ESTABLISHED,RELATED -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --dport 465 -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --sport 465 -m state --state ESTABLISHED,RELATED -j ACCEPT
  echo "     > Authorize SMTP Mailgun SSL (465)"

  # Mail SMTP - Mailtrap (porta 2525)
  /sbin/iptables -t filter -I OUTPUT 1 -p tcp --dport 2525 -j ACCEPT
  /sbin/iptables -t filter -I INPUT 1 -p tcp --sport 2525 -m state --state ESTABLISHED,RELATED -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --dport 2525 -j ACCEPT
  /sbin/iptables -t filter -I FORWARD 1 -p tcp --sport 2525 -m state --state ESTABLISHED,RELATED -j ACCEPT
  echo "     > Authorize SMTP Mailtrap (2525)"

  # Mail POP3:110
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 110 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 110 -j ACCEPT

  # Mail IMAP:143
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 143 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 143 -j ACCEPT

  # Mail POP3S:995
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 995 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 995 -j ACCEPT
  # echo "     > Authorize mail"

  # Allow Docker traffic but prevent it from overriding admin port rules
  # (now managed above)
  # /sbin/iptables -A INPUT -i docker0 -j ACCEPT
  # /sbin/iptables -A FORWARD -i docker0 -j ACCEPT
  # /sbin/iptables -A OUTPUT -o docker0 -j ACCEPT
  # echo "     > Authorize Docker with admin port protection"

  # Portainer (9334)
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 9334 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 9334 -j ACCEPT
  # echo "     > Authorize Portainer"

  # Allow specific IPs to NPM Admin (port 81)
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 81 -s 10.10.10.10/32 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 81 -s 11.11.11.11/32 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 81 -j DROP
  # echo "     > Restrict NPM Admin to trusted IPs only"

  # Allow specific IPs to Portainer (direct 9334 access - optional fallback)
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 9334 -s 10.10.10.10/32 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 9334 -s 11.11.11.11/32 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 9334 -j DROP
  # echo "     > Restrict direct Portainer access to trusted IPs only"

  # Allow specific IPs to Portainer Edge Agent (if used)
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 8000 -s 10.10.10.10/32 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 8000 -s 11.11.11.11/32 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 8000 -j DROP
  # echo "     > Restrict Portainer Edge Agent to trusted IPs only"

  # LDAP
  /sbin/iptables -t filter -A INPUT -p tcp --dport 389 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --dport 389 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 636 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 636 -j ACCEPT
  echo "     > Authorize LDAP"

  # Node Exporter (9100)
  /sbin/iptables -t filter -A INPUT -p tcp --dport 9100 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --dport 9100 -j ACCEPT
  echo "     > Authorize Node Exporter"

  # Prometheus (9090)
  /sbin/iptables -t filter -A INPUT -p tcp --dport 9090 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --dport 9090 -j ACCEPT
  echo "     > Authorize Prometheus"

  # Loki (3100)
  /sbin/iptables -t filter -A INPUT -p tcp --dport 3100 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --dport 3100 -j ACCEPT
  echo "     > Authorize Loki"

  # Promtail (9080)
  /sbin/iptables -t filter -A INPUT -p tcp --dport 9080 -j ACCEPT
  /sbin/iptables -t filter -A OUTPUT -p tcp --dport 9080 -j ACCEPT
  echo "     > Authorize Promtail"

  # Allow Docker interfaces with specific DNS priority
  /sbin/iptables -I INPUT 1 -i docker0 -p tcp --dport 53 -j ACCEPT
  /sbin/iptables -I INPUT 1 -i docker0 -p udp --dport 53 -j ACCEPT
  /sbin/iptables -I OUTPUT 1 -o docker0 -p tcp --sport 53 -j ACCEPT
  /sbin/iptables -I OUTPUT 1 -o docker0 -p udp --sport 53 -j ACCEPT
  /sbin/iptables -A INPUT -i docker0 -j ACCEPT
  /sbin/iptables -A OUTPUT -o docker0 -j ACCEPT

  # Also allow Docker bridge networks with DNS priority
  for bridge in $(ls /sys/class/net/ 2>/dev/null | grep -E '^br-'); do
    /sbin/iptables -I INPUT 1 -i $bridge -p tcp --dport 53 -j ACCEPT
    /sbin/iptables -I INPUT 1 -i $bridge -p udp --dport 53 -j ACCEPT
    /sbin/iptables -I OUTPUT 1 -o $bridge -p tcp --sport 53 -j ACCEPT
    /sbin/iptables -I OUTPUT 1 -o $bridge -p udp --sport 53 -j ACCEPT
    /sbin/iptables -A INPUT -i $bridge -j ACCEPT
    /sbin/iptables -A OUTPUT -o $bridge -j ACCEPT
  done

  # Allow Docker embedded DNS server (127.0.0.11)
  /sbin/iptables -I INPUT 1 -s 127.0.0.11 -p tcp --sport 53 -j ACCEPT
  /sbin/iptables -I INPUT 1 -s 127.0.0.11 -p udp --sport 53 -j ACCEPT
  /sbin/iptables -I OUTPUT 1 -d 127.0.0.11 -p tcp --dport 53 -j ACCEPT
  /sbin/iptables -I OUTPUT 1 -d 127.0.0.11 -p udp --dport 53 -j ACCEPT

  echo "     > Authorize Docker interfaces with DNS priority"

  # Allow KVM/libvirt bridge interface
  /sbin/iptables -I INPUT -i virbr0 -j ACCEPT
  /sbin/iptables -I FORWARD -i virbr0 -j ACCEPT
  /sbin/iptables -I OUTPUT -o virbr0 -j ACCEPT
  echo "     > Authorize WMs"

  # Saltstack
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 4505 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 4505 -j ACCEPT
  # /sbin/iptables -t filter -A OUTPUT -p tcp --dport 4506 -j ACCEPT
  # /sbin/iptables -t filter -A INPUT -p tcp --dport 4506 -j ACCEPT
  # echo "     > Authorize Saltstack"

  # Block UDP attack
  /sbin/iptables -A INPUT -m state --state INVALID -j DROP
  echo "     > Block UDP attack"

  # Block null packages
  /sbin/iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
  echo "     > Block null packages"

  # Block SYN-flood attacks
  /sbin/iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
  echo "     > Block SYN-flood attacks"

  # Block XMAS packets
  /sbin/iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  echo "     > Block XMAS packets"

  # Rate limit new connections to prevent various DoS attacks (excluding DNS)
  /sbin/iptables -A INPUT -p tcp -m state --state NEW ! --dport 53 -m limit --limit 60/min --limit-burst 10 -j ACCEPT
  /sbin/iptables -A INPUT -p udp -m state --state NEW ! --dport 53 -m limit --limit 60/min --limit-burst 10 -j ACCEPT
  # Allow DNS without rate limiting
  /sbin/iptables -A INPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT
  /sbin/iptables -A INPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
  echo "     > Rate limit new connections (DNS excluded)"

  # Log and drop suspicious packets
  /sbin/iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "qFirewall DROP: " --log-level 7 --log-tcp-options --log-ip-options

  # Log DNS issues for debugging (before final DROP)
  /sbin/iptables -A INPUT -p tcp --dport 53 -m limit --limit 2/min -j LOG --log-prefix "qFirewall DNS-TCP: " --log-level 7
  /sbin/iptables -A INPUT -p udp --dport 53 -m limit --limit 2/min -j LOG --log-prefix "qFirewall DNS-UDP: " --log-level 7

  /sbin/iptables -A INPUT -j DROP
  echo "     > Log and drop suspicious packets (with DNS debugging)"
}

# #######################################################################
# ## Other functions

function qfw_test_dns {
  qfw_separator
  echo "     > Testing DNS resolution and connectivity..."

  echo "     > Testing system DNS:"
  if timeout 10 nslookup cinepop.com.br > /dev/null 2>&1; then
    echo "     ✓ System DNS resolution: OK (cinepop.com.br)"
  else
    echo "     ✗ System DNS resolution: FAILED (cinepop.com.br)"
  fi

  if timeout 10 nslookup google.com > /dev/null 2>&1; then
    echo "     ✓ System DNS resolution: OK (google.com)"
  else
    echo "     ✗ System DNS resolution: FAILED (google.com)"
  fi

  # Test Docker DNS if available
  if command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then
    echo "     > Testing Docker DNS:"
    if docker run --rm alpine nslookup cinepop.com.br > /dev/null 2>&1; then
      echo "     ✓ Docker DNS resolution: OK (cinepop.com.br)"
    else
      echo "     ✗ Docker DNS resolution: FAILED (cinepop.com.br)"
    fi

    echo "     > Testing Docker HTTP connectivity:"
    if docker run --rm alpine sh -c "timeout 10 wget -q --spider https://cinepop.com.br/feed" > /dev/null 2>&1; then
      echo "     ✓ Docker HTTP/HTTPS: OK (cinepop.com.br/feed)"
    else
      echo "     ✗ Docker HTTP/HTTPS: FAILED (cinepop.com.br/feed)"
    fi

    echo "     > Testing staging container DNS (if running):"
    if docker ps --format "table {{.Names}}" | grep -q digitalclip-app-staging; then
      if docker exec digitalclip-app-staging php -r "echo gethostbyname('cinepop.com.br');" 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+'; then
        echo "     ✓ Staging container DNS: OK (cinepop.com.br)"
      else
        echo "     ✗ Staging container DNS: FAILED (cinepop.com.br)"
      fi

      if docker exec digitalclip-app-staging curl -I --connect-timeout 10 --max-time 15 https://cinepop.com.br/feed > /dev/null 2>&1; then
        echo "     ✓ Staging container HTTP: OK (cinepop.com.br/feed)"
      else
        echo "     ✗ Staging container HTTP: FAILED (cinepop.com.br/feed)"
      fi
    fi
  fi

  echo "     > DNS and connectivity test completed"
}

function qfw_help {
  echo "qFirewall usage: ./qfw {command}"
  echo ""
  echo "Commands:"
  echo "  start     Start the firewall and save rules for persistence"
  echo "  stop      Stop the firewall and remove all rules"
  echo "  status    Show current firewall rules"
  echo "  test-dns  Test DNS resolution and HTTP connectivity for containers"
  echo ""
  echo "Features:"
  echo "  - IPv4 and IPv6 protection"
  echo "  - Admin port security (81, 9334, 8000)"
  echo "  - Docker compatibility with proper FORWARD rules"
  echo "  - Enhanced DNS support for containers"
  echo "  - Priority DNS rules for Docker networks"
  echo "  - Rule persistence across reboots"
  exit 1
}

function qfw_seeya {
  echo "     > Thanks for using qFirewall (qfw) v0.2. Have a good day."
  echo ""
  echo ""
}

function qfw_separator {
  echo ""
  echo ""
  echo "===================== qFirewall (qfw) v0.2 ====================="
  echo ""
}

function qfw_reset {
  # Preserve Docker chains when resetting
  /sbin/iptables -F INPUT
  /sbin/iptables -F OUTPUT

  # Only flush FORWARD if Docker is not running
  if ! systemctl is-active --quiet docker; then
    /sbin/iptables -F FORWARD
  fi

  /sbin/iptables -X
  if ! systemctl is-active --quiet docker; then
    /sbin/iptables -t nat -F
    /sbin/iptables -t nat -X
  fi

  /sbin/iptables -t mangle -F
  /sbin/iptables -t mangle -X

  /sbin/iptables -P INPUT ACCEPT
  /sbin/iptables -P FORWARD ACCEPT
  /sbin/iptables -P OUTPUT ACCEPT
}

function qfw_start {
  qfw_separator
  echo "     > Starting qFirewall..."
  qfw_clean
  echo "     > Loading the rules..."
  qfw_rules
  echo "     > Rules loaded"
  echo "     > qFirewall started"

  # Save rules for persistence (no need because it's started by a service)
  # if command -v iptables-save >/dev/null 2>&1; then
  #  echo "     > Saving firewall rules for persistence"
  #  mkdir -p /etc/iptables
  #  iptables-save > /etc/iptables/rules.v4
  #  ip6tables-save > /etc/iptables/rules.v6
  #fi
}

function qfw_clean {
  echo "     > Cleaning rules..."
  qfw_reset
  echo "     > Rules cleaned"
}

function qfw_stop {
  qfw_separator
  echo "     > Stopping qFirewall..."
  qfw_clean
  echo "     > qFirewall stopped"
}

function qfw_status {
  qfw_separator
  echo "     > Current iptables rules:"
  echo ""
  /sbin/iptables -L -n -v
}

# #######################################################################
# ## Main

case "$1" in
  start)
  qfw_start
  ;;
  stop)
  qfw_stop
  ;;
  status)
  qfw_status
  ;;
  test-dns)
  qfw_test_dns
  ;;
  *)
  qfw_help
  exit 1
  ;;
esac

qfw_seeya
exit 0
