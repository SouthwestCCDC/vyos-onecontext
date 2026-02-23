# VyOS Test Image for Integration Testing
#
# Builds a VyOS image with vyos-onecontext installed from the current checkout.
# Used by CI to create a testable image for QEMU integration tests.
#
# Usage:
#   packer init .
#   packer build -var "base_image=vyos-sagitta-base.qcow2" .
#
# Prerequisites:
#   - Base VyOS Sagitta qcow2 with SSH enabled (from artifacts server)
#   - KVM support (/dev/kvm)

packer {
  required_plugins {
    qemu = {
      version = "~> 1.1"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "base_image" {
  type        = string
  description = "Path to VyOS Sagitta base image"
}

variable "vyos_password" {
  type        = string
  default     = "vyos"
  description = "Password for vyos user (must match base image)"
  sensitive   = true
}

variable "headless" {
  type        = bool
  default     = true
  description = "Run build without display"
}

variable "source_dir" {
  type        = string
  default     = ".."
  description = "Path to vyos-onecontext source directory"
}

# =============================================================================
# Source
# =============================================================================

source "qemu" "test" {
  vm_name          = "vyos-onecontext-test.qcow2"
  output_directory = "output"
  format           = "qcow2"
  accelerator      = "kvm"
  headless         = var.headless

  # Boot from base image
  iso_url      = var.base_image
  iso_checksum = "none"
  disk_image   = true
  disk_size    = 4096

  memory = 2048
  cpus   = 2

  # Base image has SSH enabled and DHCP on eth0
  boot_wait = "45s"

  communicator = "ssh"
  ssh_username = "vyos"
  ssh_password = var.vyos_password
  ssh_timeout  = "5m"

  shutdown_command = "sudo poweroff"
}

# =============================================================================
# Build
# =============================================================================

build {
  sources = ["source.qemu.test"]

  # Create installation directory and temp source directory
  provisioner "shell" {
    inline = [
      "sudo mkdir -p /opt/vyos-onecontext",
      "mkdir -p /tmp/vyos-onecontext-src/src"
    ]
  }

  # Copy only the necessary files for installation (not .git, .venv, etc.)
  provisioner "file" {
    source      = "${var.source_dir}/src/"
    destination = "/tmp/vyos-onecontext-src/src/"
  }

  provisioner "file" {
    source      = "${var.source_dir}/pyproject.toml"
    destination = "/tmp/vyos-onecontext-src/pyproject.toml"
  }

  provisioner "file" {
    source      = "${var.source_dir}/uv.lock"
    destination = "/tmp/vyos-onecontext-src/uv.lock"
  }

  provisioner "file" {
    source      = "${var.source_dir}/README.md"
    destination = "/tmp/vyos-onecontext-src/README.md"
  }

  # Configure DNS for build-time network access
  # VyOS has vyos-hostsd which manages /etc/resolv.conf. Writing to resolv.conf
  # directly causes race conditions as vyos-hostsd will overwrite it. Instead,
  # we add DNS servers through vyos-hostsd-client with the "system" tag, which
  # ensures they're included in resolv.conf and persist across any regeneration.
  # We use QEMU SLIRP's DNS proxy (10.0.2.3) which forwards to the host resolver.
  provisioner "shell" {
    inline = [
      # =======================================================================
      # DNS DIAGNOSTIC INSTRUMENTATION
      # This captures DNS state at key points to debug intermittent failures.
      # See: https://github.com/SouthwestCCDC/vyos-onecontext/issues/108
      # =======================================================================
      <<-DIAG
      dns_diag() {
        local label="$1"
        echo ""
        echo "======== DNS DIAGNOSTICS: $label ========"
        echo "--- Timestamp: $(date -Iseconds) ---"
        echo ""
        echo "--- /etc/resolv.conf ---"
        cat /etc/resolv.conf 2>/dev/null || echo "(file not found or empty)"
        echo ""
        echo "--- /etc/gai.conf ---"
        cat /etc/gai.conf 2>/dev/null || echo "(file not found or empty)"
        echo ""
        echo "--- Network interfaces ---"
        ip -4 addr show 2>/dev/null | grep -E "^[0-9]+:|inet " || echo "(no IPv4 addresses)"
        echo ""
        echo "--- Default route ---"
        ip -4 route show default 2>/dev/null || echo "(no default route)"
        echo ""
        echo "--- Test DNS resolution (IPv4 only) ---"
        echo -n "  astral.sh (getent ahostsv4): "
        getent ahostsv4 astral.sh 2>&1 | head -1 || echo "FAILED"
        echo -n "  github.com (getent ahostsv4): "
        getent ahostsv4 github.com 2>&1 | head -1 || echo "FAILED"
        echo ""
        echo "--- Test DNS resolution (dual-stack) ---"
        echo -n "  astral.sh (getent ahosts): "
        getent ahosts astral.sh 2>&1 | head -1 || echo "FAILED"
        echo -n "  github.com (getent ahosts): "
        getent ahosts github.com 2>&1 | head -1 || echo "FAILED"
        echo ""
        echo "--- vyos-hostsd service status ---"
        systemctl is-active vyos-hostsd 2>/dev/null || echo "(service check failed)"
        echo ""
        echo "======== END DNS DIAGNOSTICS ========"
        echo ""
      }
      DIAG
      ,
      # Capture initial DNS state before any changes
      "dns_diag 'BEFORE DNS CONFIGURATION'",
      # Add DNS server through vyos-hostsd with system tag (survives regeneration)
      "echo 'Calling vyos-hostsd-client to add DNS server...'",
      "sudo /usr/bin/vyos-hostsd-client --add-name-servers 10.0.2.3 --tag system --apply",
      "echo 'vyos-hostsd-client completed with exit code: '$?",
      # Wait for vyos-hostsd to settle and avoid triggering network reconfiguration
      # See: https://github.com/SouthwestCCDC/vyos-onecontext/issues/108
      "echo 'Waiting for vyos-hostsd to settle...'",
      "sleep 5",
      # Capture state after vyos-hostsd-client
      "dns_diag 'AFTER vyos-hostsd-client'",
      # Prefer IPv4 over IPv6 (QEMU SLIRP doesn't support IPv6)
      "echo 'precedence ::ffff:0:0/96 100' | sudo tee -a /etc/gai.conf",
      # Capture state after gai.conf modification
      "dns_diag 'AFTER gai.conf modification'",
      # Verify DNS is working before proceeding
      "for i in $(seq 1 10); do getent ahostsv4 astral.sh && break; echo \"DNS attempt $i failed, retrying...\"; sleep 5; done",
      "getent ahostsv4 astral.sh > /dev/null || { dns_diag 'DNS VERIFICATION FAILED'; exit 1; }",
      "echo 'DNS configuration complete - verification passed'"
    ]
  }

  # Create venv and install the package using uv
  provisioner "shell" {
    inline = [
      # =======================================================================
      # DNS DIAGNOSTIC INSTRUMENTATION (continued)
      # Redefine the function since each provisioner is a new shell session
      # =======================================================================
      <<-DIAG
      dns_diag() {
        local label="$1"
        echo ""
        echo "======== DNS DIAGNOSTICS: $label ========"
        echo "--- Timestamp: $(date -Iseconds) ---"
        echo ""
        echo "--- /etc/resolv.conf ---"
        cat /etc/resolv.conf 2>/dev/null || echo "(file not found or empty)"
        echo ""
        echo "--- /etc/gai.conf ---"
        cat /etc/gai.conf 2>/dev/null || echo "(file not found or empty)"
        echo ""
        echo "--- Network interfaces ---"
        ip -4 addr show 2>/dev/null | grep -E "^[0-9]+:|inet " || echo "(no IPv4 addresses)"
        echo ""
        echo "--- Default route ---"
        ip -4 route show default 2>/dev/null || echo "(no default route)"
        echo ""
        echo "--- Test DNS resolution (IPv4 only) ---"
        echo -n "  astral.sh (getent ahostsv4): "
        getent ahostsv4 astral.sh 2>&1 | head -1 || echo "FAILED"
        echo -n "  github.com (getent ahostsv4): "
        getent ahostsv4 github.com 2>&1 | head -1 || echo "FAILED"
        echo ""
        echo "--- Test DNS resolution (dual-stack) ---"
        echo -n "  astral.sh (getent ahosts): "
        getent ahosts astral.sh 2>&1 | head -1 || echo "FAILED"
        echo -n "  github.com (getent ahosts): "
        getent ahosts github.com 2>&1 | head -1 || echo "FAILED"
        echo ""
        echo "--- vyos-hostsd service status ---"
        systemctl is-active vyos-hostsd 2>/dev/null || echo "(service check failed)"
        echo ""
        echo "======== END DNS DIAGNOSTICS ========"
        echo ""
      }
      DIAG
      ,
      # =======================================================================
      # NETWORK READINESS CHECK
      # Ensure network is up before attempting downloads. Sometimes eth0
      # disappears between provisioners due to DHCP/vyos-hostsd interactions.
      # See: https://github.com/SouthwestCCDC/vyos-onecontext/issues/108
      # =======================================================================
      <<-NETWAIT
      echo "Checking network readiness before proceeding..."
      for attempt in $(seq 1 30); do
        # Level 1: Check if eth0 interface exists
        if ! ip link show eth0 >/dev/null 2>&1; then
          echo "Waiting for eth0 interface to exist (attempt $attempt/30)..."
        # Level 2: Check if eth0 has an IPv4 address
        elif ! ip -4 addr show eth0 2>/dev/null | grep -q "inet "; then
          echo "Waiting for eth0 to obtain IPv4 address (attempt $attempt/30)..."
        # Level 3: Check if default route exists
        elif ! ip -4 route show default 2>/dev/null | grep -q "default"; then
          echo "Waiting for default route (attempt $attempt/30)..."
        else
          echo "Network is ready (attempt $attempt/30)"
          break
        fi

        if [ "$attempt" -eq 30 ]; then
          echo "ERROR: Network failed to become ready after 30 attempts"
          dns_diag 'NETWORK READINESS CHECK FAILED'
          exit 1
        fi

        sleep 2
      done
      NETWAIT
      ,
      # Capture DNS state at start of this provisioner
      "dns_diag 'START OF UV INSTALL PROVISIONER'",
      # Download uv installer with diagnostics on failure
      <<-INSTALL
      echo "Downloading uv installer..."
      if ! curl -4 --retry 5 --retry-delay 5 --retry-all-errors -LsSf https://astral.sh/uv/install.sh -o /tmp/uv-install.sh; then
        echo "ERROR: Failed to download uv installer"
        dns_diag 'CURL DOWNLOAD FAILED'
        exit 1
      fi
      echo "uv installer downloaded successfully"

      # Run installer with error handling
      echo "Running uv installer..."
      if ! sudo UV_INSTALLER_DOWNLOAD_TIMEOUT=120 sh /tmp/uv-install.sh; then
        echo "ERROR: uv installer failed"
        dns_diag 'UV INSTALLER FAILED'
        exit 1
      fi
      echo "uv installed successfully"
      rm -f /tmp/uv-install.sh
      INSTALL
      ,
      # Create virtual environment and install package
      "sudo /root/.local/bin/uv venv /opt/vyos-onecontext/venv",
      "sudo /root/.local/bin/uv pip install --python /opt/vyos-onecontext/venv/bin/python /tmp/vyos-onecontext-src/",
      # Clean up source directory
      "sudo rm -rf /tmp/vyos-onecontext-src"
    ]
  }

  # Copy and install the boot script
  provisioner "file" {
    source      = "${var.source_dir}/scripts/vyos-onecontext-boot.sh"
    destination = "/tmp/vyos-onecontext-boot.sh"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/vyos-onecontext-boot.sh /opt/vyos-onecontext/boot.sh",
      "sudo chmod 755 /opt/vyos-onecontext/boot.sh"
    ]
  }

  # Install the postconfig bootup script (runs after config load)
  # We keep a minimal config.boot so postconfig runs
  provisioner "file" {
    source      = "${var.source_dir}/packer/files/vyos-postconfig-bootup.script"
    destination = "/tmp/vyos-postconfig-bootup.script"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/vyos-postconfig-bootup.script /config/scripts/vyos-postconfig-bootup.script",
      "sudo chmod 755 /config/scripts/vyos-postconfig-bootup.script"
    ]
  }

  # NOTE: We keep the existing config.boot from the base image.
  # This ensures VyOS boots normally and runs postconfig scripts.
  # Contextualization will apply settings on top of the base config.
}
