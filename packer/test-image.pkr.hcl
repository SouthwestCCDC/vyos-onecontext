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
      # Add DNS server through vyos-hostsd with system tag (survives regeneration)
      "sudo /usr/bin/vyos-hostsd-client --add-name-servers 10.0.2.3 --tag system --apply",
      # Prefer IPv4 over IPv6 (QEMU SLIRP doesn't support IPv6)
      "echo 'precedence ::ffff:0:0/96 100' | sudo tee -a /etc/gai.conf",
      # Verify DNS is working before proceeding
      "for i in $(seq 1 10); do getent ahostsv4 astral.sh && break; echo \"DNS attempt $i failed, retrying...\"; sleep 5; done",
      "getent ahostsv4 astral.sh > /dev/null || { echo 'ERROR: DNS resolution failed'; exit 1; }"
    ]
  }

  # Create venv and install the package using uv
  provisioner "shell" {
    inline = [
      # Install uv with retry (force IPv4 - QEMU SLIRP doesn't support IPv6)
      "curl -4 --retry 5 --retry-delay 5 --retry-connrefused -LsSf https://astral.sh/uv/install.sh | sudo UV_INSTALLER_DOWNLOAD_TIMEOUT=120 sh",
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
