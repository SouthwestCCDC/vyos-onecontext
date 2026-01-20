# VyOS Test Image - DNS Diagnostic Version
#
# This is a diagnostic version of test-image.pkr.hcl that runs extensive
# network/DNS diagnostics before attempting any downloads.
#
# Usage:
#   packer init .
#   packer build -var "base_image=vyos-sagitta-base.qcow2" test-image-diagnostic.pkr.hcl

packer {
  required_plugins {
    qemu = {
      version = "~> 1.1"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

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

source "qemu" "diagnostic" {
  vm_name          = "vyos-diagnostic.qcow2"
  output_directory = "output-diagnostic"
  format           = "qcow2"
  accelerator      = "kvm"
  headless         = var.headless

  iso_url      = var.base_image
  iso_checksum = "none"
  disk_image   = true
  disk_size    = 4096

  memory = 2048
  cpus   = 2

  boot_wait = "45s"

  communicator = "ssh"
  ssh_username = "vyos"
  ssh_password = var.vyos_password
  ssh_timeout  = "5m"

  shutdown_command = "sudo poweroff"
}

build {
  sources = ["source.qemu.diagnostic"]

  # Step 1: Capture initial network state (before any DNS config changes)
  provisioner "shell" {
    inline = [
      "echo '=== INITIAL STATE (before any changes) ==='",
      "echo '--- /etc/resolv.conf ---'",
      "cat /etc/resolv.conf",
      "echo '--- Network interfaces ---'",
      "ip addr show",
      "echo '--- Routes ---'",
      "ip route show",
      "echo '--- Initial DNS test with default config ---'",
      "getent ahostsv4 google.com || echo 'Initial DNS test failed'",
    ]
  }

  # Step 2: Configure DNS to use Google DNS (same as production)
  provisioner "shell" {
    inline = [
      "echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf",
      "echo 'nameserver 8.8.4.4' | sudo tee -a /etc/resolv.conf",
      "echo 'precedence ::ffff:0:0/96 100' | sudo tee -a /etc/gai.conf",
      "echo '--- Updated resolv.conf ---'",
      "cat /etc/resolv.conf",
    ]
  }

  # Step 3: Run comprehensive DNS diagnostics
  provisioner "file" {
    source      = "scripts/diagnose-dns.sh"
    destination = "/tmp/diagnose-dns.sh"
  }

  provisioner "shell" {
    inline = [
      "chmod +x /tmp/diagnose-dns.sh",
      "/tmp/diagnose-dns.sh 2>&1",
    ]
  }

  # Step 4: Attempt the actual download (this is what fails in CI)
  provisioner "shell" {
    inline = [
      "echo '=== ATTEMPTING ACTUAL DOWNLOAD ==='",
      "echo '--- Checking DNS one more time ---'",
      "getent ahostsv4 astral.sh || echo 'DNS check failed'",
      "echo '--- Attempting curl to astral.sh ---'",
      "curl -4 -v --connect-timeout 30 --max-time 60 -LsSf https://astral.sh/uv/install.sh -o /tmp/uv-install.sh || echo 'curl failed with exit code $?'",
      "echo '--- Download result ---'",
      "ls -la /tmp/uv-install.sh 2>/dev/null || echo 'File not downloaded'",
      "head -20 /tmp/uv-install.sh 2>/dev/null || echo 'Cannot read file'",
    ]
  }

  # Step 5: Even if download fails, capture final state
  provisioner "shell" {
    inline = [
      "echo '=== FINAL STATE ==='",
      "echo 'Diagnostic build complete. Check output above for DNS issues.'",
    ]
  }
}
