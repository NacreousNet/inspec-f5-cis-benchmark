#tfimport-terraform import google_compute_instance.f5_big_ip_adc_hourly_good_25mbps_1_vm  __project__/europe-west2-b/f5-big-ip-adc-hourly-good-25mbps-1-vm
resource "google_compute_instance" "f5_big_ip_adc_hourly_good_25mbps_1_vm" {
  provider = google-beta

  name = "f5-big-ip-adc-hourly-good-25mbps-1-vm"
  can_ip_forward = false
  zone = "europe-west2-b"
  machine_type = "n1-standard-2"
  tags = [
    "f5-big-ip-adc-hourly-good-25mbps-1-deployment"
  ]
  boot_disk {
    device_name = "autogen-vm-tmpl-boot-disk"
    auto_delete = true
    initialize_params {
      size = 41
      image = "https://www.googleapis.com/compute/v1/projects/f5-7626-networks-public/global/images/f5-bigip-14-1-5-3-0-0-5-payg-good-25mbps-221225181734"
      type = "pd-standard"
    }
  }
  network_interface {
    network = "https://www.googleapis.com/compute/v1/projects/f5-terraform-344519/global/networks/default"
    subnetwork = "https://www.googleapis.com/compute/v1/projects/f5-terraform-344519/regions/europe-west2/subnetworks/default"
    access_config {
    }
  }
  metadata = {
    google-monitoring-enable = "0"
    google-logging-enable = "0"
  }
  service_account {
    email = "default"
    scopes = ["https://www.googleapis.com/auth/cloud.useraccounts.readonly", "https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write"]
  }
}

#tfimport-terraform import google_compute_firewall.f5_big_ip_adc_hourly_good_25mbps_1_tcp_22  __project__/f5-big-ip-adc-hourly-good-25mbps-1-tcp-22
resource "google_compute_firewall" "f5_big_ip_adc_hourly_good_25mbps_1_tcp_22" {
  provider = google-beta

  name = "f5-big-ip-adc-hourly-good-25mbps-1-tcp-22"
  source_ranges = [
    "0.0.0.0/0"
  ]
  target_tags = [
    "f5-big-ip-adc-hourly-good-25mbps-1-deployment"
  ]
  network = "https://www.googleapis.com/compute/v1/projects/f5-terraform-344519/global/networks/default"
  allow {
    protocol = "TCP"
    ports = ["22"]
  }
}

#tfimport-terraform import google_compute_firewall.f5_big_ip_adc_hourly_good_25mbps_1_tcp_8443  __project__/f5-big-ip-adc-hourly-good-25mbps-1-tcp-8443
resource "google_compute_firewall" "f5_big_ip_adc_hourly_good_25mbps_1_tcp_8443" {
  provider = google-beta

  name = "f5-big-ip-adc-hourly-good-25mbps-1-tcp-8443"
  source_ranges = [
    "0.0.0.0/0"
  ]
  target_tags = [
    "f5-big-ip-adc-hourly-good-25mbps-1-deployment"
  ]
  network = "https://www.googleapis.com/compute/v1/projects/f5-terraform-344519/global/networks/default"
  allow {
    protocol = "TCP"
    ports = ["8443"]
  }
}
