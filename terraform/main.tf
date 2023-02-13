provider "google" {
  project = "f5-terraform-344519"
}


resource "google_compute_instance" "f5_big_ip_adc_hourly_good_25mbps_1_vm" {
  # (resource arguments)
}


resource "google_compute_firewall" "f5_big_ip_adc_hourly_good_25mbps_1_tcp_22" {
  # (resource arguments)
}


resource "google_compute_firewall" "f5_big_ip_adc_hourly_good_25mbps_1_tcp_8443" {
  # (resource arguments)
}