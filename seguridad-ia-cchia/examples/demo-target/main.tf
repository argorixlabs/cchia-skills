terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

provider "google" {
  project = "cchia-demo"
}

resource "google_project_iam_member" "agent_owner" {
  project = "cchia-demo"
  role    = "roles/owner"
  member  = "serviceAccount:agent@cchia-demo.iam.gserviceaccount.com"
}
