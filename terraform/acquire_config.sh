# Configure your project/deployment
DEPLOYMENT_NAME=f5-big-ip-adc-hourly-good-25mbps-1
PROJECT_ID=f5-terraform-344519

# Fetch the latest manifest for the given deployment
gcloud deployment-manager deployments describe $DEPLOYMENT_NAME \
  --project $PROJECT_ID --format="value(deployment.manifest)"
# https://www.googleapis.com/deploymentmanager/v2/projects/$PROJECT_ID/global/deployments/bq/manifests/manifest-1675529636170

# The manifest name is the last path segment from the URI
# in the above command output
MANIFEST_NAME="manifest-1675529636170"
# Save the expanded manifest to deployment.yaml
gcloud deployment-manager manifests describe $MANIFEST_NAME \
  --deployment $DEPLOYMENT_NAME --project $PROJECT_ID \
  --format="value(expandedConfig)" > deployment.yaml
