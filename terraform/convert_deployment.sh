CONVERTED_RESOURCES=deployment.hcl

docker run --rm -it --workdir=/convert \
--volume=$(pwd):/convert \
$DM_CONVERT_IMAGE \
--config deployment.yaml \
--output_format TF \
--output_file deployment.hcl \
--output_tf_import_file deployment.tf \
--deployment_name f5-big-ip-adc-hourly-good-25mbps-1 \
--project_id $PROJECT_ID

