use clap::{App, Arg};
use csv::ReaderBuilder;
use serde::Deserialize;
use std::error::Error;
use std::fs;

#[derive(Debug, Deserialize)]
struct CSVRecord {
    #[serde(rename = "Identifier")]
    identifier: String,
    #[serde(rename = "Resource type")]
    resource_type: String,
    #[serde(rename = "Tag:Name")]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TerraformMapEntry {
    #[serde(rename = "TF")]
    tf: String,
    #[serde(rename = "AWS_RT")]
    aws_rt: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("re-importer")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Tadeo Armenta <contact@tadeoarmenta.com>")
        .about("Small tool to create Terraform import blocks based on AWS Resource Explorer exported CSV files.")
        .arg(Arg::with_name("csv-file")
             .long("csv-file")
             .takes_value(true)
             .required(true)
             .help("Path to the exported CSV file from AWS resource explorer"))
        .arg(Arg::with_name("resource-map")
             .long("resource-map")
             .takes_value(true)
             .help("Path to the JSON file with mapping between AWS resource types and Terraform resource types. Uses default mapping if not provided"))
        .arg(Arg::with_name("output-file")
             .long("output-file")
             .takes_value(true)
             .help("Path to the output Terraform import file (default: ./imports.tf)"))
        .get_matches();

    let csv_file_path = matches.value_of("csv-file").unwrap();
    let resource_map_path = matches.value_of("resource-map");
    let output_file_path = matches.value_of("output-file").unwrap_or("./imports.tf");

    let terraform_map = match resource_map_path {
        Some(path) => read_terraform_map_from_file(path)?,
        None => read_terraform_map_from_default()?,
    };
    let records = read_csv_records(csv_file_path)?;
    let output = generate_output(records, &terraform_map)?;

    fs::write(output_file_path, output)?;

    Ok(())
}

fn read_terraform_map_from_file(path: &str) -> Result<Vec<TerraformMapEntry>, Box<dyn Error>> {
    let data = fs::read_to_string(path)?;
    let map: Vec<TerraformMapEntry> = serde_json::from_str(&data)?;
    Ok(map)
}

fn read_terraform_map_from_default() -> Result<Vec<TerraformMapEntry>, Box<dyn Error>> {
    let default_json = r#"
    [
        {
            "TF": "aws_accessanalyzer_analyzer",
            "AWS": "AWS::AccessAnalyzer::Analyzer",
            "AWS_RT": "accessanalyzer:analyzer"
        },
        {
            "TF": "aws_acm_certificate",
            "AWS": "AWS::CertificateManager::Certificate",
            "AWS_RT": "certificatemanager:certificate"
        },
        {
            "TF": "aws_acmpca_certificate",
            "AWS": "AWS::ACMPCA::Certificate",
            "AWS_RT": "acmpca:certificate"
        },
        {
            "TF": "aws_acmpca_certificate_authority",
            "AWS": "AWS::ACMPCA::CertificateAuthority",
            "AWS_RT": "acmpca:certificate-authority"
        },
        {
            "TF": "aws_amplify_app",
            "AWS": "AWS::Amplify::App",
            "AWS_RT": "amplify:app"
        },
        {
            "TF": "aws_amplify_branch",
            "AWS": "AWS::Amplify::Branch",
            "AWS_RT": "amplify:branch"
        },
        {
            "TF": "aws_api_gateway_account",
            "AWS": "AWS::ApiGateway::Account",
            "AWS_RT": "apigateway:account"
        },
        {
            "TF": "aws_api_gateway_api_key",
            "AWS": "AWS::ApiGateway::ApiKey",
            "AWS_RT": "apigateway:api-key"
        },
        {
            "TF": "aws_api_gateway_authorizer",
            "AWS": "AWS::ApiGateway::Authorizer",
            "AWS_RT": "apigateway:authorizer"
        },
        {
            "TF": "aws_api_gateway_base_path_mapping",
            "AWS": "AWS::ApiGateway::BasePathMapping",
            "AWS_RT": "apigateway:base-path-mapping"
        },
        {
            "TF": "aws_api_gateway_client_certificate",
            "AWS": "AWS::ApiGateway::ClientCertificate",
            "AWS_RT": "apigateway:client-certificate"
        },
        {
            "TF": "aws_api_gateway_deployment",
            "AWS": "AWS::ApiGateway::Deployment",
            "AWS_RT": "apigateway:deployment"
        },
        {
            "TF": "aws_api_gateway_documentation_part",
            "AWS": "AWS::ApiGateway::DocumentationPart",
            "AWS_RT": "apigateway:documentation-part"
        },
        {
            "TF": "aws_api_gateway_documentation_version",
            "AWS": "AWS::ApiGateway::DocumentationVersion",
            "AWS_RT": "apigateway:documentation-version"
        },
        {
            "TF": "aws_api_gateway_domain_name",
            "AWS": "AWS::ApiGateway::DomainName",
            "AWS_RT": "apigateway:domain-name"
        },
        {
            "TF": "aws_api_gateway_gateway_response",
            "AWS": "AWS::ApiGateway::GatewayResponse",
            "AWS_RT": "apigateway:gateway-response"
        },
        {
            "TF": "aws_api_gateway_method",
            "AWS": "AWS::ApiGateway::Method",
            "AWS_RT": "apigateway:method"
        },
        {
            "TF": "aws_api_gateway_model",
            "AWS": "AWS::ApiGateway::Model",
            "AWS_RT": "apigateway:model"
        },
        {
            "TF": "aws_api_gateway_request_validator",
            "AWS": "AWS::ApiGateway::RequestValidator",
            "AWS_RT": "apigateway:request-validator"
        },
        {
            "TF": "aws_api_gateway_resource",
            "AWS": "AWS::ApiGateway::Resource",
            "AWS_RT": "apigateway:resource"
        },
        {
            "TF": "aws_api_gateway_rest_api",
            "AWS": "AWS::ApiGateway::RestApi",
            "AWS_RT": "apigateway:rest-api"
        },
        {
            "TF": "aws_api_gateway_stage",
            "AWS": "AWS::ApiGateway::Stage",
            "AWS_RT": "apigateway:stage"
        },
        {
            "TF": "aws_api_gateway_usage_plan",
            "AWS": "AWS::ApiGateway::UsagePlan",
            "AWS_RT": "apigateway:usage-plan"
        },
        {
            "TF": "aws_api_gateway_usage_plan_key",
            "AWS": "AWS::ApiGateway::UsagePlanKey",
            "AWS_RT": "apigateway:usage-plan-key"
        },
        {
            "TF": "aws_api_gateway_vpc_link",
            "AWS": "AWS::ApiGateway::VpcLink",
            "AWS_RT": "apigateway:vpc-link"
        },
        {
            "TF": "aws_apigatewayv2_api",
            "AWS": "AWS::ApiGatewayV2::Api",
            "AWS_RT": "apigatewayv2:api"
        },
        {
            "TF": "aws_apigatewayv2_api_mapping",
            "AWS": "AWS::ApiGatewayV2::ApiMapping",
            "AWS_RT": "apigatewayv2:api-mapping"
        },
        {
            "TF": "aws_apigatewayv2_authorizer",
            "AWS": "AWS::ApiGatewayV2::Authorizer",
            "AWS_RT": "apigatewayv2:authorizer"
        },
        {
            "TF": "aws_apigatewayv2_deployment",
            "AWS": "AWS::ApiGatewayV2::Deployment",
            "AWS_RT": "apigatewayv2:deployment"
        },
        {
            "TF": "aws_apigatewayv2_domain_name",
            "AWS": "AWS::ApiGatewayV2::DomainName",
            "AWS_RT": "apigatewayv2:domain-name"
        },
        {
            "TF": "aws_apigatewayv2_integration",
            "AWS": "AWS::ApiGatewayV2::Integration",
            "AWS_RT": "apigatewayv2:integration"
        },
        {
            "TF": "aws_apigatewayv2_integration_response",
            "AWS": "AWS::ApiGatewayV2::IntegrationResponse",
            "AWS_RT": "apigatewayv2:integration-response"
        },
        {
            "TF": "aws_apigatewayv2_model",
            "AWS": "AWS::ApiGatewayV2::Model",
            "AWS_RT": "apigatewayv2:model"
        },
        {
            "TF": "aws_apigatewayv2_route",
            "AWS": "AWS::ApiGatewayV2::Route",
            "AWS_RT": "apigatewayv2:route"
        },
        {
            "TF": "aws_apigatewayv2_route_response",
            "AWS": "AWS::ApiGatewayV2::RouteResponse",
            "AWS_RT": "apigatewayv2:route-response"
        },
        {
            "TF": "aws_apigatewayv2_stage",
            "AWS": "AWS::ApiGatewayV2::Stage",
            "AWS_RT": "apigatewayv2:stage"
        },
        {
            "TF": "aws_apigatewayv2_vpc_link",
            "AWS": "AWS::ApiGatewayV2::VpcLink",
            "AWS_RT": "apigatewayv2:vpc-link"
        },
        {
            "TF": "aws_appautoscaling_policy",
            "AWS": "AWS::ApplicationAutoScaling::ScalingPolicy",
            "AWS_RT": "applicationautoscaling:scaling-policy"
        },
        {
            "TF": "aws_appautoscaling_target",
            "AWS": "AWS::ApplicationAutoScaling::ScalableTarget",
            "AWS_RT": "applicationautoscaling:scalable-target"
        },
        {
            "TF": "aws_appconfig_application",
            "AWS": "AWS::AppConfig::Application",
            "AWS_RT": "appconfig:application"
        },
        {
            "TF": "aws_appconfig_configuration_profile",
            "AWS": "AWS::AppConfig::ConfigurationProfile",
            "AWS_RT": "appconfig:configuration-profile"
        },
        {
            "TF": "aws_appconfig_deployment",
            "AWS": "AWS::AppConfig::Deployment",
            "AWS_RT": "appconfig:deployment"
        },
        {
            "TF": "aws_appconfig_deployment_strategy",
            "AWS": "AWS::AppConfig::DeploymentStrategy",
            "AWS_RT": "appconfig:deployment-strategy"
        },
        {
            "TF": "aws_appconfig_environment",
            "AWS": "AWS::AppConfig::Environment",
            "AWS_RT": "appconfig:environment"
        },
        {
            "TF": "aws_appconfig_hosted_configuration_version",
            "AWS": "AWS::AppConfig::HostedConfigurationVersion",
            "AWS_RT": "appconfig:hosted-configuration-version"
        },
        {
            "TF": "aws_appmesh_gateway_route",
            "AWS": "AWS::AppMesh::GatewayRoute",
            "AWS_RT": "appmesh:gateway-route"
        },
        {
            "TF": "aws_appmesh_mesh",
            "AWS": "AWS::AppMesh::Mesh",
            "AWS_RT": "appmesh:mesh"
        },
        {
            "TF": "aws_appmesh_route",
            "AWS": "AWS::AppMesh::Route",
            "AWS_RT": "appmesh:route"
        },
        {
            "TF": "aws_appmesh_virtual_gateway",
            "AWS": "AWS::AppMesh::VirtualGateway",
            "AWS_RT": "appmesh:virtual-gateway"
        },
        {
            "TF": "aws_appmesh_virtual_node",
            "AWS": "AWS::AppMesh::VirtualNode",
            "AWS_RT": "appmesh:virtual-node"
        },
        {
            "TF": "aws_appmesh_virtual_router",
            "AWS": "AWS::AppMesh::VirtualRouter",
            "AWS_RT": "appmesh:virtual-router"
        },
        {
            "TF": "aws_appmesh_virtual_service",
            "AWS": "AWS::AppMesh::VirtualService",
            "AWS_RT": "appmesh:virtual-service"
        },
        {
            "TF": "aws_apprunner_service",
            "AWS": "AWS::AppRunner::Service",
            "AWS_RT": "apprunner:service"
        },
        {
            "TF": "aws_appstream_directory_config",
            "AWS": "AWS::AppStream::DirectoryConfig",
            "AWS_RT": "appstream:directory-config"
        },
        {
            "TF": "aws_appstream_fleet",
            "AWS": "AWS::AppStream::Fleet",
            "AWS_RT": "appstream:fleet"
        },
        {
            "TF": "aws_appstream_image_builder",
            "AWS": "AWS::AppStream::ImageBuilder",
            "AWS_RT": "appstream:image-builder"
        },
        {
            "TF": "aws_appstream_stack",
            "AWS": "AWS::AppStream::Stack",
            "AWS_RT": "appstream:stack"
        },
        {
            "TF": "aws_appstream_user",
            "AWS": "AWS::AppStream::User",
            "AWS_RT": "appstream:user"
        },
        {
            "TF": "aws_appsync_api_cache",
            "AWS": "AWS::AppSync::ApiCache",
            "AWS_RT": "appsync:api-cache"
        },
        {
            "TF": "aws_appsync_api_key",
            "AWS": "AWS::AppSync::ApiKey",
            "AWS_RT": "appsync:api-key"
        },
        {
            "TF": "aws_appsync_datasource",
            "AWS": "AWS::AppSync::DataSource",
            "AWS_RT": "appsync:data-source"
        },
        {
            "TF": "aws_appsync_domain_name",
            "AWS": "AWS::AppSync::DomainName",
            "AWS_RT": "appsync:domain-name"
        },
        {
            "TF": "aws_appsync_domain_name_api_association",
            "AWS": "AWS::AppSync::DomainNameApiAssociation",
            "AWS_RT": "appsync:domain-name-api-association"
        },
        {
            "TF": "aws_appsync_graphql_api",
            "AWS": "AWS::AppSync::GraphQLApi",
            "AWS_RT": "appsync:graph-ql-api"
        },
        {
            "TF": "aws_appsync_resolver",
            "AWS": "AWS::AppSync::Resolver",
            "AWS_RT": "appsync:resolver"
        },
        {
            "TF": "aws_athena_named_query",
            "AWS": "AWS::Athena::NamedQuery",
            "AWS_RT": "athena:named-query"
        },
        {
            "TF": "aws_athena_workgroup",
            "AWS": "AWS::Athena::WorkGroup",
            "AWS_RT": "athena:work-group"
        },
        {
            "TF": "aws_autoscaling_group",
            "AWS": "AWS::AutoScaling::AutoScalingGroup",
            "AWS_RT": "autoscaling:auto-scaling-group"
        },
        {
            "TF": "aws_autoscaling_lifecycle_hook",
            "AWS": "AWS::AutoScaling::LifecycleHook",
            "AWS_RT": "autoscaling:lifecycle-hook"
        },
        {
            "TF": "aws_autoscaling_policy",
            "AWS": "AWS::AutoScaling::ScalingPolicy",
            "AWS_RT": "autoscaling:scaling-policy"
        },
        {
            "TF": "aws_autoscaling_schedule",
            "AWS": "AWS::AutoScaling::ScheduledAction",
            "AWS_RT": "autoscaling:scheduled-action"
        },
        {
            "TF": "aws_autoscalingplans_scaling_plan",
            "AWS": "AWS::AutoScalingPlans::ScalingPlan",
            "AWS_RT": "autoscalingplans:scaling-plan"
        },
        {
            "TF": "aws_batch_compute_environment",
            "AWS": "AWS::Batch::ComputeEnvironment",
            "AWS_RT": "batch:compute-environment"
        },
        {
            "TF": "aws_batch_job_definition",
            "AWS": "AWS::Batch::JobDefinition",
            "AWS_RT": "batch:job-definition"
        },
        {
            "TF": "aws_batch_job_queue",
            "AWS": "AWS::Batch::JobQueue",
            "AWS_RT": "batch:job-queue"
        },
        {
            "TF": "aws_batch_scheduling_policy",
            "AWS": "AWS::Batch::SchedulingPolicy",
            "AWS_RT": "batch:scheduling-policy"
        },
        {
            "TF": "aws_budgets_budget",
            "AWS": "AWS::Budgets::Budget",
            "AWS_RT": "budgets:budget"
        },
        {
            "TF": "aws_cloud9_environment_ec2",
            "AWS": "AWS::Cloud9::EnvironmentEC2",
            "AWS_RT": "cloud9:environment-ec2"
        },
        {
            "TF": "aws_cloudformation_stack",
            "AWS": "AWS::CloudFormation::Stack",
            "AWS_RT": "cloudformation:stack"
        },
        {
            "TF": "aws_cloudformation_stack_set",
            "AWS": "AWS::CloudFormation::StackSet",
            "AWS_RT": "cloudformation:stack-set"
        },
        {
            "TF": "aws_cloudfront_cache_policy",
            "AWS": "AWS::CloudFront::CachePolicy",
            "AWS_RT": "cloudfront:cache-policy"
        },
        {
            "TF": "aws_cloudfront_distribution",
            "AWS": "AWS::CloudFront::Distribution",
            "AWS_RT": "cloudfront:distribution"
        },
        {
            "TF": "aws_cloudfront_function",
            "AWS": "AWS::CloudFront::Function",
            "AWS_RT": "cloudfront:function"
        },
        {
            "TF": "aws_cloudfront_key_group",
            "AWS": "AWS::CloudFront::KeyGroup",
            "AWS_RT": "cloudfront:key-group"
        },
        {
            "TF": "aws_cloudfront_origin_request_policy",
            "AWS": "AWS::CloudFront::OriginRequestPolicy",
            "AWS_RT": "cloudfront:origin-request-policy"
        },
        {
            "TF": "aws_cloudfront_public_key",
            "AWS": "AWS::CloudFront::PublicKey",
            "AWS_RT": "cloudfront:public-key"
        },
        {
            "TF": "aws_cloudfront_realtime_log_config",
            "AWS": "AWS::CloudFront::RealtimeLogConfig",
            "AWS_RT": "cloudfront:realtime-log-config"
        },
        {
            "TF": "aws_cloudfront_response_headers_policy",
            "AWS": "AWS::CloudFront::ResponseHeadersPolicy",
            "AWS_RT": "cloudfront:response-headers-policy"
        },
        {
            "TF": "aws_cloudwatch_composite_alarm",
            "AWS": "AWS::CloudWatch::CompositeAlarm",
            "AWS_RT": "cloudwatch:composite-alarm"
        },
        {
            "TF": "aws_cloudwatch_dashboard",
            "AWS": "AWS::CloudWatch::Dashboard",
            "AWS_RT": "cloudwatch:dashboard"
        },
        {
            "TF": "aws_cloudwatch_event_api_destination",
            "AWS": "AWS::Events::ApiDestination",
            "AWS_RT": "events:api-destination"
        },
        {
            "TF": "aws_cloudwatch_event_archive",
            "AWS": "AWS::Events::Archive",
            "AWS_RT": "events:archive"
        },
        {
            "TF": "aws_cloudwatch_event_connection",
            "AWS": "AWS::Events::Connection",
            "AWS_RT": "events:connection"
        },
        {
            "TF": "aws_cloudwatch_event_rule",
            "AWS": "AWS::Events::Rule",
            "AWS_RT": "events:rule"
        },
        {
            "TF": "aws_cloudwatch_log_destination",
            "AWS": "AWS::Logs::Destination",
            "AWS_RT": "logs:destination"
        },
        {
            "TF": "aws_cloudwatch_log_group",
            "AWS": "AWS::Logs::LogGroup",
            "AWS_RT": "logs:log-group"
        },
        {
            "TF": "aws_cloudwatch_log_metric_filter",
            "AWS": "AWS::Logs::MetricFilter",
            "AWS_RT": "logs:metric-filter"
        },
        {
            "TF": "aws_cloudwatch_log_resource_policy",
            "AWS": "AWS::Logs::ResourcePolicy",
            "AWS_RT": "logs:resource-policy"
        },
        {
            "TF": "aws_cloudwatch_log_stream",
            "AWS": "AWS::Logs::LogStream",
            "AWS_RT": "logs:log-stream"
        },
        {
            "TF": "aws_cloudwatch_log_subscription_filter",
            "AWS": "AWS::Logs::SubscriptionFilter",
            "AWS_RT": "logs:subscription-filter"
        },
        {
            "TF": "aws_cloudwatch_metric_alarm",
            "AWS": "AWS::CloudWatch::Alarm",
            "AWS_RT": "cloudwatch:alarm"
        },
        {
            "TF": "aws_cloudwatch_metric_stream",
            "AWS": "AWS::CloudWatch::MetricStream",
            "AWS_RT": "cloudwatch:metric-stream"
        },
        {
            "TF": "aws_codeartifact_domain",
            "AWS": "AWS::CodeArtifact::Domain",
            "AWS_RT": "codeartifact:domain"
        },
        {
            "TF": "aws_codeartifact_repository",
            "AWS": "AWS::CodeArtifact::Repository",
            "AWS_RT": "codeartifact:repository"
        },
        {
            "TF": "aws_codebuild_project",
            "AWS": "AWS::CodeBuild::Project",
            "AWS_RT": "codebuild:project"
        },
        {
            "TF": "aws_codebuild_report_group",
            "AWS": "AWS::CodeBuild::ReportGroup",
            "AWS_RT": "codebuild:report-group"
        },
        {
            "TF": "aws_codebuild_source_credential",
            "AWS": "AWS::CodeBuild::SourceCredential",
            "AWS_RT": "codebuild:source-credential"
        },
        {
            "TF": "aws_codecommit_repository",
            "AWS": "AWS::CodeCommit::Repository",
            "AWS_RT": "codecommit:repository"
        },
        {
            "TF": "aws_codedeploy_deployment_config",
            "AWS": "AWS::CodeDeploy::DeploymentConfig",
            "AWS_RT": "codedeploy:deployment-config"
        },
        {
            "TF": "aws_codedeploy_deployment_group",
            "AWS": "AWS::CodeDeploy::DeploymentGroup",
            "AWS_RT": "codedeploy:deployment-group"
        },
        {
            "TF": "aws_codepipeline_webhook",
            "AWS": "AWS::CodePipeline::Webhook",
            "AWS_RT": "codepipeline:webhook"
        },
        {
            "TF": "aws_codestarconnections_connection",
            "AWS": "AWS::CodeStarConnections::Connection",
            "AWS_RT": "codestarconnections:connection"
        },
        {
            "TF": "aws_codestarnotifications_notification_rule",
            "AWS": "AWS::CodeStarNotifications::NotificationRule",
            "AWS_RT": "codestarnotifications:notification-rule"
        },
        {
            "TF": "aws_cognito_identity_pool",
            "AWS": "AWS::Cognito::IdentityPool",
            "AWS_RT": "cognito:identity-pool"
        },
        {
            "TF": "aws_cognito_identity_pool_roles_attachment",
            "AWS": "AWS::Cognito::IdentityPoolRoleAttachment",
            "AWS_RT": "cognito:identity-pool-role-attachment"
        },
        {
            "TF": "aws_cognito_user_group",
            "AWS": "AWS::Cognito::UserPoolGroup",
            "AWS_RT": "cognito:user-pool-group"
        },
        {
            "TF": "aws_cognito_user_pool",
            "AWS": "AWS::Cognito::UserPool",
            "AWS_RT": "cognito:user-pool"
        },
        {
            "TF": "aws_cognito_user_pool_client",
            "AWS": "AWS::Cognito::UserPoolClient",
            "AWS_RT": "cognito:user-pool-client"
        },
        {
            "TF": "aws_cognito_user_pool_domain",
            "AWS": "AWS::Cognito::UserPoolDomain",
            "AWS_RT": "cognito:user-pool-domain"
        },
        {
            "TF": "aws_config_config_rule",
            "AWS": "AWS::Config::ConfigRule",
            "AWS_RT": "config:config-rule"
        },
        {
            "TF": "aws_config_configuration_aggregator",
            "AWS": "AWS::Config::ConfigurationAggregator",
            "AWS_RT": "config:configuration-aggregator"
        },
        {
            "TF": "aws_config_configuration_recorder",
            "AWS": "AWS::Config::ConfigurationRecorder",
            "AWS_RT": "config:configuration-recorder"
        },
        {
            "TF": "aws_config_conformance_pack",
            "AWS": "AWS::Config::ConformancePack",
            "AWS_RT": "config:conformance-pack"
        },
        {
            "TF": "aws_config_delivery_channel",
            "AWS": "AWS::Config::DeliveryChannel",
            "AWS_RT": "config:delivery-channel"
        },
        {
            "TF": "aws_config_organization_conformance_pack",
            "AWS": "AWS::Config::OrganizationConformancePack",
            "AWS_RT": "config:organization-conformance-pack"
        },
        {
            "TF": "aws_config_remediation_configuration",
            "AWS": "AWS::Config::RemediationConfiguration",
            "AWS_RT": "config:remediation-configuration"
        },
        {
            "TF": "aws_connect_contact_flow",
            "AWS": "AWS::Connect::ContactFlow",
            "AWS_RT": "connect:contact-flow"
        },
        {
            "TF": "aws_connect_contact_flow_module",
            "AWS": "AWS::Connect::ContactFlowModule",
            "AWS_RT": "connect:contact-flow-module"
        },
        {
            "TF": "aws_connect_hours_of_operation",
            "AWS": "AWS::Connect::HoursOfOperation",
            "AWS_RT": "connect:hours-of-operation"
        },
        {
            "TF": "aws_connect_quick_connect",
            "AWS": "AWS::Connect::QuickConnect",
            "AWS_RT": "connect:quick-connect"
        },
        {
            "TF": "aws_cur_report_definition",
            "AWS": "AWS::CUR::ReportDefinition",
            "AWS_RT": "cur:report-definition"
        },
        {
            "TF": "aws_datapipeline_pipeline",
            "AWS": "AWS::DataPipeline::Pipeline",
            "AWS_RT": "datapipeline:pipeline"
        },
        {
            "TF": "aws_datasync_agent",
            "AWS": "AWS::DataSync::Agent",
            "AWS_RT": "datasync:agent"
        },
        {
            "TF": "aws_datasync_location_efs",
            "AWS": "AWS::DataSync::LocationEFS",
            "AWS_RT": "datasync:location-efs"
        },
        {
            "TF": "aws_datasync_location_hdfs",
            "AWS": "AWS::DataSync::LocationHDFS",
            "AWS_RT": "datasync:location-hdfs"
        },
        {
            "TF": "aws_datasync_location_nfs",
            "AWS": "AWS::DataSync::LocationNFS",
            "AWS_RT": "datasync:location-nfs"
        },
        {
            "TF": "aws_datasync_location_s3",
            "AWS": "AWS::DataSync::LocationS3",
            "AWS_RT": "datasync:location-s3"
        },
        {
            "TF": "aws_datasync_location_smb",
            "AWS": "AWS::DataSync::LocationSMB",
            "AWS_RT": "datasync:location-smb"
        },
        {
            "TF": "aws_datasync_task",
            "AWS": "AWS::DataSync::Task",
            "AWS_RT": "datasync:task"
        },
        {
            "TF": "aws_dax_cluster",
            "AWS": "AWS::DAX::Cluster",
            "AWS_RT": "dax:cluster"
        },
        {
            "TF": "aws_dax_parameter_group",
            "AWS": "AWS::DAX::ParameterGroup",
            "AWS_RT": "dax:parameter-group"
        },
        {
            "TF": "aws_dax_subnet_group",
            "AWS": "AWS::DAX::SubnetGroup",
            "AWS_RT": "dax:subnet-group"
        },
        {
            "TF": "aws_db_instance",
            "AWS": "AWS::RDS::DBInstance",
            "AWS_RT": "rds:db-instance"
        },
        {
            "TF": "aws_db_option_group",
            "AWS": "AWS::RDS::OptionGroup",
            "AWS_RT": "rds:og"
        },
        {
            "TF": "aws_db_parameter_group",
            "AWS": "AWS::RDS::DBParameterGroup",
            "AWS_RT": "rds:db-parameter-group"
        },
        {
            "TF": "aws_db_proxy",
            "AWS": "AWS::RDS::DBProxy",
            "AWS_RT": "rds:db-proxy"
        },
        {
            "TF": "aws_db_proxy_endpoint",
            "AWS": "AWS::RDS::DBProxyEndpoint",
            "AWS_RT": "rds:db-proxy-endpoint"
        },
        {
            "TF": "aws_db_security_group",
            "AWS": "AWS::RDS::DBSecurityGroup",
            "AWS_RT": "rds:db-security-group"
        },
        {
            "TF": "aws_db_subnet_group",
            "AWS": "AWS::RDS::DBSubnetGroup",
            "AWS_RT": "rds:db-subnet-group"
        },
        {
            "TF": "aws_detective_graph",
            "AWS": "AWS::Detective::Graph",
            "AWS_RT": "detective:graph"
        },
        {
            "TF": "aws_devicefarm_device_pool",
            "AWS": "AWS::DeviceFarm::DevicePool",
            "AWS_RT": "devicefarm:device-pool"
        },
        {
            "TF": "aws_devicefarm_instance_profile",
            "AWS": "AWS::DeviceFarm::InstanceProfile",
            "AWS_RT": "devicefarm:instance-profile"
        },
        {
            "TF": "aws_devicefarm_network_profile",
            "AWS": "AWS::DeviceFarm::NetworkProfile",
            "AWS_RT": "devicefarm:network-profile"
        },
        {
            "TF": "aws_devicefarm_project",
            "AWS": "AWS::DeviceFarm::Project",
            "AWS_RT": "devicefarm:project"
        },
        {
            "TF": "aws_dlm_lifecycle_policy",
            "AWS": "AWS::DLM::LifecyclePolicy",
            "AWS_RT": "dlm:lifecycle-policy"
        },
        {
            "TF": "aws_dms_certificate",
            "AWS": "AWS::DMS::Certificate",
            "AWS_RT": "dms:certificate"
        },
        {
            "TF": "aws_dms_endpoint",
            "AWS": "AWS::DMS::Endpoint",
            "AWS_RT": "dms:endpoint"
        },
        {
            "TF": "aws_dms_event_subscription",
            "AWS": "AWS::DMS::EventSubscription",
            "AWS_RT": "dms:event-subscription"
        },
        {
            "TF": "aws_dms_replication_instance",
            "AWS": "AWS::DMS::ReplicationInstance",
            "AWS_RT": "dms:replication-instance"
        },
        {
            "TF": "aws_dms_replication_subnet_group",
            "AWS": "AWS::DMS::ReplicationSubnetGroup",
            "AWS_RT": "dms:replication-subnet-group"
        },
        {
            "TF": "aws_dms_replication_task",
            "AWS": "AWS::DMS::ReplicationTask",
            "AWS_RT": "dms:replication-task"
        },
        {
            "TF": "aws_dynamodb_global_table",
            "AWS": "AWS::DynamoDB::GlobalTable",
            "AWS_RT": "dynamodb:global-table"
        },
        {
            "TF": "aws_dynamodb_table",
            "AWS": "AWS::DynamoDB::Table",
            "AWS_RT": "dynamodb:table"
        },
        {
            "TF": "aws_ebs_volume",
            "AWS": "AWS::EC2::Volume",
            "AWS_RT": "ec2:volume"
        },
        {
            "TF": "aws_ec2_capacity_reservation",
            "AWS": "AWS::EC2::CapacityReservation",
            "AWS_RT": "ec2:capacity-reservation"
        },
        {
            "TF": "aws_ec2_carrier_gateway",
            "AWS": "AWS::EC2::CarrierGateway",
            "AWS_RT": "ec2:carrier-gateway"
        },
        {
            "TF": "aws_ec2_client_vpn_authorization_rule",
            "AWS": "AWS::EC2::ClientVpnAuthorizationRule",
            "AWS_RT": "ec2:client-vpn-authorization-rule"
        },
        {
            "TF": "aws_ec2_client_vpn_endpoint",
            "AWS": "AWS::EC2::ClientVpnEndpoint",
            "AWS_RT": "ec2:client-vpn-endpoint"
        },
        {
            "TF": "aws_ec2_client_vpn_route",
            "AWS": "AWS::EC2::ClientVpnRoute",
            "AWS_RT": "ec2:client-vpn-route"
        },
        {
            "TF": "aws_ec2_host",
            "AWS": "AWS::EC2::Host",
            "AWS_RT": "ec2:host"
        },
        {
            "TF": "aws_ec2_local_gateway_route",
            "AWS": "AWS::EC2::LocalGatewayRoute",
            "AWS_RT": "ec2:local-gateway-route"
        },
        {
            "TF": "aws_ec2_local_gateway_route_table_vpc_association",
            "AWS": "AWS::EC2::LocalGatewayRouteTableVPCAssociation",
            "AWS_RT": "ec2:local-gateway-route-table-vpc-association"
        },
        {
            "TF": "aws_ec2_traffic_mirror_filter",
            "AWS": "AWS::EC2::TrafficMirrorFilter",
            "AWS_RT": "ec2:traffic-mirror-filter"
        },
        {
            "TF": "aws_ec2_traffic_mirror_filter_rule",
            "AWS": "AWS::EC2::TrafficMirrorFilterRule",
            "AWS_RT": "ec2:traffic-mirror-filter-rule"
        },
        {
            "TF": "aws_ec2_traffic_mirror_session",
            "AWS": "AWS::EC2::TrafficMirrorSession",
            "AWS_RT": "ec2:traffic-mirror-session"
        },
        {
            "TF": "aws_ec2_traffic_mirror_target",
            "AWS": "AWS::EC2::TrafficMirrorTarget",
            "AWS_RT": "ec2:traffic-mirror-target"
        },
        {
            "TF": "aws_ec2_transit_gateway",
            "AWS": "AWS::EC2::TransitGateway",
            "AWS_RT": "ec2:transit-gateway"
        },
        {
            "TF": "aws_ec2_transit_gateway_peering_attachment",
            "AWS": "AWS::EC2::TransitGatewayPeeringAttachment",
            "AWS_RT": "ec2:transit-gateway-peering-attachment"
        },
        {
            "TF": "aws_ec2_transit_gateway_route",
            "AWS": "AWS::EC2::TransitGatewayRoute",
            "AWS_RT": "ec2:transit-gateway-route"
        },
        {
            "TF": "aws_ec2_transit_gateway_route_table",
            "AWS": "AWS::EC2::TransitGatewayRouteTable",
            "AWS_RT": "ec2:transit-gateway-route-table"
        },
        {
            "TF": "aws_ec2_transit_gateway_route_table_association",
            "AWS": "AWS::EC2::TransitGatewayRouteTableAssociation",
            "AWS_RT": "ec2:transit-gateway-route-table-association"
        },
        {
            "TF": "aws_ec2_transit_gateway_route_table_propagation",
            "AWS": "AWS::EC2::TransitGatewayRouteTablePropagation",
            "AWS_RT": "ec2:transit-gateway-route-table-propagation"
        },
        {
            "TF": "aws_ec2_transit_gateway_vpc_attachment",
            "AWS": "AWS::EC2::TransitGatewayVpcAttachment",
            "AWS_RT": "ec2:transit-gateway-vpc-attachment"
        },
        {
            "TF": "aws_ecr_registry_policy",
            "AWS": "AWS::ECR::RegistryPolicy",
            "AWS_RT": "ecr:registry-policy"
        },
        {
            "TF": "aws_ecr_replication_configuration",
            "AWS": "AWS::ECR::ReplicationConfiguration",
            "AWS_RT": "ecr:replication-configuration"
        },
        {
            "TF": "aws_ecr_repository",
            "AWS": "AWS::ECR::Repository",
            "AWS_RT": "ecr:repository"
        },
        {
            "TF": "aws_ecrpublic_repository",
            "AWS": "AWS::ECR::PublicRepository",
            "AWS_RT": "ecr:public-repository"
        },
        {
            "TF": "aws_ecs_capacity_provider",
            "AWS": "AWS::ECS::CapacityProvider",
            "AWS_RT": "ecs:capacity-provider"
        },
        {
            "TF": "aws_ecs_cluster",
            "AWS": "AWS::ECS::Cluster",
            "AWS_RT": "ecs:cluster"
        },
        {
            "TF": "aws_ecs_service",
            "AWS": "AWS::ECS::Service",
            "AWS_RT": "ecs:service"
        },
        {
            "TF": "aws_ecs_task_definition",
            "AWS": "AWS::ECS::TaskDefinition",
            "AWS_RT": "ecs:task-definition"
        },
        {
            "TF": "aws_ecs_task_set",
            "AWS": "AWS::ECS::TaskSet",
            "AWS_RT": "ecs:task-set"
        },
        {
            "TF": "aws_efs_access_point",
            "AWS": "AWS::EFS::AccessPoint",
            "AWS_RT": "efs:access-point"
        },
        {
            "TF": "aws_efs_file_system",
            "AWS": "AWS::EFS::FileSystem",
            "AWS_RT": "efs:file-system"
        },
        {
            "TF": "aws_efs_mount_target",
            "AWS": "AWS::EFS::MountTarget",
            "AWS_RT": "efs:mount-target"
        },
        {
            "TF": "aws_eip",
            "AWS": "AWS::EC2::EIP",
            "AWS_RT": "ec2:elastic-ip"
        },
        {
            "TF": "aws_eks_addon",
            "AWS": "AWS::EKS::Addon",
            "AWS_RT": "eks:addon"
        },
        {
            "TF": "aws_eks_cluster",
            "AWS": "AWS::EKS::Cluster",
            "AWS_RT": "eks:cluster"
        },
        {
            "TF": "aws_eks_fargate_profile",
            "AWS": "AWS::EKS::FargateProfile",
            "AWS_RT": "eks:fargate-profile"
        },
        {
            "TF": "aws_eks_node_group",
            "AWS": "AWS::EKS::Nodegroup",
            "AWS_RT": "eks:nodegroup"
        },
        {
            "TF": "aws_elastic_beanstalk_application",
            "AWS": "AWS::ElasticBeanstalk::Application",
            "AWS_RT": "elasticbeanstalk:application"
        },
        {
            "TF": "aws_elastic_beanstalk_application_version",
            "AWS": "AWS::ElasticBeanstalk::ApplicationVersion",
            "AWS_RT": "elasticbeanstalk:application-version"
        },
        {
            "TF": "aws_elastic_beanstalk_configuration_template",
            "AWS": "AWS::ElasticBeanstalk::ConfigurationTemplate",
            "AWS_RT": "elasticbeanstalk:configuration-template"
        },
        {
            "TF": "aws_elastic_beanstalk_environment",
            "AWS": "AWS::ElasticBeanstalk::Environment",
            "AWS_RT": "elasticbeanstalk:environment"
        },
        {
            "TF": "aws_elasticache_global_replication_group",
            "AWS": "AWS::ElastiCache::GlobalReplicationGroup",
            "AWS_RT": "elasticache:global-replication-group"
        },
        {
            "TF": "aws_elasticache_parameter_group",
            "AWS": "AWS::ElastiCache::ParameterGroup",
            "AWS_RT": "elasticache:parametergroup"
        },
        {
            "TF": "aws_elasticache_replication_group",
            "AWS": "AWS::ElastiCache::ReplicationGroup",
            "AWS_RT": "elasticache:replication-group"
        },
        {
            "TF": "aws_elasticache_security_group",
            "AWS": "AWS::ElastiCache::SecurityGroup",
            "AWS_RT": "elasticache:security-group"
        },
        {
            "TF": "aws_elasticache_subnet_group",
            "AWS": "AWS::ElastiCache::SubnetGroup",
            "AWS_RT": "elasticache:subnet-group"
        },
        {
            "TF": "aws_elasticache_user",
            "AWS": "AWS::ElastiCache::User",
            "AWS_RT": "elasticache:user"
        },
        {
            "TF": "aws_elasticache_user_group",
            "AWS": "AWS::ElastiCache::UserGroup",
            "AWS_RT": "elasticache:user-group"
        },
        {
            "TF": "aws_elasticsearch_domain",
            "AWS": "AWS::Elasticsearch::Domain",
            "AWS_RT": "elasticsearch:domain"
        },
        {
            "TF": "aws_elb",
            "AWS": "AWS::ElasticLoadBalancing::LoadBalancer",
            "AWS_RT": "elasticloadbalancing:load-balancer"
        },
        {
            "TF": "aws_emr_cluster",
            "AWS": "AWS::EMR::Cluster",
            "AWS_RT": "emr:cluster"
        },
        {
            "TF": "aws_emr_security_configuration",
            "AWS": "AWS::EMR::SecurityConfiguration",
            "AWS_RT": "emr:security-configuration"
        },
        {
            "TF": "aws_emr_studio",
            "AWS": "AWS::EMR::Studio",
            "AWS_RT": "emr:studio"
        },
        {
            "TF": "aws_emr_studio_session_mapping",
            "AWS": "AWS::EMR::StudioSessionMapping",
            "AWS_RT": "emr:studio-session-mapping"
        },
        {
            "TF": "aws_flow_log",
            "AWS": "AWS::EC2::FlowLog",
            "AWS_RT": "ec2:flow-log"
        },
        {
            "TF": "aws_fms_policy",
            "AWS": "AWS::FMS::Policy",
            "AWS_RT": "fms:policy"
        },
        {
            "TF": "aws_gamelift_alias",
            "AWS": "AWS::GameLift::Alias",
            "AWS_RT": "gamelift:alias"
        },
        {
            "TF": "aws_gamelift_build",
            "AWS": "AWS::GameLift::Build",
            "AWS_RT": "gamelift:build"
        },
        {
            "TF": "aws_gamelift_fleet",
            "AWS": "AWS::GameLift::Fleet",
            "AWS_RT": "gamelift:fleet"
        },
        {
            "TF": "aws_gamelift_game_session_queue",
            "AWS": "AWS::GameLift::GameSessionQueue",
            "AWS_RT": "gamelift:game-session-queue"
        },
        {
            "TF": "aws_globalaccelerator_accelerator",
            "AWS": "AWS::GlobalAccelerator::Accelerator",
            "AWS_RT": "globalaccelerator:accelerator"
        },
        {
            "TF": "aws_globalaccelerator_endpoint_group",
            "AWS": "AWS::GlobalAccelerator::EndpointGroup",
            "AWS_RT": "globalaccelerator:endpoint-group"
        },
        {
            "TF": "aws_globalaccelerator_listener",
            "AWS": "AWS::GlobalAccelerator::Listener",
            "AWS_RT": "globalaccelerator:listener"
        },
        {
            "TF": "aws_glue_classifier",
            "AWS": "AWS::Glue::Classifier",
            "AWS_RT": "glue:classifier"
        },
        {
            "TF": "aws_glue_connection",
            "AWS": "AWS::Glue::Connection",
            "AWS_RT": "glue:connection"
        },
        {
            "TF": "aws_glue_crawler",
            "AWS": "AWS::Glue::Crawler",
            "AWS_RT": "glue:crawler"
        },
        {
            "TF": "aws_glue_data_catalog_encryption_settings",
            "AWS": "AWS::Glue::DataCatalogEncryptionSettings",
            "AWS_RT": "glue:data-catalog-encryption-settings"
        },
        {
            "TF": "aws_glue_dev_endpoint",
            "AWS": "AWS::Glue::DevEndpoint",
            "AWS_RT": "glue:dev-endpoint"
        },
        {
            "TF": "aws_glue_job",
            "AWS": "AWS::Glue::Job",
            "AWS_RT": "glue:job"
        },
        {
            "TF": "aws_glue_ml_transform",
            "AWS": "AWS::Glue::MLTransform",
            "AWS_RT": "glue:ml-transform"
        },
        {
            "TF": "aws_glue_partition",
            "AWS": "AWS::Glue::Partition",
            "AWS_RT": "glue:partition"
        },
        {
            "TF": "aws_glue_registry",
            "AWS": "AWS::Glue::Registry",
            "AWS_RT": "glue:registry"
        },
        {
            "TF": "aws_glue_schema",
            "AWS": "AWS::Glue::Schema",
            "AWS_RT": "glue:schema"
        },
        {
            "TF": "aws_glue_security_configuration",
            "AWS": "AWS::Glue::SecurityConfiguration",
            "AWS_RT": "glue:security-configuration"
        },
        {
            "TF": "aws_glue_trigger",
            "AWS": "AWS::Glue::Trigger",
            "AWS_RT": "glue:trigger"
        },
        {
            "TF": "aws_glue_workflow",
            "AWS": "AWS::Glue::Workflow",
            "AWS_RT": "glue:workflow"
        },
        {
            "TF": "aws_guardduty_detector",
            "AWS": "AWS::GuardDuty::Detector",
            "AWS_RT": "guardduty:detector"
        },
        {
            "TF": "aws_guardduty_filter",
            "AWS": "AWS::GuardDuty::Filter",
            "AWS_RT": "guardduty:filter"
        },
        {
            "TF": "aws_guardduty_ipset",
            "AWS": "AWS::GuardDuty::IPSet",
            "AWS_RT": "guardduty:ip-set"
        },
        {
            "TF": "aws_guardduty_member",
            "AWS": "AWS::GuardDuty::Member",
            "AWS_RT": "guardduty:member"
        },
        {
            "TF": "aws_guardduty_threatintelset",
            "AWS": "AWS::GuardDuty::ThreatIntelSet",
            "AWS_RT": "guardduty:threat-intel-set"
        },
        {
            "TF": "aws_iam_access_key",
            "AWS": "AWS::IAM::AccessKey",
            "AWS_RT": "iam:access-key"
        },
        {
            "TF": "aws_iam_group",
            "AWS": "AWS::IAM::Group",
            "AWS_RT": "iam:group"
        },
        {
            "TF": "aws_iam_instance_profile",
            "AWS": "AWS::IAM::InstanceProfile",
            "AWS_RT": "iam:instance-profile"
        },
        {
            "TF": "aws_iam_policy",
            "AWS": "AWS::IAM::ManagedPolicy",
            "AWS_RT": "iam:managed-policy"
        },
        {
            "TF": "aws_iam_role",
            "AWS": "AWS::IAM::Role",
            "AWS_RT": "iam:role"
        },
        {
            "TF": "aws_iam_saml_provider",
            "AWS": "AWS::IAM::SAMLProvider",
            "AWS_RT": "iam:saml-provider"
        },
        {
            "TF": "aws_iam_server_certificate",
            "AWS": "AWS::IAM::ServerCertificate",
            "AWS_RT": "iam:server-certificate"
        },
        {
            "TF": "aws_iam_service_linked_role",
            "AWS": "AWS::IAM::ServiceLinkedRole",
            "AWS_RT": "iam:service-linked-role"
        },
        {
            "TF": "aws_iam_user",
            "AWS": "AWS::IAM::User",
            "AWS_RT": "iam:user"
        },
        {
            "TF": "aws_imagebuilder_component",
            "AWS": "AWS::ImageBuilder::Component",
            "AWS_RT": "imagebuilder:component"
        },
        {
            "TF": "aws_imagebuilder_distribution_configuration",
            "AWS": "AWS::ImageBuilder::DistributionConfiguration",
            "AWS_RT": "imagebuilder:distribution-configuration"
        },
        {
            "TF": "aws_imagebuilder_image",
            "AWS": "AWS::ImageBuilder::Image",
            "AWS_RT": "imagebuilder:image"
        },
        {
            "TF": "aws_imagebuilder_image_pipeline",
            "AWS": "AWS::ImageBuilder::ImagePipeline",
            "AWS_RT": "imagebuilder:image-pipeline"
        },
        {
            "TF": "aws_imagebuilder_image_recipe",
            "AWS": "AWS::ImageBuilder::ImageRecipe",
            "AWS_RT": "imagebuilder:image-recipe"
        },
        {
            "TF": "aws_imagebuilder_infrastructure_configuration",
            "AWS": "AWS::ImageBuilder::InfrastructureConfiguration",
            "AWS_RT": "imagebuilder:infrastructure-configuration"
        },
        {
            "TF": "aws_inspector_assessment_target",
            "AWS": "AWS::Inspector::AssessmentTarget",
            "AWS_RT": "inspector:assessment-target"
        },
        {
            "TF": "aws_inspector_assessment_template",
            "AWS": "AWS::Inspector::AssessmentTemplate",
            "AWS_RT": "inspector:assessment-template"
        },
        {
            "TF": "aws_inspector_resource_group",
            "AWS": "AWS::Inspector::ResourceGroup",
            "AWS_RT": "inspector:resource-group"
        },
        {
            "TF": "aws_instance",
            "AWS": "AWS::EC2::Instance",
            "AWS_RT": "ec2:instance"
        },
        {
            "TF": "aws_ami",
            "AWS": "AWS::EC2::Image",
            "AWS_RT": "ec2:image"
        },
        {
            "TF": "aws_internet_gateway",
            "AWS": "AWS::EC2::InternetGateway",
            "AWS_RT": "ec2:internet-gateway"
        },
        {
            "TF": "aws_iot_authorizer",
            "AWS": "AWS::IoT::Authorizer",
            "AWS_RT": "iot:authorizer"
        },
        {
            "TF": "aws_iot_certificate",
            "AWS": "AWS::IoT::Certificate",
            "AWS_RT": "iot:certificate"
        },
        {
            "TF": "aws_iot_policy",
            "AWS": "AWS::IoT::Policy",
            "AWS_RT": "iot:policy"
        },
        {
            "TF": "aws_iot_thing",
            "AWS": "AWS::IoT::Thing",
            "AWS_RT": "iot:thing"
        },
        {
            "TF": "aws_iot_thing_principal_attachment",
            "AWS": "AWS::IoT::ThingPrincipalAttachment",
            "AWS_RT": "iot:thing-principal-attachment"
        },
        {
            "TF": "aws_iot_topic_rule",
            "AWS": "AWS::IoT::TopicRule",
            "AWS_RT": "iot:topic-rule"
        },
        {
            "TF": "aws_kinesis_analytics_application",
            "AWS": "AWS::KinesisAnalytics::Application",
            "AWS_RT": "kinesisanalytics:application"
        },
        {
            "TF": "aws_kinesis_firehose_delivery_stream",
            "AWS": "AWS::KinesisFirehose::DeliveryStream",
            "AWS_RT": "kinesisfirehose:delivery-stream"
        },
        {
            "TF": "aws_kinesis_stream",
            "AWS": "AWS::Kinesis::Stream",
            "AWS_RT": "kinesis:stream"
        },
        {
            "TF": "aws_kinesis_stream_consumer",
            "AWS": "AWS::Kinesis::StreamConsumer",
            "AWS_RT": "kinesis:stream-consumer"
        },
        {
            "TF": "aws_kinesis_video_stream",
            "AWS": "AWS::KinesisVideo::Stream",
            "AWS_RT": "kinesisvideo:stream"
        },
        {
            "TF": "aws_kinesisanalyticsv2_application",
            "AWS": "AWS::KinesisAnalyticsV2::Application",
            "AWS_RT": "kinesisanalyticsv2:application"
        },
        {
            "TF": "aws_kms_alias",
            "AWS": "AWS::KMS::Alias",
            "AWS_RT": "kms:alias"
        },
        {
            "TF": "aws_kms_key",
            "AWS": "AWS::KMS::Key",
            "AWS_RT": "kms:key"
        },
        {
            "TF": "aws_kms_replica_key",
            "AWS": "AWS::KMS::ReplicaKey",
            "AWS_RT": "kms:replica-key"
        },
        {
            "TF": "aws_lakeformation_data_lake_settings",
            "AWS": "AWS::LakeFormation::DataLakeSettings",
            "AWS_RT": "lakeformation:data-lake-settings"
        },
        {
            "TF": "aws_lakeformation_permissions",
            "AWS": "AWS::LakeFormation::Permissions",
            "AWS_RT": "lakeformation:permissions"
        },
        {
            "TF": "aws_lakeformation_resource",
            "AWS": "AWS::LakeFormation::Resource",
            "AWS_RT": "lakeformation:resource"
        },
        {
            "TF": "aws_lambda_alias",
            "AWS": "AWS::Lambda::Alias",
            "AWS_RT": "lambda:alias"
        },
        {
            "TF": "aws_lambda_code_signing_config",
            "AWS": "AWS::Lambda::CodeSigningConfig",
            "AWS_RT": "lambda:code-signing-config"
        },
        {
            "TF": "aws_lambda_event_source_mapping",
            "AWS": "AWS::Lambda::EventSourceMapping",
            "AWS_RT": "lambda:event-source-mapping"
        },
        {
            "TF": "aws_lambda_function",
            "AWS": "AWS::Lambda::Function",
            "AWS_RT": "lambda:function"
        },
        {
            "TF": "aws_lambda_layer_version",
            "AWS": "AWS::Lambda::LayerVersion",
            "AWS_RT": "lambda:layer-version"
        },
        {
            "TF": "aws_lambda_layer_version_permission",
            "AWS": "AWS::Lambda::LayerVersionPermission",
            "AWS_RT": "lambda:layer-version-permission"
        },
        {
            "TF": "aws_lambda_permission",
            "AWS": "AWS::Lambda::Permission",
            "AWS_RT": "lambda:permission"
        },
        {
            "TF": "aws_launch_configuration",
            "AWS": "AWS::AutoScaling::LaunchConfiguration",
            "AWS_RT": "autoscaling:launch-configuration"
        },
        {
            "TF": "aws_launch_template",
            "AWS": "AWS::EC2::LaunchTemplate",
            "AWS_RT": "ec2:launch-template"
        },
        {
            "TF": "aws_lb",
            "AWS": "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "AWS_RT": "elasticloadbalancingv2:load-balancer"
        },
        {
            "TF": "aws_lb_listener",
            "AWS": "AWS::ElasticLoadBalancingV2::Listener",
            "AWS_RT": "elasticloadbalancingv2:listener"
        },
        {
            "TF": "aws_lb_listener_certificate",
            "AWS": "AWS::ElasticLoadBalancingV2::ListenerCertificate",
            "AWS_RT": "elasticloadbalancingv2:listener-certificate"
        },
        {
            "TF": "aws_lb_listener_rule",
            "AWS": "AWS::ElasticLoadBalancingV2::ListenerRule",
            "AWS_RT": "elasticloadbalancingv2:listener-rule"
        },
        {
            "TF": "aws_lb_target_group",
            "AWS": "AWS::ElasticLoadBalancingV2::TargetGroup",
            "AWS_RT": "elasticloadbalancingv2:target-group"
        },
        {
            "TF": "aws_lex_bot",
            "AWS": "AWS::Lex::Bot",
            "AWS_RT": "lex:bot"
        },
        {
            "TF": "aws_lex_bot_alias",
            "AWS": "AWS::Lex::BotAlias",
            "AWS_RT": "lex:bot-alias"
        },
        {
            "TF": "aws_lightsail_instance",
            "AWS": "AWS::Lightsail::Instance",
            "AWS_RT": "lightsail:instance"
        },
        {
            "TF": "aws_lightsail_static_ip",
            "AWS": "AWS::Lightsail::StaticIp",
            "AWS_RT": "lightsail:static-ip"
        },
        {
            "TF": "aws_media_convert_queue",
            "AWS": "AWS::MediaConvert::Queue",
            "AWS_RT": "mediaconvert:queue"
        },
        {
            "TF": "aws_media_package_channel",
            "AWS": "AWS::MediaPackage::Channel",
            "AWS_RT": "mediapackage:channel"
        },
        {
            "TF": "aws_media_store_container",
            "AWS": "AWS::MediaStore::Container",
            "AWS_RT": "mediastore:container"
        },
        {
            "TF": "aws_memorydb_acl",
            "AWS": "AWS::MemoryDB::ACL",
            "AWS_RT": "memorydb:acl"
        },
        {
            "TF": "aws_memorydb_cluster",
            "AWS": "AWS::MemoryDB::Cluster",
            "AWS_RT": "memorydb:cluster"
        },
        {
            "TF": "aws_memorydb_parameter_group",
            "AWS": "AWS::MemoryDB::ParameterGroup",
            "AWS_RT": "memorydb:parameter-group"
        },
        {
            "TF": "aws_memorydb_subnet_group",
            "AWS": "AWS::MemoryDB::SubnetGroup",
            "AWS_RT": "memorydb:subnet-group"
        },
        {
            "TF": "aws_memorydb_user",
            "AWS": "AWS::MemoryDB::User",
            "AWS_RT": "memorydb:user"
        },
        {
            "TF": "aws_msk_cluster",
            "AWS": "AWS::MSK::Cluster",
            "AWS_RT": "msk:cluster"
        },
        {
            "TF": "aws_mwaa_environment",
            "AWS": "AWS::MWAA::Environment",
            "AWS_RT": "mwaa:environment"
        },
        {
            "TF": "aws_nat_gateway",
            "AWS": "AWS::EC2::NatGateway",
            "AWS_RT": "ec2:nat-gateway"
        },
        {
            "TF": "aws_neptune_cluster_parameter_group",
            "AWS": "AWS::Neptune::DBClusterParameterGroup",
            "AWS_RT": "neptune:db-cluster-parameter-group"
        },
        {
            "TF": "aws_network_acl",
            "AWS": "AWS::EC2::NetworkAcl",
            "AWS_RT": "ec2:network-acl"
        },
        {
            "TF": "aws_networkfirewall_firewall",
            "AWS": "AWS::NetworkFirewall::Firewall",
            "AWS_RT": "networkfirewall:firewall"
        },
        {
            "TF": "aws_networkfirewall_firewall_policy",
            "AWS": "AWS::NetworkFirewall::FirewallPolicy",
            "AWS_RT": "networkfirewall:firewall-policy"
        },
        {
            "TF": "aws_networkfirewall_logging_configuration",
            "AWS": "AWS::NetworkFirewall::LoggingConfiguration",
            "AWS_RT": "networkfirewall:logging-configuration"
        },
        {
            "TF": "aws_networkfirewall_rule_group",
            "AWS": "AWS::NetworkFirewall::RuleGroup",
            "AWS_RT": "networkfirewall:rule-group"
        },
        {
            "TF": "aws_opsworks_instance",
            "AWS": "AWS::OpsWorks::Instance",
            "AWS_RT": "opsworks:instance"
        },
        {
            "TF": "aws_opsworks_stack",
            "AWS": "AWS::OpsWorks::Stack",
            "AWS_RT": "opsworks:stack"
        },
        {
            "TF": "aws_opsworks_user_profile",
            "AWS": "AWS::OpsWorks::UserProfile",
            "AWS_RT": "opsworks:user-profile"
        },
        {
            "TF": "aws_pinpoint_adm_channel",
            "AWS": "AWS::Pinpoint::ADMChannel",
            "AWS_RT": "pinpoint:adm-channel"
        },
        {
            "TF": "aws_pinpoint_apns_channel",
            "AWS": "AWS::Pinpoint::APNSChannel",
            "AWS_RT": "pinpoint:apns-channel"
        },
        {
            "TF": "aws_pinpoint_apns_sandbox_channel",
            "AWS": "AWS::Pinpoint::APNSSandboxChannel",
            "AWS_RT": "pinpoint:apns-sandbox-channel"
        },
        {
            "TF": "aws_pinpoint_apns_voip_channel",
            "AWS": "AWS::Pinpoint::APNSVoipChannel",
            "AWS_RT": "pinpoint:apns-voip-channel"
        },
        {
            "TF": "aws_pinpoint_apns_voip_sandbox_channel",
            "AWS": "AWS::Pinpoint::APNSVoipSandboxChannel",
            "AWS_RT": "pinpoint:apns-voip-sandbox-channel"
        },
        {
            "TF": "aws_pinpoint_app",
            "AWS": "AWS::Pinpoint::App",
            "AWS_RT": "pinpoint:app"
        },
        {
            "TF": "aws_pinpoint_baidu_channel",
            "AWS": "AWS::Pinpoint::BaiduChannel",
            "AWS_RT": "pinpoint:baidu-channel"
        },
        {
            "TF": "aws_pinpoint_email_channel",
            "AWS": "AWS::Pinpoint::EmailChannel",
            "AWS_RT": "pinpoint:email-channel"
        },
        {
            "TF": "aws_pinpoint_event_stream",
            "AWS": "AWS::Pinpoint::EventStream",
            "AWS_RT": "pinpoint:event-stream"
        },
        {
            "TF": "aws_pinpoint_gcm_channel",
            "AWS": "AWS::Pinpoint::GCMChannel",
            "AWS_RT": "pinpoint:gcm-channel"
        },
        {
            "TF": "aws_pinpoint_sms_channel",
            "AWS": "AWS::Pinpoint::SMSChannel",
            "AWS_RT": "pinpoint:sms-channel"
        },
        {
            "TF": "aws_qldb_ledger",
            "AWS": "AWS::QLDB::Ledger",
            "AWS_RT": "qldb:ledger"
        },
        {
            "TF": "aws_quicksight_data_source",
            "AWS": "AWS::QuickSight::DataSource",
            "AWS_RT": "quicksight:data-source"
        },
        {
            "TF": "aws_ram_resource_share",
            "AWS": "AWS::RAM::ResourceShare",
            "AWS_RT": "ram:resource-share"
        },
        {
            "TF": "aws_rds_cluster",
            "AWS": "AWS::RDS::DBCluster",
            "AWS_RT": "rds:db-cluster"
        },
        {
            "TF": "aws_rds_cluster_parameter_group",
            "AWS": "AWS::RDS::DBClusterParameterGroup",
            "AWS_RT": "rds:db-cluster-parameter-group"
        },
        {
            "TF": "aws_rds_global_cluster",
            "AWS": "AWS::RDS::GlobalCluster",
            "AWS_RT": "rds:global-cluster"
        },
        {
            "TF": "aws_redshift_cluster",
            "AWS": "AWS::Redshift::Cluster",
            "AWS_RT": "redshift:cluster"
        },
        {
            "TF": "aws_redshift_parameter_group",
            "AWS": "AWS::Redshift::ClusterParameterGroup",
            "AWS_RT": "redshift:cluster-parameter-group"
        },
        {
            "TF": "aws_redshift_security_group",
            "AWS": "AWS::Redshift::ClusterSecurityGroup",
            "AWS_RT": "redshift:cluster-security-group"
        },
        {
            "TF": "aws_redshift_subnet_group",
            "AWS": "AWS::Redshift::ClusterSubnetGroup",
            "AWS_RT": "redshift:cluster-subnet-group"
        },
        {
            "TF": "aws_resourcegroups_group",
            "AWS": "AWS::ResourceGroups::Group",
            "AWS_RT": "resourcegroups:group"
        },
        {
            "TF": "aws_route",
            "AWS": "AWS::EC2::Route",
            "AWS_RT": "ec2:route"
        },
        {
            "TF": "aws_route_table",
            "AWS": "AWS::EC2::RouteTable",
            "AWS_RT": "ec2:route-table"
        },
        {
            "TF": "aws_route_table_association",
            "AWS": "AWS::EC2::SubnetRouteTableAssociation",
            "AWS_RT": "ec2:subnet-route-table-association"
        },
        {
            "TF": "aws_route53_health_check",
            "AWS": "AWS::Route53::HealthCheck",
            "AWS_RT": "route53:health-check"
        },
        {
            "TF": "aws_route53_key_signing_key",
            "AWS": "AWS::Route53::KeySigningKey",
            "AWS_RT": "route53:key-signing-key"
        },
        {
            "TF": "aws_route53_record",
            "AWS": "AWS::Route53::RecordSet",
            "AWS_RT": "route53:record-set"
        },
        {
            "TF": "aws_route53_resolver_firewall_domain_list",
            "AWS": "AWS::Route53Resolver::FirewallDomainList",
            "AWS_RT": "route53resolver:firewall-domain-list"
        },
        {
            "TF": "aws_route53_resolver_firewall_rule_group",
            "AWS": "AWS::Route53Resolver::FirewallRuleGroup",
            "AWS_RT": "route53resolver:firewall-rule-group"
        },
        {
            "TF": "aws_route53_resolver_firewall_rule_group_association",
            "AWS": "AWS::Route53Resolver::FirewallRuleGroupAssociation",
            "AWS_RT": "route53resolver:firewall-rule-group-association"
        },
        {
            "TF": "aws_route53_zone",
            "AWS": "AWS::Route53::HostedZone",
            "AWS_RT": "route53:hosted-zone"
        },
        {
            "TF": "aws_route53recoveryreadiness_cell",
            "AWS": "AWS::Route53RecoveryReadiness::Cell",
            "AWS_RT": "route53recoveryreadiness:cell"
        },
        {
            "TF": "aws_route53recoveryreadiness_readiness_check",
            "AWS": "AWS::Route53RecoveryReadiness::ReadinessCheck",
            "AWS_RT": "route53recoveryreadiness:readiness-check"
        },
        {
            "TF": "aws_route53recoveryreadiness_recovery_group",
            "AWS": "AWS::Route53RecoveryReadiness::RecoveryGroup",
            "AWS_RT": "route53recoveryreadiness:recovery-group"
        },
        {
            "TF": "aws_route53recoveryreadiness_resource_set",
            "AWS": "AWS::Route53RecoveryReadiness::ResourceSet",
            "AWS_RT": "route53recoveryreadiness:resource-set"
        },
        {
            "TF": "aws_s3_access_point",
            "AWS": "AWS::S3::AccessPoint",
            "AWS_RT": "s3:access-point"
        },
        {
            "TF": "aws_s3_bucket",
            "AWS": "AWS::S3::Bucket",
            "AWS_RT": "s3:bucket"
        },
        {
            "TF": "aws_s3_bucket_policy",
            "AWS": "AWS::S3::BucketPolicy",
            "AWS_RT": "s3:bucket-policy"
        },
        {
            "TF": "aws_s3outposts_endpoint",
            "AWS": "AWS::S3Outposts::Endpoint",
            "AWS_RT": "s3outposts:endpoint"
        },
        {
            "TF": "aws_sagemaker_app",
            "AWS": "AWS::SageMaker::App",
            "AWS_RT": "sagemaker:app"
        },
        {
            "TF": "aws_sagemaker_app_image_config",
            "AWS": "AWS::SageMaker::AppImageConfig",
            "AWS_RT": "sagemaker:app-image-config"
        },
        {
            "TF": "aws_sagemaker_code_repository",
            "AWS": "AWS::SageMaker::CodeRepository",
            "AWS_RT": "sagemaker:code-repository"
        },
        {
            "TF": "aws_sagemaker_device",
            "AWS": "AWS::SageMaker::Device",
            "AWS_RT": "sagemaker:device"
        },
        {
            "TF": "aws_sagemaker_device_fleet",
            "AWS": "AWS::SageMaker::DeviceFleet",
            "AWS_RT": "sagemaker:device-fleet"
        },
        {
            "TF": "aws_sagemaker_domain",
            "AWS": "AWS::SageMaker::Domain",
            "AWS_RT": "sagemaker:domain"
        },
        {
            "TF": "aws_sagemaker_endpoint",
            "AWS": "AWS::SageMaker::Endpoint",
            "AWS_RT": "sagemaker:endpoint"
        },
        {
            "TF": "aws_sagemaker_feature_group",
            "AWS": "AWS::SageMaker::FeatureGroup",
            "AWS_RT": "sagemaker:feature-group"
        },
        {
            "TF": "aws_sagemaker_image",
            "AWS": "AWS::SageMaker::Image",
            "AWS_RT": "sagemaker:image"
        },
        {
            "TF": "aws_sagemaker_image_version",
            "AWS": "AWS::SageMaker::ImageVersion",
            "AWS_RT": "sagemaker:image-version"
        },
        {
            "TF": "aws_sagemaker_model",
            "AWS": "AWS::SageMaker::Model",
            "AWS_RT": "sagemaker:model"
        },
        {
            "TF": "aws_sagemaker_model_package_group",
            "AWS": "AWS::SageMaker::ModelPackageGroup",
            "AWS_RT": "sagemaker:model-package-group"
        },
        {
            "TF": "aws_sagemaker_notebook_instance",
            "AWS": "AWS::SageMaker::NotebookInstance",
            "AWS_RT": "sagemaker:notebook-instance"
        },
        {
            "TF": "aws_sagemaker_user_profile",
            "AWS": "AWS::SageMaker::UserProfile",
            "AWS_RT": "sagemaker:user-profile"
        },
        {
            "TF": "aws_sagemaker_workteam",
            "AWS": "AWS::SageMaker::Workteam",
            "AWS_RT": "sagemaker:workteam"
        },
        {
            "TF": "aws_schemas_discoverer",
            "AWS": "AWS::EventSchemas::Discoverer",
            "AWS_RT": "eventschemas:discoverer"
        },
        {
            "TF": "aws_schemas_registry",
            "AWS": "AWS::EventSchemas::Registry",
            "AWS_RT": "eventschemas:registry"
        },
        {
            "TF": "aws_schemas_schema",
            "AWS": "AWS::EventSchemas::Schema",
            "AWS_RT": "eventschemas:schema"
        },
        {
            "TF": "aws_secretsmanager_secret",
            "AWS": "AWS::SecretsManager::Secret",
            "AWS_RT": "secretsmanager:secret"
        },
        {
            "TF": "aws_security_group",
            "AWS": "AWS::EC2::SecurityGroup",
            "AWS_RT": "ec2:security-group"
        },
        {
            "TF": "aws_service_discovery_http_namespace",
            "AWS": "AWS::ServiceDiscovery::HttpNamespace",
            "AWS_RT": "servicediscovery:http-namespace"
        },
        {
            "TF": "aws_service_discovery_instance",
            "AWS": "AWS::ServiceDiscovery::Instance",
            "AWS_RT": "servicediscovery:instance"
        },
        {
            "TF": "aws_service_discovery_private_dns_namespace",
            "AWS": "AWS::ServiceDiscovery::PrivateDnsNamespace",
            "AWS_RT": "servicediscovery:private-dns-namespace"
        },
        {
            "TF": "aws_service_discovery_public_dns_namespace",
            "AWS": "AWS::ServiceDiscovery::PublicDnsNamespace",
            "AWS_RT": "servicediscovery:public-dns-namespace"
        },
        {
            "TF": "aws_service_discovery_service",
            "AWS": "AWS::ServiceDiscovery::Service",
            "AWS_RT": "servicediscovery:service"
        },
        {
            "TF": "aws_servicecatalog_portfolio",
            "AWS": "AWS::ServiceCatalog::Portfolio",
            "AWS_RT": "servicecatalog:portfolio"
        },
        {
            "TF": "aws_servicecatalog_portfolio_share",
            "AWS": "AWS::ServiceCatalog::PortfolioShare",
            "AWS_RT": "servicecatalog:portfolio-share"
        },
        {
            "TF": "aws_servicecatalog_service_action",
            "AWS": "AWS::ServiceCatalog::ServiceAction",
            "AWS_RT": "servicecatalog:service-action"
        },
        {
            "TF": "aws_servicecatalog_tag_option",
            "AWS": "AWS::ServiceCatalog::TagOption",
            "AWS_RT": "servicecatalog:tag-option"
        },
        {
            "TF": "aws_ses_configuration_set",
            "AWS": "AWS::SES::ConfigurationSet",
            "AWS_RT": "ses:configuration-set"
        },
        {
            "TF": "aws_ses_receipt_filter",
            "AWS": "AWS::SES::ReceiptFilter",
            "AWS_RT": "ses:receipt-filter"
        },
        {
            "TF": "aws_ses_receipt_rule",
            "AWS": "AWS::SES::ReceiptRule",
            "AWS_RT": "ses:receipt-rule"
        },
        {
            "TF": "aws_ses_receipt_rule_set",
            "AWS": "AWS::SES::ReceiptRuleSet",
            "AWS_RT": "ses:receipt-rule-set"
        },
        {
            "TF": "aws_ses_template",
            "AWS": "AWS::SES::Template",
            "AWS_RT": "ses:template"
        },
        {
            "TF": "aws_signer_signing_profile",
            "AWS": "AWS::Signer::SigningProfile",
            "AWS_RT": "signer:signing-profile"
        },
        {
            "TF": "aws_sns_topic",
            "AWS": "AWS::SNS::Topic",
            "AWS_RT": "sns:topic"
        },
        {
            "TF": "aws_sns_topic_policy",
            "AWS": "AWS::SNS::TopicPolicy",
            "AWS_RT": "sns:topic-policy"
        },
        {
            "TF": "aws_sns_topic_subscription",
            "AWS": "AWS::SNS::Subscription",
            "AWS_RT": "sns:subscription"
        },
        {
            "TF": "aws_sqs_queue",
            "AWS": "AWS::SQS::Queue",
            "AWS_RT": "sqs:queue"
        },
        {
            "TF": "aws_sqs_queue_policy",
            "AWS": "AWS::SQS::QueuePolicy",
            "AWS_RT": "sqs:queue-policy"
        },
        {
            "TF": "aws_ssm_association",
            "AWS": "AWS::SSM::Association",
            "AWS_RT": "ssm:association"
        },
        {
            "TF": "aws_ssm_document",
            "AWS": "AWS::SSM::Document",
            "AWS_RT": "ssm:document"
        },
        {
            "TF": "aws_ssm_maintenance_window",
            "AWS": "AWS::SSM::MaintenanceWindow",
            "AWS_RT": "ssm:maintenance-window"
        },
        {
            "TF": "aws_ssm_maintenance_window_target",
            "AWS": "AWS::SSM::MaintenanceWindowTarget",
            "AWS_RT": "ssm:maintenance-window-target"
        },
        {
            "TF": "aws_ssm_maintenance_window_task",
            "AWS": "AWS::SSM::MaintenanceWindowTask",
            "AWS_RT": "ssm:maintenance-window-task"
        },
        {
            "TF": "aws_ssm_parameter",
            "AWS": "AWS::SSM::Parameter",
            "AWS_RT": "ssm:parameter"
        },
        {
            "TF": "aws_ssm_patch_baseline",
            "AWS": "AWS::SSM::PatchBaseline",
            "AWS_RT": "ssm:patch-baseline"
        },
        {
            "TF": "aws_ssm_resource_data_sync",
            "AWS": "AWS::SSM::ResourceDataSync",
            "AWS_RT": "ssm:resource-data-sync"
        },
        {
            "TF": "aws_subnet",
            "AWS": "AWS::EC2::Subnet",
            "AWS_RT": "ec2:subnet"
        },
        {
            "TF": "aws_synthetics_canary",
            "AWS": "AWS::Synthetics::Canary",
            "AWS_RT": "synthetics:canary"
        },
        {
            "TF": "aws_transfer_server",
            "AWS": "AWS::Transfer::Server",
            "AWS_RT": "transfer:server"
        },
        {
            "TF": "aws_transfer_user",
            "AWS": "AWS::Transfer::User",
            "AWS_RT": "transfer:user"
        },
        {
            "TF": "aws_volume_attachment",
            "AWS": "AWS::EC2::VolumeAttachment",
            "AWS_RT": "ec2:volume-attachment"
        },
        {
            "TF": "aws_vpc",
            "AWS": "AWS::EC2::VPC",
            "AWS_RT": "ec2:vpc"
        },
        {
            "TF": "aws_vpc_dhcp_options_association",
            "AWS": "AWS::EC2::VPCDHCPOptionsAssociation",
            "AWS_RT": "ec2:vpcdhcp-options-association"
        },
        {
            "TF": "aws_vpc_endpoint",
            "AWS": "AWS::EC2::VPCEndpoint",
            "AWS_RT": "ec2:vpc-endpoint"
        },
        {
            "TF": "aws_vpc_endpoint_connection_notification",
            "AWS": "AWS::EC2::VPCEndpointConnectionNotification",
            "AWS_RT": "ec2:vpc-endpoint-connection-notification"
        },
        {
            "TF": "aws_vpc_endpoint_service",
            "AWS": "AWS::EC2::VPCEndpointService",
            "AWS_RT": "ec2:vpc-endpoint-service"
        },
        {
            "TF": "aws_vpc_peering_connection",
            "AWS": "AWS::EC2::VPCPeeringConnection",
            "AWS_RT": "ec2:vpc-peering-connection"
        },
        {
            "TF": "aws_vpn_connection",
            "AWS": "AWS::EC2::VPNConnection",
            "AWS_RT": "ec2:vpn-connection"
        },
        {
            "TF": "aws_vpn_connection_route",
            "AWS": "AWS::EC2::VPNConnectionRoute",
            "AWS_RT": "ec2:vpn-connection-route"
        },
        {
            "TF": "aws_vpn_gateway",
            "AWS": "AWS::EC2::VPNGateway",
            "AWS_RT": "ec2:vpn-gateway"
        },
        {
            "TF": "aws_vpn_gateway_route_propagation",
            "AWS": "AWS::EC2::VPNGatewayRoutePropagation",
            "AWS_RT": "ec2:vpn-gateway-route-propagation"
        },
        {
            "TF": "aws_waf_byte_match_set",
            "AWS": "AWS::WAF::ByteMatchSet",
            "AWS_RT": "waf:byte-match-set"
        },
        {
            "TF": "aws_waf_ipset",
            "AWS": "AWS::WAF::IPSet",
            "AWS_RT": "waf:ip-set"
        },
        {
            "TF": "aws_waf_rule",
            "AWS": "AWS::WAF::Rule",
            "AWS_RT": "waf:rule"
        },
        {
            "TF": "aws_waf_size_constraint_set",
            "AWS": "AWS::WAF::SizeConstraintSet",
            "AWS_RT": "waf:size-constraint-set"
        },
        {
            "TF": "aws_waf_sql_injection_match_set",
            "AWS": "AWS::WAF::SqlInjectionMatchSet",
            "AWS_RT": "waf:sql-injection-match-set"
        },
        {
            "TF": "aws_waf_web_acl",
            "AWS": "AWS::WAF::WebACL",
            "AWS_RT": "waf:web-acl"
        },
        {
            "TF": "aws_waf_xss_match_set",
            "AWS": "AWS::WAF::XssMatchSet",
            "AWS_RT": "waf:xss-match-set"
        },
        {
            "TF": "aws_wafregional_byte_match_set",
            "AWS": "AWS::WAFRegional::ByteMatchSet",
            "AWS_RT": "wafregional:byte-match-set"
        },
        {
            "TF": "aws_wafregional_geo_match_set",
            "AWS": "AWS::WAFRegional::GeoMatchSet",
            "AWS_RT": "wafregional:geo-match-set"
        },
        {
            "TF": "aws_wafregional_ipset",
            "AWS": "AWS::WAFRegional::IPSet",
            "AWS_RT": "wafregional:ip-set"
        },
        {
            "TF": "aws_wafregional_rate_based_rule",
            "AWS": "AWS::WAFRegional::RateBasedRule",
            "AWS_RT": "wafregional:rate-based-rule"
        },
        {
            "TF": "aws_wafregional_regex_pattern_set",
            "AWS": "AWS::WAFRegional::RegexPatternSet",
            "AWS_RT": "wafregional:regex-pattern-set"
        },
        {
            "TF": "aws_wafregional_rule",
            "AWS": "AWS::WAFRegional::Rule",
            "AWS_RT": "wafregional:rule"
        },
        {
            "TF": "aws_wafregional_size_constraint_set",
            "AWS": "AWS::WAFRegional::SizeConstraintSet",
            "AWS_RT": "wafregional:size-constraint-set"
        },
        {
            "TF": "aws_wafregional_sql_injection_match_set",
            "AWS": "AWS::WAFRegional::SqlInjectionMatchSet",
            "AWS_RT": "wafregional:sql-injection-match-set"
        },
        {
            "TF": "aws_wafregional_web_acl",
            "AWS": "AWS::WAFRegional::WebACL",
            "AWS_RT": "wafregional:web-acl"
        },
        {
            "TF": "aws_wafregional_web_acl_association",
            "AWS": "AWS::WAFRegional::WebACLAssociation",
            "AWS_RT": "wafregional:web-acl-association"
        },
        {
            "TF": "aws_wafregional_xss_match_set",
            "AWS": "AWS::WAFRegional::XssMatchSet",
            "AWS_RT": "wafregional:xss-match-set"
        },
        {
            "TF": "aws_wafv2_ip_set",
            "AWS": "AWS::WAFv2::IPSet",
            "AWS_RT": "wafv2:ip-set"
        },
        {
            "TF": "aws_wafv2_regex_pattern_set",
            "AWS": "AWS::WAFv2::RegexPatternSet",
            "AWS_RT": "wafv2:regex-pattern-set"
        },
        {
            "TF": "aws_wafv2_rule_group",
            "AWS": "AWS::WAFv2::RuleGroup",
            "AWS_RT": "wafv2:rule-group"
        },
        {
            "TF": "aws_wafv2_web_acl",
            "AWS": "AWS::WAFv2::WebACL",
            "AWS_RT": "wafv2:web-acl"
        },
        {
            "TF": "aws_wafv2_web_acl_association",
            "AWS": "AWS::WAFv2::WebACLAssociation",
            "AWS_RT": "wafv2:web-acl-association"
        },
        {
            "TF": "aws_workspaces_workspace",
            "AWS": "AWS::WorkSpaces::Workspace",
            "AWS_RT": "workspaces:workspace"
        },
        {
            "TF": "aws_xray_group",
            "AWS": "AWS::XRay::Group",
            "AWS_RT": "xray:group"
        },
        {
            "TF": "aws_xray_sampling_rule",
            "AWS": "AWS::XRay::SamplingRule",
            "AWS_RT": "xray:sampling-rule"
        },
        {
            "TF": "aws_db_instance",
            "AWS": "AWS::RDS::Instance",
            "AWS_RT": "rds:db"
        },
        {
            "TF": "aws_db_snapshot",
            "AWS": "AWS::RDS::Snapshot",
            "AWS_RT": "rds:snapshot"
        },
        {
            "TF": "aws_ebs_snapshot",
            "AWS": "AWS::EC2::Snapshot",
            "AWS_RT": "ec2:snapshot"
        }
    ]
    "#;
    let map: Vec<TerraformMapEntry> = serde_json::from_str(default_json)?;
    Ok(map)
}

fn read_csv_records(path: &str) -> Result<Vec<CSVRecord>, Box<dyn Error>> {
    let mut rdr = ReaderBuilder::new().from_path(path)?;
    let mut records = Vec::new();
    for result in rdr.deserialize() {
        let record: CSVRecord = result?;
        records.push(record);
    }
    Ok(records)
}

fn generate_output(records: Vec<CSVRecord>, map: &[TerraformMapEntry]) -> Result<String, Box<dyn Error>> {
    let mut output = String::new();
    let mut non_matching_records = Vec::new();

    for record in records {
        match map.iter().find(|e| e.aws_rt == record.resource_type) {
            Some(tf_entry) => {
                let resource_name = match record.name.as_deref() {
                    Some("(not tagged)") | None => record.identifier.clone(),
                    Some(name) => name.to_string(),
                };
                let formatted = format!(
                    "import {{\n    id = \"{id}\"\n    to = {tf_type}.{resource_name}\n}}\n\n",
                    id = record.identifier,
                    tf_type = tf_entry.tf,
                    resource_name = format_resource_name(&resource_name)
                );
                output.push_str(&formatted);
            }
            None => non_matching_records.push(record),
        }
    }

    if !non_matching_records.is_empty() {
        output.push_str("\n/*** Non-matching records: ***/\n");
        for record in non_matching_records {
            output.push_str(&format!("/* Identifier: {}, Resource Type: {} - unknown terraform resource */\n", record.identifier, record.resource_type));
        }
    }

    Ok(output)
}


fn format_resource_name(name: &str) -> String {
    // Implement better formatting logic here
    name
    .replace(' ', "_")
    .replace('-', "_")
    .replace('.', "_")
    .replace(':', "_")
    .replace('/', "_")
    .to_lowercase()
}


#[cfg(test)]
mod tests {
    use super::*;

    fn mock_terraform_map_entries() -> Vec<TerraformMapEntry> {
        vec![
            TerraformMapEntry {
                tf: "aws_instance".to_string(),
                aws_rt: "ec2:instance".to_string(),
            },
        ]
    }

    fn mock_csv_records() -> Vec<CSVRecord> {
        vec![
            CSVRecord {
                identifier: "i-07012d8f6a2f55aa3".to_string(),
                resource_type: "ec2:instance".to_string(),
                name: Some("instance with tag name".to_string()),
            }
        ]
    }
    fn expected_import_output(id: &str, tf_type: &str, resource_name: &str) -> String {
        format!(
            "import {{\n    id = \"{id}\"\n    to = {tf_type}.{resource_name}\n}}\n\n",
            id = id,
            tf_type = tf_type,
            resource_name = resource_name
        )
    }
    

    #[test]
    fn test_generate_output() {
        let map_entries = mock_terraform_map_entries();
        let csv_records = mock_csv_records();
        let output = generate_output(csv_records, &map_entries).unwrap();

        let expected_output = expected_import_output("i-07012d8f6a2f55aa3", "aws_instance", "instance_with_tag_name");


        assert_eq!(output, expected_output);
    }

    #[test]
    fn test_format_resource_name() {
        assert_eq!(format_resource_name("instance with-tag.name"), "instance_with_tag_name");
        assert_eq!(format_resource_name("Another-Test"), "another_test");
    }
}
