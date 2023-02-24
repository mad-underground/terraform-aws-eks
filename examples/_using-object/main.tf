module "aws_eks" {
  source = "terraform-aws-modules/eks/aws"
  version = "19.7.0"
  create = local.aws_eks_cluster.create
  tags = local.aws_eks_cluster.tags
  prefix_separator = local.aws_eks_cluster.prefix_separator
  cluster_name = local.aws_eks_cluster.cluster_name
  cluster_version = local.aws_eks_cluster.cluster_version
  cluster_enabled_log_types = local.aws_eks_cluster.cluster_enabled_log_types
  cluster_additional_security_group_ids = local.aws_eks_cluster.cluster_additional_security_group_ids
  control_plane_subnet_ids = local.aws_eks_cluster.control_plane_subnet_ids
  subnet_ids = local.aws_eks_cluster.subnet_ids
  cluster_endpoint_private_access = local.aws_eks_cluster.cluster_endpoint_private_access
  cluster_endpoint_public_access = local.aws_eks_cluster.cluster_endpoint_public_access
  cluster_endpoint_public_access_cidrs = local.aws_eks_cluster.cluster_endpoint_public_access_cidrs
  cluster_ip_family = local.aws_eks_cluster.cluster_ip_family
  cluster_service_ipv4_cidr = local.aws_eks_cluster.cluster_service_ipv4_cidr
  cluster_service_ipv6_cidr = local.aws_eks_cluster.cluster_service_ipv6_cidr
  outpost_config = local.aws_eks_cluster.outpost_config
  cluster_encryption_config = local.aws_eks_cluster.cluster_encryption_config
  attach_cluster_encryption_policy = local.aws_eks_cluster.attach_cluster_encryption_policy
  cluster_tags = local.aws_eks_cluster.cluster_tags
  create_cluster_primary_security_group_tags = local.aws_eks_cluster.create_cluster_primary_security_group_tags
  cluster_timeouts = local.aws_eks_cluster.cluster_timeouts
  create_kms_key = local.aws_eks_cluster.create_kms_key
  kms_key_description = local.aws_eks_cluster.kms_key_description
  kms_key_deletion_window_in_days = local.aws_eks_cluster.kms_key_deletion_window_in_days
  enable_kms_key_rotation = local.aws_eks_cluster.enable_kms_key_rotation
  kms_key_enable_default_policy = local.aws_eks_cluster.kms_key_enable_default_policy
  kms_key_owners = local.aws_eks_cluster.kms_key_owners
  kms_key_administrators = local.aws_eks_cluster.kms_key_administrators
  kms_key_users = local.aws_eks_cluster.kms_key_users
  kms_key_service_users = local.aws_eks_cluster.kms_key_service_users
  kms_key_source_policy_documents = local.aws_eks_cluster.kms_key_source_policy_documents
  kms_key_override_policy_documents = local.aws_eks_cluster.kms_key_override_policy_documents
  kms_key_aliases = local.aws_eks_cluster.kms_key_aliases
  create_cloudwatch_log_group = local.aws_eks_cluster.create_cloudwatch_log_group
  cloudwatch_log_group_retention_in_days = local.aws_eks_cluster.cloudwatch_log_group_retention_in_days
  cloudwatch_log_group_kms_key_id = local.aws_eks_cluster.cloudwatch_log_group_kms_key_id
  create_cluster_security_group = local.aws_eks_cluster.create_cluster_security_group
  cluster_security_group_id = local.aws_eks_cluster.cluster_security_group_id
  vpc_id = local.aws_eks_cluster.vpc_id
  cluster_security_group_name = local.aws_eks_cluster.cluster_security_group_name
  cluster_security_group_use_name_prefix = local.aws_eks_cluster.cluster_security_group_use_name_prefix
  cluster_security_group_description = local.aws_eks_cluster.cluster_security_group_description
  cluster_security_group_additional_rules = local.aws_eks_cluster.cluster_security_group_additional_rules
  cluster_security_group_tags = local.aws_eks_cluster.cluster_security_group_tags
  create_cni_ipv6_iam_policy = local.aws_eks_cluster.create_cni_ipv6_iam_policy
  create_node_security_group = local.aws_eks_cluster.create_node_security_group
  node_security_group_id = local.aws_eks_cluster.node_security_group_id
  node_security_group_name = local.aws_eks_cluster.node_security_group_name
  node_security_group_use_name_prefix = local.aws_eks_cluster.node_security_group_use_name_prefix
  node_security_group_description = local.aws_eks_cluster.node_security_group_description
  node_security_group_additional_rules = local.aws_eks_cluster.node_security_group_additional_rules
  node_security_group_enable_recommended_rules = local.aws_eks_cluster.node_security_group_enable_recommended_rules
  node_security_group_tags = local.aws_eks_cluster.node_security_group_tags
  enable_irsa = local.aws_eks_cluster.enable_irsa
  openid_connect_audiences = local.aws_eks_cluster.openid_connect_audiences
  custom_oidc_thumbprints = local.aws_eks_cluster.custom_oidc_thumbprints
  create_iam_role = local.aws_eks_cluster.create_iam_role
  iam_role_arn = local.aws_eks_cluster.iam_role_arn
  iam_role_name = local.aws_eks_cluster.iam_role_name
  iam_role_use_name_prefix = local.aws_eks_cluster.iam_role_use_name_prefix
  iam_role_path = local.aws_eks_cluster.iam_role_path
  iam_role_description = local.aws_eks_cluster.iam_role_description
  iam_role_permissions_boundary = local.aws_eks_cluster.iam_role_permissions_boundary
  iam_role_additional_policies = local.aws_eks_cluster.iam_role_additional_policies
  cluster_iam_role_dns_suffix = local.aws_eks_cluster.cluster_iam_role_dns_suffix
  iam_role_tags = local.aws_eks_cluster.iam_role_tags
  cluster_encryption_policy_use_name_prefix = local.aws_eks_cluster.cluster_encryption_policy_use_name_prefix
  cluster_encryption_policy_name = local.aws_eks_cluster.cluster_encryption_policy_name
  cluster_encryption_policy_description = local.aws_eks_cluster.cluster_encryption_policy_description
  cluster_encryption_policy_path = local.aws_eks_cluster.cluster_encryption_policy_path
  cluster_encryption_policy_tags = local.aws_eks_cluster.cluster_encryption_policy_tags
  cluster_addons = local.aws_eks_cluster.cluster_addons
  cluster_addons_timeouts = local.aws_eks_cluster.cluster_addons_timeouts
  cluster_identity_providers = local.aws_eks_cluster.cluster_identity_providers
  fargate_profiles = local.aws_eks_cluster.fargate_profiles
  fargate_profile_defaults = local.aws_eks_cluster.fargate_profile_defaults
  self_managed_node_groups = local.aws_eks_cluster.self_managed_node_groups
  self_managed_node_group_defaults = local.aws_eks_cluster.self_managed_node_group_defaults
  eks_managed_node_groups = local.aws_eks_cluster.eks_managed_node_groups
  eks_managed_node_group_defaults = local.aws_eks_cluster.eks_managed_node_group_defaults
  putin_khuylo = local.aws_eks_cluster.putin_khuylo
  manage_aws_auth_configmap = local.aws_eks_cluster.manage_aws_auth_configmap
  create_aws_auth_configmap = local.aws_eks_cluster.create_aws_auth_configmap
  aws_auth_node_iam_role_arns_non_windows = local.aws_eks_cluster.aws_auth_node_iam_role_arns_non_windows
  aws_auth_node_iam_role_arns_windows = local.aws_eks_cluster.aws_auth_node_iam_role_arns_windows
  aws_auth_fargate_profile_pod_execution_role_arns = local.aws_eks_cluster.aws_auth_fargate_profile_pod_execution_role_arns
  aws_auth_roles = local.aws_eks_cluster.aws_auth_roles
  aws_auth_users = local.aws_eks_cluster.aws_auth_users
  aws_auth_accounts = local.aws_eks_cluster.aws_auth_accounts
}