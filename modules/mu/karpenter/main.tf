module "eks_karpenter" {
  source = "terraform-aws-modules/eks/aws"
  version = "20.0.0"

  # "Type of the access entry. `EC2_LINUX`, `FARGATE_LINUX`, or `EC2_WINDOWS`; defaults to `EC2_LINUX`"
  access_entry_type = try(local.karpenter.access_entry_type, "EC2_LINUX")

  # "List of SSM Parameter ARNs that Karpenter controller is allowed read access (for retrieving AMI IDs)"
  ami_id_ssm_parameter_arns = try(local.karpenter.ami_id_ssm_parameter_arns, [])

  # "The IP family used to assign Kubernetes pod and service addresses. Valid values are `ipv4` (default) and `ipv6`. Note: If `ipv6` is specified, the `AmazonEKS_CNI_IPv6_Policy` must exist in the account. This policy is created by the EKS module with `create_cni_ipv6_iam_policy = true`"
  cluster_ip_family = try(local.karpenter.cluster_ip_family, null)

  # "The name of the EKS cluster"
  cluster_name = try(local.karpenter.cluster_name, "")

  # "Controls if resources should be created (affects nearly all resources)"
  create = try(local.karpenter.create, true)

  # "Determines whether an access entry is created for the IAM role used by the node IAM role"
  create_access_entry = try(local.karpenter.create_access_entry, true)

  # "Determines whether an IAM role is created"
  create_iam_role = try(local.karpenter.create_iam_role, true)

  # "Whether to create an IAM instance profile"
  create_instance_profile = try(local.karpenter.create_instance_profile, false)

  # "Determines whether an IAM role is created or to use an existing IAM role"
  create_node_iam_role = try(local.karpenter.create_node_iam_role, true)

  # "Determines whether to enable support IAM role for service account"
  enable_irsa = try(local.karpenter.enable_irsa, false)

  # "Determines whether to enable native spot termination handling"
  enable_spot_termination = try(local.karpenter.enable_spot_termination, true)

  # "IAM policy description"
  iam_policy_description = try(local.karpenter.iam_policy_description, "Karpenter controller IAM policy")

  # "Name of the IAM policy"
  iam_policy_name = try(local.karpenter.iam_policy_name, "KarpenterController")

  # "Path of the IAM policy"
  iam_policy_path = try(local.karpenter.iam_policy_path, "/")

  # "Determines whether the name of the IAM policy (`iam_policy_name`) is used as a prefix"
  iam_policy_use_name_prefix = try(local.karpenter.iam_policy_use_name_prefix, true)

  # "IAM role description"
  iam_role_description = try(local.karpenter.iam_role_description, "Karpenter controller IAM role")

  # "Maximum API session duration in seconds between 3600 and 43200"
  iam_role_max_session_duration = try(local.karpenter.iam_role_max_session_duration, null)

  # "Name of the IAM role"
  iam_role_name = try(local.karpenter.iam_role_name, "KarpenterController")

  # "Path of the IAM role"
  iam_role_path = try(local.karpenter.iam_role_path, "/")

  # "Permissions boundary ARN to use for the IAM role"
  iam_role_permissions_boundary_arn = try(local.karpenter.iam_role_permissions_boundary_arn, null)

  # "Policies to attach to the IAM role in `{'static_name' = 'policy_arn'}` format"
  iam_role_policies = try(local.karpenter.iam_role_policies, {})

  # "A map of additional tags to add the the IAM role"
  iam_role_tags = try(local.karpenter.iam_role_tags, {})

  # "Determines whether the name of the IAM role (`iam_role_name`) is used as a prefix"
  iam_role_use_name_prefix = try(local.karpenter.iam_role_use_name_prefix, true)

  # "Name of the [IAM condition operator](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html) to evaluate when assuming the role"
  irsa_assume_role_condition_test = try(local.karpenter.irsa_assume_role_condition_test, "StringEquals")

  # "List of `namespace:serviceaccount`pairs to use in trust policy for IAM role for service accounts"
  irsa_namespace_service_accounts = try(local.karpenter.irsa_namespace_service_accounts, ["karpenter:karpenter"])

  # "OIDC provider arn used in trust policy for IAM role for service accounts"
  irsa_oidc_provider_arn = try(local.karpenter.irsa_oidc_provider_arn, "")

  # "Additional policies to be added to the IAM role"
  node_iam_role_additional_policies = try(local.karpenter.node_iam_role_additional_policies, {})

  # "Existing IAM role ARN for the IAM instance profile. Required if `create_iam_role` is set to `false`"
  node_iam_role_arn = try(local.karpenter.node_iam_role_arn, null)

  # "Whether to attach the `AmazonEKS_CNI_Policy`/`AmazonEKS_CNI_IPv6_Policy` IAM policy to the IAM IAM role. WARNING: If set `false` the permissions must be assigned to the `aws-node` DaemonSet pods via another method or nodes will not be able to join the cluster"
  node_iam_role_attach_cni_policy = try(local.karpenter.node_iam_role_attach_cni_policy, true)

  # "Description of the role"
  node_iam_role_description = try(local.karpenter.node_iam_role_description, null)

  # "Maximum API session duration in seconds between 3600 and 43200"
  node_iam_role_max_session_duration = try(local.karpenter.node_iam_role_max_session_duration, null)

  # "Name to use on IAM role created"
  node_iam_role_name = try(local.karpenter.node_iam_role_name, null)

  # "IAM role path"
  node_iam_role_path = try(local.karpenter.node_iam_role_path, "/")

  # "ARN of the policy that is used to set the permissions boundary for the IAM role"
  node_iam_role_permissions_boundary = try(local.karpenter.node_iam_role_permissions_boundary, null)

  # "A map of additional tags to add to the IAM role created"
  node_iam_role_tags = try(local.karpenter.node_iam_role_tags, {})

  # "Determines whether the IAM role name (`iam_role_name`) is used as a prefix"
  node_iam_role_use_name_prefix = try(local.karpenter.node_iam_role_use_name_prefix, true)

  # "The length of time, in seconds, for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again"
  queue_kms_data_key_reuse_period_seconds = try(local.karpenter.queue_kms_data_key_reuse_period_seconds, null)

  # "The ID of an AWS-managed customer master key (CMK) for Amazon SQS or a custom CMK"
  queue_kms_master_key_id = try(local.karpenter.queue_kms_master_key_id, null)

  # "Boolean to enable server-side encryption (SSE) of message content with SQS-owned encryption keys"
  queue_managed_sse_enabled = try(local.karpenter.queue_managed_sse_enabled, true)

  # "Name of the SQS queue"
  queue_name = try(local.karpenter.queue_name, null)

  # "Prefix used for all event bridge rules"
  rule_name_prefix = try(local.karpenter.rule_name_prefix, "Karpenter")

  # "A map of tags to add to all resources"
  tags = try(local.karpenter.tags, {})

}