module "eks_karpenter" {
  source = "${local.eks_karpenter_source}"
  version = "${local.eks_karpenter_version}"

  # "The IP family used to assign Kubernetes pod and service addresses. Valid values are `ipv4` (default) and `ipv6`"
  cluster_ip_family = try(local.karpenter.cluster_ip_family, null)

  # "The name of the EKS cluster"
  cluster_name = try(local.karpenter.cluster_name, "")

  # "Determines whether to create EKS managed node group or not"
  create = try(local.karpenter.create, true)

  # "Determines whether an IAM role is created or to use an existing IAM role"
  create_iam_role = try(local.karpenter.create_iam_role, true)

  # "Whether to create an IAM instance profile"
  create_instance_profile = try(local.karpenter.create_instance_profile, true)

  # "Determines whether an IAM role for service accounts is created"
  create_irsa = try(local.karpenter.create_irsa, true)

  # "Determines whether to enable native spot termination handling"
  enable_spot_termination = try(local.karpenter.enable_spot_termination, true)

  # "Additional policies to be added to the IAM role"
  iam_role_additional_policies = try(local.karpenter.iam_role_additional_policies, [])

  # "Existing IAM role ARN for the IAM instance profile. Required if `create_iam_role` is set to `false`"
  iam_role_arn = try(local.karpenter.iam_role_arn, null)

  # "Whether to attach the `AmazonEKS_CNI_Policy`/`AmazonEKS_CNI_IPv6_Policy` IAM policy to the IAM IAM role. WARNING: If set `false` the permissions must be assigned to the `aws-node` DaemonSet pods via another method or nodes will not be able to join the cluster"
  iam_role_attach_cni_policy = try(local.karpenter.iam_role_attach_cni_policy, true)

  # "Description of the role"
  iam_role_description = try(local.karpenter.iam_role_description, null)

  # "Maximum API session duration in seconds between 3600 and 43200"
  iam_role_max_session_duration = try(local.karpenter.iam_role_max_session_duration, null)

  # "Name to use on IAM role created"
  iam_role_name = try(local.karpenter.iam_role_name, null)

  # "IAM role path"
  iam_role_path = try(local.karpenter.iam_role_path, "/")

  # "ARN of the policy that is used to set the permissions boundary for the IAM role"
  iam_role_permissions_boundary = try(local.karpenter.iam_role_permissions_boundary, null)

  # "A map of additional tags to add to the IAM role created"
  iam_role_tags = try(local.karpenter.iam_role_tags, {})

  # "Determines whether the IAM role name (`iam_role_name`) is used as a prefix"
  iam_role_use_name_prefix = try(local.karpenter.iam_role_use_name_prefix, true)

  # "Name of the [IAM condition operator](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html) to evaluate when assuming the role"
  irsa_assume_role_condition_test = try(local.karpenter.irsa_assume_role_condition_test, "StringEquals")

  # "IAM role for service accounts description"
  irsa_description = try(local.karpenter.irsa_description, "Karpenter IAM role for service account")

  # "Maximum API session duration in seconds between 3600 and 43200"
  irsa_max_session_duration = try(local.karpenter.irsa_max_session_duration, null)

  # "Name of IAM role for service accounts"
  irsa_name = try(local.karpenter.irsa_name, null)

  # "List of `namespace:serviceaccount`pairs to use in trust policy for IAM role for service accounts"
  irsa_namespace_service_accounts = try(local.karpenter.irsa_namespace_service_accounts, ["karpenter:karpenter"])

  # "OIDC provider arn used in trust policy for IAM role for service accounts"
  irsa_oidc_provider_arn = try(local.karpenter.irsa_oidc_provider_arn, "")

  # "Path of IAM role for service accounts"
  irsa_path = try(local.karpenter.irsa_path, "/")

  # "Permissions boundary ARN to use for IAM role for service accounts"
  irsa_permissions_boundary_arn = try(local.karpenter.irsa_permissions_boundary_arn, null)

  # "Name of IAM policy for service accounts"
  irsa_policy_name = try(local.karpenter.irsa_policy_name, null)

  # "List of SSM Parameter ARNs that contain AMI IDs launched by Karpenter"
  irsa_ssm_parameter_arns = try(local.karpenter.irsa_ssm_parameter_arns, ["arn:aws:ssm:*:*:parameter/aws/service/*"])

  # "Account ID of where the subnets Karpenter will utilize resides. Used when subnets are shared from another account"
  irsa_subnet_account_id = try(local.karpenter.irsa_subnet_account_id, "")

  # "Tag key (`{key = value}`) applied to resources launched by Karpenter through the Karpenter provisioner"
  irsa_tag_key = try(local.karpenter.irsa_tag_key, "karpenter.sh/discovery")

  # "A map of additional tags to add the the IAM role for service accounts"
  irsa_tags = try(local.karpenter.irsa_tags, {})

  # "Determines whether the IAM role for service accounts name (`irsa_name`) is used as a prefix"
  irsa_use_name_prefix = try(local.karpenter.irsa_use_name_prefix, true)

  # "Policies to attach to the IAM role in `{'static_name' = 'policy_arn'}` format"
  policies = try(local.karpenter.policies, {})

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