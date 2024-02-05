variable "karpenter" {
  description = "Node provisioning for Kubernetes"
  default = null
  type = object({
    # "Type of the access entry. `EC2_LINUX`, `FARGATE_LINUX`, or `EC2_WINDOWS`; defaults to `EC2_LINUX`"
    access_entry_type = optional(string, "EC2_LINUX")

    # "List of SSM Parameter ARNs that Karpenter controller is allowed read access (for retrieving AMI IDs)"
    ami_id_ssm_parameter_arns = optional(list(string), [])

    # "The IP family used to assign Kubernetes pod and service addresses. Valid values are `ipv4` (default) and `ipv6`. Note: If `ipv6` is specified, the `AmazonEKS_CNI_IPv6_Policy` must exist in the account. This policy is created by the EKS module with `create_cni_ipv6_iam_policy = true`"
    cluster_ip_family = optional(string, null)

    # "The name of the EKS cluster"
    cluster_name = optional(string, "")

    # "Controls if resources should be created (affects nearly all resources)"
    create = optional(bool, true)

    # "Determines whether an access entry is created for the IAM role used by the node IAM role"
    create_access_entry = optional(bool, true)

    # "Determines whether an IAM role is created"
    create_iam_role = optional(bool, true)

    # "Whether to create an IAM instance profile"
    create_instance_profile = optional(bool, false)

    # "Determines whether an IAM role is created or to use an existing IAM role"
    create_node_iam_role = optional(bool, true)

    # "Determines whether to enable support IAM role for service account"
    enable_irsa = optional(bool, false)

    # "Determines whether to enable native spot termination handling"
    enable_spot_termination = optional(bool, true)

    # "IAM policy description"
    iam_policy_description = optional(string, "Karpenter controller IAM policy")

    # "Name of the IAM policy"
    iam_policy_name = optional(string, "KarpenterController")

    # "Path of the IAM policy"
    iam_policy_path = optional(string, "/")

    # "Determines whether the name of the IAM policy (`iam_policy_name`) is used as a prefix"
    iam_policy_use_name_prefix = optional(bool, true)

    # "IAM role description"
    iam_role_description = optional(string, "Karpenter controller IAM role")

    # "Maximum API session duration in seconds between 3600 and 43200"
    iam_role_max_session_duration = optional(number, null)

    # "Name of the IAM role"
    iam_role_name = optional(string, "KarpenterController")

    # "Path of the IAM role"
    iam_role_path = optional(string, "/")

    # "Permissions boundary ARN to use for the IAM role"
    iam_role_permissions_boundary_arn = optional(string, null)

    # "Policies to attach to the IAM role in `{'static_name' = 'policy_arn'}` format"
    iam_role_policies = optional(map(string), {})

    # "A map of additional tags to add the the IAM role"
    iam_role_tags = optional(map(any), {})

    # "Determines whether the name of the IAM role (`iam_role_name`) is used as a prefix"
    iam_role_use_name_prefix = optional(bool, true)

    # "Name of the [IAM condition operator](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html) to evaluate when assuming the role"
    irsa_assume_role_condition_test = optional(string, "StringEquals")

    # "List of `namespace:serviceaccount`pairs to use in trust policy for IAM role for service accounts"
    irsa_namespace_service_accounts = optional(list(string), ["karpenter:karpenter"])

    # "OIDC provider arn used in trust policy for IAM role for service accounts"
    irsa_oidc_provider_arn = optional(string, "")

    # "Additional policies to be added to the IAM role"
    node_iam_role_additional_policies = optional(map(string), {})

    # "Existing IAM role ARN for the IAM instance profile. Required if `create_iam_role` is set to `false`"
    node_iam_role_arn = optional(string, null)

    # "Whether to attach the `AmazonEKS_CNI_Policy`/`AmazonEKS_CNI_IPv6_Policy` IAM policy to the IAM IAM role. WARNING: If set `false` the permissions must be assigned to the `aws-node` DaemonSet pods via another method or nodes will not be able to join the cluster"
    node_iam_role_attach_cni_policy = optional(bool, true)

    # "Description of the role"
    node_iam_role_description = optional(string, null)

    # "Maximum API session duration in seconds between 3600 and 43200"
    node_iam_role_max_session_duration = optional(number, null)

    # "Name to use on IAM role created"
    node_iam_role_name = optional(string, null)

    # "IAM role path"
    node_iam_role_path = optional(string, "/")

    # "ARN of the policy that is used to set the permissions boundary for the IAM role"
    node_iam_role_permissions_boundary = optional(string, null)

    # "A map of additional tags to add to the IAM role created"
    node_iam_role_tags = optional(map(string), {})

    # "Determines whether the IAM role name (`iam_role_name`) is used as a prefix"
    node_iam_role_use_name_prefix = optional(bool, true)

    # "The length of time, in seconds, for which Amazon SQS can reuse a data key to encrypt or decrypt messages before calling AWS KMS again"
    queue_kms_data_key_reuse_period_seconds = optional(number, null)

    # "The ID of an AWS-managed customer master key (CMK) for Amazon SQS or a custom CMK"
    queue_kms_master_key_id = optional(string, null)

    # "Boolean to enable server-side encryption (SSE) of message content with SQS-owned encryption keys"
    queue_managed_sse_enabled = optional(bool, true)

    # "Name of the SQS queue"
    queue_name = optional(string, null)

    # "Prefix used for all event bridge rules"
    rule_name_prefix = optional(string, "Karpenter")

    # "A map of tags to add to all resources"
    tags = optional(map(string), {})

  })
}
