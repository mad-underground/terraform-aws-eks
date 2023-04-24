variable "karpenter" {
  description = "Node provisioning for Kubernetes"
  default = null
  type = object({
    # "The IP family used to assign Kubernetes pod and service addresses. Valid values are `ipv4` (default) and `ipv6`"
    cluster_ip_family = optional(string, null)

    # "The name of the EKS cluster"
    cluster_name = optional(string, "")

    # "Determines whether to create EKS managed node group or not"
    create = optional(bool, true)

    # "Determines whether an IAM role is created or to use an existing IAM role"
    create_iam_role = optional(bool, true)

    # "Whether to create an IAM instance profile"
    create_instance_profile = optional(bool, true)

    # "Determines whether an IAM role for service accounts is created"
    create_irsa = optional(bool, true)

    # "Determines whether to enable native spot termination handling"
    enable_spot_termination = optional(bool, true)

    # "Additional policies to be added to the IAM role"
    iam_role_additional_policies = optional(list(string), [])

    # "Existing IAM role ARN for the IAM instance profile. Required if `create_iam_role` is set to `false`"
    iam_role_arn = optional(string, null)

    # "Whether to attach the `AmazonEKS_CNI_Policy`/`AmazonEKS_CNI_IPv6_Policy` IAM policy to the IAM IAM role. WARNING: If set `false` the permissions must be assigned to the `aws-node` DaemonSet pods via another method or nodes will not be able to join the cluster"
    iam_role_attach_cni_policy = optional(bool, true)

    # "Description of the role"
    iam_role_description = optional(string, null)

    # "Maximum API session duration in seconds between 3600 and 43200"
    iam_role_max_session_duration = optional(number, null)

    # "Name to use on IAM role created"
    iam_role_name = optional(string, null)

    # "IAM role path"
    iam_role_path = optional(string, "/")

    # "ARN of the policy that is used to set the permissions boundary for the IAM role"
    iam_role_permissions_boundary = optional(string, null)

    # "A map of additional tags to add to the IAM role created"
    iam_role_tags = optional(map(string), {})

    # "Determines whether the IAM role name (`iam_role_name`) is used as a prefix"
    iam_role_use_name_prefix = optional(bool, true)

    # "Name of the [IAM condition operator](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html) to evaluate when assuming the role"
    irsa_assume_role_condition_test = optional(string, "StringEquals")

    # "IAM role for service accounts description"
    irsa_description = optional(string, "Karpenter IAM role for service account")

    # "Maximum API session duration in seconds between 3600 and 43200"
    irsa_max_session_duration = optional(number, null)

    # "Name of IAM role for service accounts"
    irsa_name = optional(string, null)

    # "List of `namespace:serviceaccount`pairs to use in trust policy for IAM role for service accounts"
    irsa_namespace_service_accounts = optional(list(string), ["karpenter:karpenter"])

    # "OIDC provider arn used in trust policy for IAM role for service accounts"
    irsa_oidc_provider_arn = optional(string, "")

    # "Path of IAM role for service accounts"
    irsa_path = optional(string, "/")

    # "Permissions boundary ARN to use for IAM role for service accounts"
    irsa_permissions_boundary_arn = optional(string, null)

    # "Name of IAM policy for service accounts"
    irsa_policy_name = optional(string, null)

    # "List of SSM Parameter ARNs that contain AMI IDs launched by Karpenter"
    irsa_ssm_parameter_arns = optional(list(string), ["arn:aws:ssm:*:*:parameter/aws/service/*"])

    # "Account ID of where the subnets Karpenter will utilize resides. Used when subnets are shared from another account"
    irsa_subnet_account_id = optional(string, "")

    # "Tag key (`{key = value}`) applied to resources launched by Karpenter through the Karpenter provisioner"
    irsa_tag_key = optional(string, "karpenter.sh/discovery")

    # "A map of additional tags to add the the IAM role for service accounts"
    irsa_tags = optional(map(any), {})

    # "Determines whether the IAM role for service accounts name (`irsa_name`) is used as a prefix"
    irsa_use_name_prefix = optional(bool, true)

    # "Policies to attach to the IAM role in `{'static_name' = 'policy_arn'}` format"
    policies = optional(map(string), {})

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
