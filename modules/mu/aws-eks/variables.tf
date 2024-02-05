variable "cluster" {
  description = "AWS EKS cluster resources to be created"
  default = null
  type = object({
    # "Map of access entries to add to the cluster"
    access_entries = optional(any, {})

    # "Indicates whether or not to attach an additional policy for the cluster IAM role to utilize the encryption key provided"
    attach_cluster_encryption_policy = optional(bool, true)

    # "The authentication mode for the cluster. Valid values are `CONFIG_MAP`, `API` or `API_AND_CONFIG_MAP`"
    authentication_mode = optional(string, "API_AND_CONFIG_MAP")

    # "Specified the log class of the log group. Possible values are: `STANDARD` or `INFREQUENT_ACCESS`"
    cloudwatch_log_group_class = optional(string, null)

    # "If a KMS Key ARN is set, this key will be used to encrypt the corresponding log group. Please be sure that the KMS Key has an appropriate key policy (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html)"
    cloudwatch_log_group_kms_key_id = optional(string, null)

    # "Number of days to retain log events. Default retention - 90 days"
    cloudwatch_log_group_retention_in_days = optional(number, 90)

    # "A map of additional tags to add to the cloudwatch log group created"
    cloudwatch_log_group_tags = optional(map(string), {})

    # "List of additional, externally created security group IDs to attach to the cluster control plane"
    cluster_additional_security_group_ids = optional(list(string), [])

    # "Map of cluster addon configurations to enable for the cluster. Addon name can be the map keys or set with `name`"
    cluster_addons = optional(any, {})

    # "Create, update, and delete timeout configurations for the cluster addons"
    cluster_addons_timeouts = optional(map(string), {})

    # "A list of the desired control plane logs to enable. For more information, see Amazon EKS Control Plane Logging documentation (https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html)"
    cluster_enabled_log_types = optional(list(string), ["audit", "api", "authenticator"])

    # "Configuration block with encryption configuration for the cluster. To disable secret encryption, set this value to `{}`"
    cluster_encryption_config = optional(any, {
      resources = ["secrets"]
    })

    # "Description of the cluster encryption policy created"
    cluster_encryption_policy_description = optional(string, "Cluster encryption policy to allow cluster role to utilize CMK provided")

    # "Name to use on cluster encryption policy created"
    cluster_encryption_policy_name = optional(string, null)

    # "Cluster encryption policy path"
    cluster_encryption_policy_path = optional(string, null)

    # "A map of additional tags to add to the cluster encryption policy created"
    cluster_encryption_policy_tags = optional(map(string), {})

    # "Determines whether cluster encryption policy name (`cluster_encryption_policy_name`) is used as a prefix"
    cluster_encryption_policy_use_name_prefix = optional(bool, true)

    # "Indicates whether or not the Amazon EKS private API server endpoint is enabled"
    cluster_endpoint_private_access = optional(bool, true)

    # "Indicates whether or not the Amazon EKS public API server endpoint is enabled"
    cluster_endpoint_public_access = optional(bool, false)

    # "List of CIDR blocks which can access the Amazon EKS public API server endpoint"
    cluster_endpoint_public_access_cidrs = optional(list(string), ["0.0.0.0/0"])

    # "Map of cluster identity provider configurations to enable for the cluster. Note - this is different/separate from IRSA"
    cluster_identity_providers = optional(any, {})

    # "The IP family used to assign Kubernetes pod and service addresses. Valid values are `ipv4` (default) and `ipv6`. You can only specify an IP family when you create a cluster, changing this value will force a new cluster to be created"
    cluster_ip_family = optional(string, null)

    # "Name of the EKS cluster"
    cluster_name = optional(string, "")

    # "List of additional security group rules to add to the cluster security group created. Set `source_node_security_group = true` inside rules to set the `node_security_group` as source"
    cluster_security_group_additional_rules = optional(any, {})

    # "Description of the cluster security group created"
    cluster_security_group_description = optional(string, "EKS cluster security group")

    # "Existing security group ID to be attached to the cluster"
    cluster_security_group_id = optional(string, "")

    # "Name to use on cluster security group created"
    cluster_security_group_name = optional(string, null)

    # "A map of additional tags to add to the cluster security group created"
    cluster_security_group_tags = optional(map(string), {})

    # "Determines whether cluster security group name (`cluster_security_group_name`) is used as a prefix"
    cluster_security_group_use_name_prefix = optional(bool, true)

    # "The CIDR block to assign Kubernetes service IP addresses from. If you don't specify a block, Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks"
    cluster_service_ipv4_cidr = optional(string, null)

    # "The CIDR block to assign Kubernetes pod and service IP addresses from if `ipv6` was specified when the cluster was created. Kubernetes assigns service addresses from the unique local address range (fc00::/7) because you can't specify a custom IPv6 CIDR block when you create the cluster"
    cluster_service_ipv6_cidr = optional(string, null)

    # "A map of additional tags to add to the cluster"
    cluster_tags = optional(map(string), {})

    # "Create, update, and delete timeout configurations for the cluster"
    cluster_timeouts = optional(map(string), {})

    # "Kubernetes `<major>.<minor>` version to use for the EKS cluster (i.e.: `1.27`)"
    cluster_version = optional(string, null)

    # "A list of subnet IDs where the EKS cluster control plane (ENIs) will be provisioned. Used for expanding the pool of subnets used by nodes/node groups without replacing the EKS control plane"
    control_plane_subnet_ids = optional(list(string), [])

    # "Controls if resources should be created (affects nearly all resources)"
    create = optional(bool, true)

    # "Determines whether a log group is created by this module for the cluster logs. If not, AWS will automatically create one if logging is enabled"
    create_cloudwatch_log_group = optional(bool, true)

    # "Indicates whether or not to tag the cluster's primary security group. This security group is created by the EKS service, not the module, and therefore tagging is handled after cluster creation"
    create_cluster_primary_security_group_tags = optional(bool, true)

    # "Determines if a security group is created for the cluster. Note: the EKS service creates a primary security group for the cluster by default"
    create_cluster_security_group = optional(bool, true)

    # "Determines whether to create an [`AmazonEKS_CNI_IPv6_Policy`](https://docs.aws.amazon.com/eks/latest/userguide/cni-iam-role.html#cni-iam-role-create-ipv6-policy)"
    create_cni_ipv6_iam_policy = optional(bool, false)

    # "Determines whether a an IAM role is created or to use an existing IAM role"
    create_iam_role = optional(bool, true)

    # "Controls if a KMS key for cluster encryption should be created"
    create_kms_key = optional(bool, true)

    # "Determines whether to create a security group for the node groups or use the existing `node_security_group_id`"
    create_node_security_group = optional(bool, true)

    # "Additional list of server certificate thumbprints for the OpenID Connect (OIDC) identity provider's server certificate(s)"
    custom_oidc_thumbprints = optional(list(string), [])

    # "Duration to wait after the EKS cluster has become active before creating the dataplane components (EKS managed nodegroup(s), self-managed nodegroup(s), Fargate profile(s))"
    dataplane_wait_duration = optional(string, "30s")

    # "Map of EKS managed node group default configurations"
    eks_managed_node_group_defaults = optional(any, {})

    # "Map of EKS managed node group definitions to create"
    eks_managed_node_groups = optional(any, {})

    # "Indicates whether or not to add the cluster creator (the identity used by Terraform) as an administrator via access entry"
    enable_cluster_creator_admin_permissions = optional(bool, false)

    # "Determines whether to create an OpenID Connect Provider for EKS to enable IRSA"
    enable_irsa = optional(bool, true)

    # "Specifies whether key rotation is enabled"
    enable_kms_key_rotation = optional(bool, true)

    # "Map of Fargate Profile default configurations"
    fargate_profile_defaults = optional(any, {})

    # "Map of Fargate Profile definitions to create"
    fargate_profiles = optional(any, {})

    # "Additional policies to be added to the IAM role"
    iam_role_additional_policies = optional(map(string), {})

    # "Existing IAM role ARN for the cluster. Required if `create_iam_role` is set to `false`"
    iam_role_arn = optional(string, null)

    # "Description of the role"
    iam_role_description = optional(string, null)

    # "Name to use on IAM role created"
    iam_role_name = optional(string, null)

    # "Cluster IAM role path"
    iam_role_path = optional(string, null)

    # "ARN of the policy that is used to set the permissions boundary for the IAM role"
    iam_role_permissions_boundary = optional(string, null)

    # "A map of additional tags to add to the IAM role created"
    iam_role_tags = optional(map(string), {})

    # "Determines whether the IAM role name (`iam_role_name`) is used as a prefix"
    iam_role_use_name_prefix = optional(bool, true)

    # "Determines whether to include the root CA thumbprint in the OpenID Connect (OIDC) identity provider's server certificate(s)"
    include_oidc_root_ca_thumbprint = optional(bool, true)

    # "A list of IAM ARNs for [key administrators](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#key-policy-default-allow-administrators). If no value is provided, the current caller identity is used to ensure at least one key admin is available"
    kms_key_administrators = optional(list(string), [])

    # "A list of aliases to create. Note - due to the use of `toset()`, values must be static strings and not computed values"
    kms_key_aliases = optional(list(string), [])

    # "The waiting period, specified in number of days. After the waiting period ends, AWS KMS deletes the KMS key. If you specify a value, it must be between `7` and `30`, inclusive. If you do not specify a value, it defaults to `30`"
    kms_key_deletion_window_in_days = optional(number, null)

    # "The description of the key as viewed in AWS console"
    kms_key_description = optional(string, null)

    # "Specifies whether to enable the default key policy"
    kms_key_enable_default_policy = optional(bool, true)

    # "List of IAM policy documents that are merged together into the exported document. In merging, statements with non-blank `sid`s will override statements with the same `sid`"
    kms_key_override_policy_documents = optional(list(string), [])

    # "A list of IAM ARNs for those who will have full key permissions (`kms:*`)"
    kms_key_owners = optional(list(string), [])

    # "A list of IAM ARNs for [key service users](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#key-policy-service-integration)"
    kms_key_service_users = optional(list(string), [])

    # "List of IAM policy documents that are merged together into the exported document. Statements must have unique `sid`s"
    kms_key_source_policy_documents = optional(list(string), [])

    # "A list of IAM ARNs for [key users](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#key-policy-default-allow-users)"
    kms_key_users = optional(list(string), [])

    # "List of additional security group rules to add to the node security group created. Set `source_cluster_security_group = true` inside rules to set the `cluster_security_group` as source"
    node_security_group_additional_rules = optional(any, {})

    # "Description of the node security group created"
    node_security_group_description = optional(string, "EKS node shared security group")

    # "Determines whether to enable recommended security group rules for the node security group created. This includes node-to-node TCP ingress on ephemeral ports and allows all egress traffic"
    node_security_group_enable_recommended_rules = optional(bool, true)

    # "ID of an existing security group to attach to the node groups created"
    node_security_group_id = optional(string, "")

    # "Name to use on node security group created"
    node_security_group_name = optional(string, null)

    # "A map of additional tags to add to the node security group created"
    node_security_group_tags = optional(map(string), {})

    # "Determines whether node security group name (`node_security_group_name`) is used as a prefix"
    node_security_group_use_name_prefix = optional(bool, true)

    # "List of OpenID Connect audience client IDs to add to the IRSA provider"
    openid_connect_audiences = optional(list(string), [])

    # "Configuration for the AWS Outpost to provision the cluster on"
    outpost_config = optional(any, {})

    # "The separator to use between the prefix and the generated timestamp for resource names"
    prefix_separator = optional(string, "-")

    # "Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Putin_khuylo!"
    putin_khuylo = optional(bool, true)

    # "Map of self-managed node group default configurations"
    self_managed_node_group_defaults = optional(any, {})

    # "Map of self-managed node group definitions to create"
    self_managed_node_groups = optional(any, {})

    # "A list of subnet IDs where the nodes/node groups will be provisioned. If `control_plane_subnet_ids` is not provided, the EKS cluster control plane (ENIs) will be provisioned in these subnets"
    subnet_ids = optional(list(string), [])

    # "A map of tags to add to all resources"
    tags = optional(map(string), {})

    # "ID of the VPC where the cluster security group will be provisioned"
    vpc_id = optional(string, null)

  })
}