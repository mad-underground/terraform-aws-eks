variable "eks_managed_node_groups" {
  description = "AWS EKS managed node group to be created"
  default = null
  type = object({
    # "The AMI from which to launch the instance. If not supplied, EKS will use its own default image"
    ami_id = optional(string, "")

    # "AMI version of the EKS Node Group. Defaults to latest version for Kubernetes version"
    ami_release_version = optional(string, null)

    # "Type of Amazon Machine Image (AMI) associated with the EKS Node Group. See the [AWS documentation](https://docs.aws.amazon.com/eks/latest/APIReference/API_Nodegroup.html#AmazonEKS-Type-Nodegroup-amiType) for valid values"
    ami_type = optional(string, null)

    # "Specify volumes to attach to the instance besides the volumes specified by the AMI"
    block_device_mappings = optional(any, {})

    # "Additional arguments passed to the bootstrap script. When `platform` = `bottlerocket`; these are additional [settings](https://github.com/bottlerocket-os/bottlerocket#settings) that are provided to the Bottlerocket user data"
    bootstrap_extra_args = optional(string, "")

    # "Targeting for EC2 capacity reservations"
    capacity_reservation_specification = optional(any, {})

    # "Type of capacity associated with the EKS Node Group. Valid values: `ON_DEMAND`, `SPOT`"
    capacity_type = optional(string, "ON_DEMAND")

    # "Base64 encoded CA of associated EKS cluster"
    cluster_auth_base64 = optional(string, "")

    # "Endpoint of associated EKS cluster"
    cluster_endpoint = optional(string, "")

    # "The IP family used to assign Kubernetes pod and service addresses. Valid values are `ipv4` (default) and `ipv6`"
    cluster_ip_family = optional(string, null)

    # "Name of associated EKS cluster"
    cluster_name = optional(string, null)

    # "The ID of the EKS cluster primary security group to associate with the instance(s). This is the security group that is automatically created by the EKS service"
    cluster_primary_security_group_id = optional(string, null)

    # "The CIDR block to assign Kubernetes service IP addresses from. If you don't specify a block, Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks"
    cluster_service_ipv4_cidr = optional(string, null)

    # "Kubernetes version. Defaults to EKS Cluster Kubernetes version"
    cluster_version = optional(string, null)

    # "The CPU options for the instance"
    cpu_options = optional(map(string), {})

    # "Determines whether to create EKS managed node group or not"
    create = optional(bool, true)

    # "Determines whether an IAM role is created or to use an existing IAM role"
    create_iam_role = optional(bool, true)

    # "Determines whether to create a launch template or not. If set to `false`, EKS will use its own default launch template"
    create_launch_template = optional(bool, true)

    # "Determines whether to create autoscaling group schedule or not"
    create_schedule = optional(bool, true)

    # "Customize the credit specification of the instance"
    credit_specification = optional(map(string), {})

    # "Desired number of instances/nodes"
    desired_size = optional(number, 1)

    # "If true, enables EC2 instance termination protection"
    disable_api_termination = optional(bool, null)

    # "Disk size in GiB for nodes. Defaults to `20`. Only valid when `use_custom_launch_template` = `false`"
    disk_size = optional(number, null)

    # "If true, the launched EC2 instance(s) will be EBS-optimized"
    ebs_optimized = optional(bool, null)

    # "The elastic GPU to attach to the instance"
    elastic_gpu_specifications = optional(any, {})

    # "Configuration block containing an Elastic Inference Accelerator to attach to the instance"
    elastic_inference_accelerator = optional(map(string), {})

    # "Determines whether the bootstrap configurations are populated within the user data template. Only valid when using a custom AMI via `ami_id`"
    enable_bootstrap_user_data = optional(bool, false)

    # "Enables/disables detailed monitoring"
    enable_monitoring = optional(bool, true)

    # "Enable Nitro Enclaves on launched instances"
    enclave_options = optional(map(string), {})

    # "Force version update if existing pods are unable to be drained due to a pod disruption budget issue"
    force_update_version = optional(bool, null)

    # "Additional policies to be added to the IAM role"
    iam_role_additional_policies = optional(map(string), {})

    # "Existing IAM role ARN for the node group. Required if `create_iam_role` is set to `false`"
    iam_role_arn = optional(string, null)

    # "Whether to attach the `AmazonEKS_CNI_Policy`/`AmazonEKS_CNI_IPv6_Policy` IAM policy to the IAM IAM role. WARNING: If set `false` the permissions must be assigned to the `aws-node` DaemonSet pods via another method or nodes will not be able to join the cluster"
    iam_role_attach_cni_policy = optional(bool, true)

    # "Description of the role"
    iam_role_description = optional(string, null)

    # "Name to use on IAM role created"
    iam_role_name = optional(string, null)

    # "IAM role path"
    iam_role_path = optional(string, null)

    # "ARN of the policy that is used to set the permissions boundary for the IAM role"
    iam_role_permissions_boundary = optional(string, null)

    # "A map of additional tags to add to the IAM role created"
    iam_role_tags = optional(map(string), {})

    # "Determines whether the IAM role name (`iam_role_name`) is used as a prefix"
    iam_role_use_name_prefix = optional(bool, true)

    # "The market (purchasing) option for the instance"
    instance_market_options = optional(any, {})

    # "Set of instance types associated with the EKS Node Group. Defaults to `[\"t3.medium\"]`"
    instance_types = optional(list(string), null)

    # "The kernel ID"
    kernel_id = optional(string, null)

    # "The key name that should be used for the instance(s)"
    key_name = optional(string, null)

    # "Key-value map of Kubernetes labels. Only labels that are applied with the EKS API are managed by this argument. Other Kubernetes labels applied to the EKS Node Group will not be managed"
    labels = optional(map(string), null)

    # "Default version of the launch template"
    launch_template_default_version = optional(string, null)

    # "Description of the launch template"
    launch_template_description = optional(string, null)

    # "The ID of an existing launch template to use. Required when `create_launch_template` = `false` and `use_custom_launch_template` = `true`"
    launch_template_id = optional(string, "")

    # "Name of launch template to be created"
    launch_template_name = optional(string, null)

    # "A map of additional tags to add to the tag_specifications of launch template created"
    launch_template_tags = optional(map(string), {})

    # "Determines whether to use `launch_template_name` as is or create a unique name beginning with the `launch_template_name` as the prefix"
    launch_template_use_name_prefix = optional(bool, true)

    # "Launch template version number. The default is `$Default`"
    launch_template_version = optional(string, null)

    # "A map of license specifications to associate with"
    license_specifications = optional(any, {})

    # "The maintenance options for the instance"
    maintenance_options = optional(any, {})

    # "Maximum number of instances/nodes"
    max_size = optional(number, 3)

    # "Customize the metadata options for the instance"
    metadata_options = optional(map(string), {
      http_endpoint               = "enabled"
      http_tokens                 = "required"
      http_put_response_hop_limit = 2
    })

    # "Minimum number of instances/nodes"
    min_size = optional(number, 0)

    # "Name of the EKS managed node group"
    name = optional(string, "")

    # "Customize network interfaces to be attached at instance boot time"
    network_interfaces = optional(list(any), [])

    # "The placement of the instance"
    placement = optional(map(string), {})

    # "Identifies if the OS platform is `bottlerocket` or `linux` based; `windows` is not supported"
    platform = optional(string, "linux")

    # "User data that is appended to the user data script after of the EKS bootstrap script. Not used when `platform` = `bottlerocket`"
    post_bootstrap_user_data = optional(string, "")

    # "User data that is injected into the user data script ahead of the EKS bootstrap script. Not used when `platform` = `bottlerocket`"
    pre_bootstrap_user_data = optional(string, "")

    # "The options for the instance hostname. The default values are inherited from the subnet"
    private_dns_name_options = optional(map(string), {})

    # "The ID of the ram disk"
    ram_disk_id = optional(string, null)

    # "Configuration block with remote access settings. Only valid when `use_custom_launch_template` = `false`"
    remote_access = optional(any, {})

    # "Map of autoscaling group schedule to create"
    schedules = optional(map(any), {})

    # "Identifiers of EC2 Subnets to associate with the EKS Node Group. These subnets must have the following resource tag: `kubernetes.io/cluster/CLUSTER_NAME`"
    subnet_ids = optional(list(string), null)

    # "The tags to apply to the resources during launch"
    tag_specifications = optional(list(string), ["instance", "volume", "network-interface"])

    # "A map of tags to add to all resources"
    tags = optional(map(string), {})

    # "The Kubernetes taints to be applied to the nodes in the node group. Maximum of 50 taints per node group"
    taints = optional(any, {})

    # "Create, update, and delete timeout configurations for the node group"
    timeouts = optional(map(string), {})

    # "Configuration block of settings for max unavailable resources during node group updates"
    update_config = optional(map(string), {
      max_unavailable_percentage = 33
    })

    # "Whether to update the launch templates default version on each update. Conflicts with `launch_template_default_version`"
    update_launch_template_default_version = optional(bool, true)

    # "Determines whether to use a custom launch template or not. If set to `false`, EKS will use its own default launch template"
    use_custom_launch_template = optional(bool, true)

    # "Determines whether to use `name` as is or create a unique name beginning with the `name` as the prefix"
    use_name_prefix = optional(bool, true)

    # "Path to a local, custom user data template file to use when rendering user data"
    user_data_template_path = optional(string, "")

    # "A list of security group IDs to associate"
    vpc_security_group_ids = optional(list(string), [])

  })
}
