module "eks_managed_node_group" {
  source = "${local.eks_managed_node_group_module_source}"
  version = "${local.eks_module_version}"

  for_each = local.eks_managed_node_groups

  # "The AMI from which to launch the instance. If not supplied, EKS will use its own default image"
  ami_id = try(each.value.ami_id, "")

  # "AMI version of the EKS Node Group. Defaults to latest version for Kubernetes version"
  ami_release_version = try(each.value.ami_release_version, null)

  # "Type of Amazon Machine Image (AMI) associated with the EKS Node Group. Valid values are `AL2_x86_64`, `AL2_x86_64_GPU`, `AL2_ARM_64`, `CUSTOM`, `BOTTLEROCKET_ARM_64`, `BOTTLEROCKET_x86_64`"
  ami_type = try(each.value.ami_type, null)

  # "Specify volumes to attach to the instance besides the volumes specified by the AMI"
  block_device_mappings = try(each.value.block_device_mappings, {})

  # "Additional arguments passed to the bootstrap script. When `platform` = `bottlerocket`; these are additional [settings](https://github.com/bottlerocket-os/bottlerocket#settings) that are provided to the Bottlerocket user data"
  bootstrap_extra_args = try(each.value.bootstrap_extra_args, "")

  # "Targeting for EC2 capacity reservations"
  capacity_reservation_specification = try(each.value.capacity_reservation_specification, {})

  # "Type of capacity associated with the EKS Node Group. Valid values: `ON_DEMAND`, `SPOT`"
  capacity_type = try(each.value.capacity_type, "ON_DEMAND")

  # "Base64 encoded CA of associated EKS cluster"
  cluster_auth_base64 = try(each.value.cluster_auth_base64, "")

  # "Endpoint of associated EKS cluster"
  cluster_endpoint = try(each.value.cluster_endpoint, "")

  # "The IP family used to assign Kubernetes pod and service addresses. Valid values are `ipv4` (default) and `ipv6`"
  cluster_ip_family = try(each.value.cluster_ip_family, null)

  # "Name of associated EKS cluster"
  cluster_name = try(each.value.cluster_name, null)

  # "The ID of the EKS cluster primary security group to associate with the instance(s). This is the security group that is automatically created by the EKS service"
  cluster_primary_security_group_id = try(each.value.cluster_primary_security_group_id, null)

  # "The CIDR block to assign Kubernetes service IP addresses from. If you don't specify a block, Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks"
  cluster_service_ipv4_cidr = try(each.value.cluster_service_ipv4_cidr, null)

  # "Kubernetes version. Defaults to EKS Cluster Kubernetes version"
  cluster_version = try(each.value.cluster_version, null)

  # "The CPU options for the instance"
  cpu_options = try(each.value.cpu_options, {})

  # "Determines whether to create EKS managed node group or not"
  create = try(each.value.create, true)

  # "Determines whether an IAM role is created or to use an existing IAM role"
  create_iam_role = try(each.value.create_iam_role, true)

  # "Determines whether to create a launch template or not. If set to `false`, EKS will use its own default launch template"
  create_launch_template = try(each.value.create_launch_template, true)

  # "Determines whether to create autoscaling group schedule or not"
  create_schedule = try(each.value.create_schedule, true)

  # "Customize the credit specification of the instance"
  credit_specification = try(each.value.credit_specification, {})

  # "Desired number of instances/nodes"
  desired_size = try(each.value.desired_size, 1)

  # "If true, enables EC2 instance termination protection"
  disable_api_termination = try(each.value.disable_api_termination, null)

  # "Disk size in GiB for nodes. Defaults to `20`. Only valid when `use_custom_launch_template` = `false`"
  disk_size = try(each.value.disk_size, null)

  # "If true, the launched EC2 instance(s) will be EBS-optimized"
  ebs_optimized = try(each.value.ebs_optimized, null)

  # "The elastic GPU to attach to the instance"
  elastic_gpu_specifications = try(each.value.elastic_gpu_specifications, {})

  # "Configuration block containing an Elastic Inference Accelerator to attach to the instance"
  elastic_inference_accelerator = try(each.value.elastic_inference_accelerator, {})

  # "Determines whether the bootstrap configurations are populated within the user data template. Only valid when using a custom AMI via `ami_id`"
  enable_bootstrap_user_data = try(each.value.enable_bootstrap_user_data, false)

  # "Enables/disables detailed monitoring"
  enable_monitoring = try(each.value.enable_monitoring, true)

  # "Enable Nitro Enclaves on launched instances"
  enclave_options = try(each.value.enclave_options, {})

  # "Force version update if existing pods are unable to be drained due to a pod disruption budget issue"
  force_update_version = try(each.value.force_update_version, null)

  # "Additional policies to be added to the IAM role"
  iam_role_additional_policies = try(each.value.iam_role_additional_policies, {})

  # "Existing IAM role ARN for the node group. Required if `create_iam_role` is set to `false`"
  iam_role_arn = try(each.value.iam_role_arn, null)

  # "Whether to attach the `AmazonEKS_CNI_Policy`/`AmazonEKS_CNI_IPv6_Policy` IAM policy to the IAM IAM role. WARNING: If set `false` the permissions must be assigned to the `aws-node` DaemonSet pods via another method or nodes will not be able to join the cluster"
  iam_role_attach_cni_policy = try(each.value.iam_role_attach_cni_policy, true)

  # "Description of the role"
  iam_role_description = try(each.value.iam_role_description, null)

  # "Name to use on IAM role created"
  iam_role_name = try(each.value.iam_role_name, null)

  # "IAM role path"
  iam_role_path = try(each.value.iam_role_path, null)

  # "ARN of the policy that is used to set the permissions boundary for the IAM role"
  iam_role_permissions_boundary = try(each.value.iam_role_permissions_boundary, null)

  # "A map of additional tags to add to the IAM role created"
  iam_role_tags = try(each.value.iam_role_tags, {})

  # "Determines whether the IAM role name (`iam_role_name`) is used as a prefix"
  iam_role_use_name_prefix = try(each.value.iam_role_use_name_prefix, true)

  # "The market (purchasing) option for the instance"
  instance_market_options = try(each.value.instance_market_options, {})

  # "Set of instance types associated with the EKS Node Group. Defaults to `[\"t3.medium\"]`"
  instance_types = try(each.value.instance_types, null)

  # "The kernel ID"
  kernel_id = try(each.value.kernel_id, null)

  # "The key name that should be used for the instance(s)"
  key_name = try(each.value.key_name, null)

  # "Key-value map of Kubernetes labels. Only labels that are applied with the EKS API are managed by this argument. Other Kubernetes labels applied to the EKS Node Group will not be managed"
  labels = try(each.value.labels, null)

  # "Default version of the launch template"
  launch_template_default_version = try(each.value.launch_template_default_version, null)

  # "Description of the launch template"
  launch_template_description = try(each.value.launch_template_description, null)

  # "The ID of an existing launch template to use. Required when `create_launch_template` = `false` and `use_custom_launch_template` = `true`"
  launch_template_id = try(each.value.launch_template_id, "")

  # "Name of launch template to be created"
  launch_template_name = try(each.value.launch_template_name, null)

  # "A map of additional tags to add to the tag_specifications of launch template created"
  launch_template_tags = try(each.value.launch_template_tags, {})

  # "Determines whether to use `launch_template_name` as is or create a unique name beginning with the `launch_template_name` as the prefix"
  launch_template_use_name_prefix = try(each.value.launch_template_use_name_prefix, true)

  # "Launch template version number. The default is `$Default`"
  launch_template_version = try(each.value.launch_template_version, null)

  # "A map of license specifications to associate with"
  license_specifications = try(each.value.license_specifications, {})

  # "The maintenance options for the instance"
  maintenance_options = try(each.value.maintenance_options, {})

  # "Maximum number of instances/nodes"
  max_size = try(each.value.max_size, 3)

  # "Customize the metadata options for the instance"
  metadata_options = try(each.value.metadata_options, {
      http_endpoint               = "enabled"
      http_tokens                 = "required"
      http_put_response_hop_limit = 2
    })

  # "Minimum number of instances/nodes"
  min_size = try(each.value.min_size, 0)

  # "Name of the EKS managed node group"
  name = try(each.value.name, "")

  # "Customize network interfaces to be attached at instance boot time"
  network_interfaces = try(each.value.network_interfaces, [])

  # "The placement of the instance"
  placement = try(each.value.placement, {})

  # "Identifies if the OS platform is `bottlerocket` or `linux` based; `windows` is not supported"
  platform = try(each.value.platform, "linux")

  # "User data that is appended to the user data script after of the EKS bootstrap script. Not used when `platform` = `bottlerocket`"
  post_bootstrap_user_data = try(each.value.post_bootstrap_user_data, "")

  # "User data that is injected into the user data script ahead of the EKS bootstrap script. Not used when `platform` = `bottlerocket`"
  pre_bootstrap_user_data = try(each.value.pre_bootstrap_user_data, "")

  # "The options for the instance hostname. The default values are inherited from the subnet"
  private_dns_name_options = try(each.value.private_dns_name_options, {})

  # "The ID of the ram disk"
  ram_disk_id = try(each.value.ram_disk_id, null)

  # "Configuration block with remote access settings. Only valid when `use_custom_launch_template` = `false`"
  remote_access = try(each.value.remote_access, {})

  # "Map of autoscaling group schedule to create"
  schedules = try(each.value.schedules, {})

  # "Identifiers of EC2 Subnets to associate with the EKS Node Group. These subnets must have the following resource tag: `kubernetes.io/cluster/CLUSTER_NAME`"
  subnet_ids = try(each.value.subnet_ids, null)

  # "The tags to apply to the resources during launch"
  tag_specifications = try(each.value.tag_specifications, ["instance", "volume", "network-interface"])

  # "A map of tags to add to all resources"
  tags = try(each.value.tags, {})

  # "The Kubernetes taints to be applied to the nodes in the node group. Maximum of 50 taints per node group"
  taints = try(each.value.taints, {})

  # "Create, update, and delete timeout configurations for the node group"
  timeouts = try(each.value.timeouts, {})

  # "Configuration block of settings for max unavailable resources during node group updates"
  update_config = try(each.value.update_config, {
      max_unavailable_percentage = 33
    })

  # "Whether to update the launch templates default version on each update. Conflicts with `launch_template_default_version`"
  update_launch_template_default_version = try(each.value.update_launch_template_default_version, true)

  # "Determines whether to use a custom launch template or not. If set to `false`, EKS will use its own default launch template"
  use_custom_launch_template = try(each.value.use_custom_launch_template, true)

  # "Determines whether to use `name` as is or create a unique name beginning with the `name` as the prefix"
  use_name_prefix = try(each.value.use_name_prefix, true)

  # "Path to a local, custom user data template file to use when rendering user data"
  user_data_template_path = try(each.value.user_data_template_path, "")

  # "A list of security group IDs to associate"
  vpc_security_group_ids = try(each.value.vpc_security_group_ids, [])

}