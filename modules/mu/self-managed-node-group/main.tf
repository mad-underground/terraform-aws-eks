module "self_managed_node_group" {
  source = "terraform-aws-modules/eks/aws//modules/self-managed-node-group"
  version = "20.0.0"

  for_each = local.self_managed_node_groups

  # "The AMI from which to launch the instance"
  ami_id = try(each.value.ami_id, "")

  # "A map of additional tags to add to the autoscaling group created. Tags are applied to the autoscaling group only and are NOT propagated to instances"
  autoscaling_group_tags = try(each.value.autoscaling_group_tags, {})

  # "A list of one or more availability zones for the group. Used for EC2-Classic and default subnets when not specified with `subnet_ids` argument. Conflicts with `subnet_ids`"
  availability_zones = try(each.value.availability_zones, null)

  # "Specify volumes to attach to the instance besides the volumes specified by the AMI"
  block_device_mappings = try(each.value.block_device_mappings, {})

  # "Additional arguments passed to the bootstrap script. When `platform` = `bottlerocket`; these are additional [settings](https://github.com/bottlerocket-os/bottlerocket#settings) that are provided to the Bottlerocket user data"
  bootstrap_extra_args = try(each.value.bootstrap_extra_args, "")

  # "Indicates whether capacity rebalance is enabled"
  capacity_rebalance = try(each.value.capacity_rebalance, null)

  # "Targeting for EC2 capacity reservations"
  capacity_reservation_specification = try(each.value.capacity_reservation_specification, {})

  # "Base64 encoded CA of associated EKS cluster"
  cluster_auth_base64 = try(each.value.cluster_auth_base64, "")

  # "Endpoint of associated EKS cluster"
  cluster_endpoint = try(each.value.cluster_endpoint, "")

  # "The IP family used to assign Kubernetes pod and service addresses. Valid values are `ipv4` (default) and `ipv6`"
  cluster_ip_family = try(each.value.cluster_ip_family, null)

  # "Name of associated EKS cluster"
  cluster_name = try(each.value.cluster_name, "")

  # "The ID of the EKS cluster primary security group to associate with the instance(s). This is the security group that is automatically created by the EKS service"
  cluster_primary_security_group_id = try(each.value.cluster_primary_security_group_id, null)

  # "Kubernetes cluster version - used to lookup default AMI ID if one is not provided"
  cluster_version = try(each.value.cluster_version, null)

  # "Reserved"
  context = try(each.value.context, null)

  # "The CPU options for the instance"
  cpu_options = try(each.value.cpu_options, {})

  # "Determines whether to create self managed node group or not"
  create = try(each.value.create, true)

  # "Determines whether an access entry is created for the IAM role used by the nodegroup"
  create_access_entry = try(each.value.create_access_entry, true)

  # "Determines whether to create autoscaling group or not"
  create_autoscaling_group = try(each.value.create_autoscaling_group, true)

  # "Determines whether an IAM instance profile is created or to use an existing IAM instance profile"
  create_iam_instance_profile = try(each.value.create_iam_instance_profile, true)

  # "Determines whether to create launch template or not"
  create_launch_template = try(each.value.create_launch_template, true)

  # "Determines whether to create autoscaling group schedule or not"
  create_schedule = try(each.value.create_schedule, true)

  # "Customize the credit specification of the instance"
  credit_specification = try(each.value.credit_specification, {})

  # "The amount of time, in seconds, after a scaling activity completes before another scaling activity can start"
  default_cooldown = try(each.value.default_cooldown, null)

  # "Amount of time, in seconds, until a newly launched instance can contribute to the Amazon CloudWatch metrics. This delay lets an instance finish initializing before Amazon EC2 Auto Scaling aggregates instance metrics, resulting in more reliable usage data"
  default_instance_warmup = try(each.value.default_instance_warmup, null)

  # "Delete timeout to wait for destroying autoscaling group"
  delete_timeout = try(each.value.delete_timeout, null)

  # "The number of Amazon EC2 instances that should be running in the autoscaling group"
  desired_size = try(each.value.desired_size, 1)

  # "If true, enables EC2 instance termination protection"
  disable_api_termination = try(each.value.disable_api_termination, null)

  # "If true, the launched EC2 instance will be EBS-optimized"
  ebs_optimized = try(each.value.ebs_optimized, null)

  # "The elastic GPU to attach to the instance"
  elastic_gpu_specifications = try(each.value.elastic_gpu_specifications, {})

  # "Configuration block containing an Elastic Inference Accelerator to attach to the instance"
  elastic_inference_accelerator = try(each.value.elastic_inference_accelerator, {})

  # "Enables/disables detailed monitoring"
  enable_monitoring = try(each.value.enable_monitoring, true)

  # "A list of metrics to collect. The allowed values are `GroupDesiredCapacity`, `GroupInServiceCapacity`, `GroupPendingCapacity`, `GroupMinSize`, `GroupMaxSize`, `GroupInServiceInstances`, `GroupPendingInstances`, `GroupStandbyInstances`, `GroupStandbyCapacity`, `GroupTerminatingCapacity`, `GroupTerminatingInstances`, `GroupTotalCapacity`, `GroupTotalInstances`"
  enabled_metrics = try(each.value.enabled_metrics, [])

  # "Enable Nitro Enclaves on launched instances"
  enclave_options = try(each.value.enclave_options, {})

  # "Allows deleting the Auto Scaling Group without waiting for all instances in the pool to terminate. You can force an Auto Scaling Group to delete even if it's in the process of scaling a resource. Normally, Terraform drains all the instances before deleting the group. This bypasses that behavior and potentially leaves resources dangling"
  force_delete = try(each.value.force_delete, null)

  # "Allows deleting the Auto Scaling Group without waiting for all instances in the warm pool to terminate"
  force_delete_warm_pool = try(each.value.force_delete_warm_pool, null)

  # "Time (in seconds) after instance comes into service before checking health"
  health_check_grace_period = try(each.value.health_check_grace_period, null)

  # "`EC2` or `ELB`. Controls how health checking is done"
  health_check_type = try(each.value.health_check_type, null)

  # "The hibernation options for the instance"
  hibernation_options = try(each.value.hibernation_options, {})

  # "Amazon Resource Name (ARN) of an existing IAM instance profile that provides permissions for the node group. Required if `create_iam_instance_profile` = `false`"
  iam_instance_profile_arn = try(each.value.iam_instance_profile_arn, null)

  # "Additional policies to be added to the IAM role"
  iam_role_additional_policies = try(each.value.iam_role_additional_policies, {})

  # "ARN of the IAM role used by the instance profile. Required when `create_access_entry = true` and `create_iam_instance_profile = false`"
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

  # "Determines whether cluster IAM role name (`iam_role_name`) is used as a prefix"
  iam_role_use_name_prefix = try(each.value.iam_role_use_name_prefix, true)

  # "One or more Lifecycle Hooks to attach to the Auto Scaling Group before instances are launched. The syntax is exactly the same as the separate `aws_autoscaling_lifecycle_hook` resource, without the `autoscaling_group_name` attribute. Please note that this will only work when creating a new Auto Scaling Group. For all other use-cases, please use `aws_autoscaling_lifecycle_hook` resource"
  initial_lifecycle_hooks = try(each.value.initial_lifecycle_hooks, [])

  # "Shutdown behavior for the instance. Can be `stop` or `terminate`. (Default: `stop`)"
  instance_initiated_shutdown_behavior = try(each.value.instance_initiated_shutdown_behavior, null)

  # "If this block is configured, add a instance maintenance policy to the specified Auto Scaling group"
  instance_maintenance_policy = try(each.value.instance_maintenance_policy, {})

  # "The market (purchasing) option for the instance"
  instance_market_options = try(each.value.instance_market_options, {})

  # "If this block is configured, start an Instance Refresh when this Auto Scaling Group is updated"
  instance_refresh = try(each.value.instance_refresh, {
      strategy = "Rolling"
      preferences = {
        min_healthy_percentage = 66
      })

  # "The attribute requirements for the type of instance. If present then `instance_type` cannot be present"
  instance_requirements = try(each.value.instance_requirements, {})

  # "The type of the instance to launch"
  instance_type = try(each.value.instance_type, "")

  # "The kernel ID"
  kernel_id = try(each.value.kernel_id, null)

  # "The key name that should be used for the instance"
  key_name = try(each.value.key_name, null)

  # "Default Version of the launch template"
  launch_template_default_version = try(each.value.launch_template_default_version, null)

  # "Description of the launch template"
  launch_template_description = try(each.value.launch_template_description, null)

  # "The ID of an existing launch template to use. Required when `create_launch_template` = `false`"
  launch_template_id = try(each.value.launch_template_id, "")

  # "Name of launch template to be created"
  launch_template_name = try(each.value.launch_template_name, null)

  # "A map of additional tags to add to the tag_specifications of launch template created"
  launch_template_tags = try(each.value.launch_template_tags, {})

  # "Determines whether to use `launch_template_name` as is or create a unique name beginning with the `launch_template_name` as the prefix"
  launch_template_use_name_prefix = try(each.value.launch_template_use_name_prefix, true)

  # "Launch template version. Can be version number, `$Latest`, or `$Default`"
  launch_template_version = try(each.value.launch_template_version, null)

  # "A map of license specifications to associate with"
  license_specifications = try(each.value.license_specifications, {})

  # "The maintenance options for the instance"
  maintenance_options = try(each.value.maintenance_options, {})

  # "The maximum amount of time, in seconds, that an instance can be in service, values must be either equal to 0 or between 604800 and 31536000 seconds"
  max_instance_lifetime = try(each.value.max_instance_lifetime, null)

  # "The maximum size of the autoscaling group"
  max_size = try(each.value.max_size, 3)

  # "Customize the metadata options for the instance"
  metadata_options = try(each.value.metadata_options, {
      http_endpoint               = "enabled"
      http_tokens                 = "required"
      http_put_response_hop_limit = 2
    })

  # "The granularity to associate with the metrics to collect. The only valid value is `1Minute`"
  metrics_granularity = try(each.value.metrics_granularity, null)

  # "Setting this causes Terraform to wait for this number of instances to show up healthy in the ELB only on creation. Updates will not wait on ELB instance number changes"
  min_elb_capacity = try(each.value.min_elb_capacity, null)

  # "The minimum size of the autoscaling group"
  min_size = try(each.value.min_size, 0)

  # "Configuration block containing settings to define launch targets for Auto Scaling groups"
  mixed_instances_policy = try(each.value.mixed_instances_policy, null)

  # "Name of the Self managed Node Group"
  name = try(each.value.name, "")

  # "Customize network interfaces to be attached at instance boot time"
  network_interfaces = try(each.value.network_interfaces, [])

  # "The placement of the instance"
  placement = try(each.value.placement, {})

  # "The name of the placement group into which you'll launch your instances, if any"
  placement_group = try(each.value.placement_group, null)

  # "Identifies if the OS platform is `bottlerocket`, `linux`, or `windows` based"
  platform = try(each.value.platform, "linux")

  # "User data that is appended to the user data script after of the EKS bootstrap script. Not used when `platform` = `bottlerocket`"
  post_bootstrap_user_data = try(each.value.post_bootstrap_user_data, "")

  # "User data that is injected into the user data script ahead of the EKS bootstrap script. Not used when `platform` = `bottlerocket`"
  pre_bootstrap_user_data = try(each.value.pre_bootstrap_user_data, "")

  # "The options for the instance hostname. The default values are inherited from the subnet"
  private_dns_name_options = try(each.value.private_dns_name_options, {})

  # "Allows setting instance protection. The autoscaling group will not select instances with this setting for termination during scale in events."
  protect_from_scale_in = try(each.value.protect_from_scale_in, false)

  # "The ID of the ram disk"
  ram_disk_id = try(each.value.ram_disk_id, null)

  # "Map of autoscaling group schedule to create"
  schedules = try(each.value.schedules, {})

  # "The ARN of the service-linked role that the ASG will use to call other AWS services"
  service_linked_role_arn = try(each.value.service_linked_role_arn, null)

  # "A list of subnet IDs to launch resources in. Subnets automatically determine which availability zones the group will reside. Conflicts with `availability_zones`"
  subnet_ids = try(each.value.subnet_ids, null)

  # "A list of processes to suspend for the Auto Scaling Group. The allowed values are `Launch`, `Terminate`, `HealthCheck`, `ReplaceUnhealthy`, `AZRebalance`, `AlarmNotification`, `ScheduledActions`, `AddToLoadBalancer`. Note that if you suspend either the `Launch` or `Terminate` process types, it can prevent your Auto Scaling Group from functioning properly"
  suspended_processes = try(each.value.suspended_processes, [])

  # "The tags to apply to the resources during launch"
  tag_specifications = try(each.value.tag_specifications, ["instance", "volume", "network-interface"])

  # "A map of tags to add to all resources"
  tags = try(each.value.tags, {})

  # "A set of `aws_alb_target_group` ARNs, for use with Application or Network Load Balancing"
  target_group_arns = try(each.value.target_group_arns, [])

  # "A list of policies to decide how the instances in the Auto Scaling Group should be terminated. The allowed values are `OldestInstance`, `NewestInstance`, `OldestLaunchConfiguration`, `ClosestToNextInstanceHour`, `OldestLaunchTemplate`, `AllocationStrategy`, `Default`"
  termination_policies = try(each.value.termination_policies, [])

  # "Whether to update Default Version each update. Conflicts with `launch_template_default_version`"
  update_launch_template_default_version = try(each.value.update_launch_template_default_version, true)

  # "Determines whether to use a mixed instances policy in the autoscaling group or not"
  use_mixed_instances_policy = try(each.value.use_mixed_instances_policy, false)

  # "Determines whether to use `name` as is or create a unique name beginning with the `name` as the prefix"
  use_name_prefix = try(each.value.use_name_prefix, true)

  # "Path to a local, custom user data template file to use when rendering user data"
  user_data_template_path = try(each.value.user_data_template_path, "")

  # "A list of security group IDs to associate"
  vpc_security_group_ids = try(each.value.vpc_security_group_ids, [])

  # "A maximum duration that Terraform should wait for ASG instances to be healthy before timing out. (See also Waiting for Capacity below.) Setting this to '0' causes Terraform to skip all Capacity Waiting behavior."
  wait_for_capacity_timeout = try(each.value.wait_for_capacity_timeout, null)

  # "Setting this will cause Terraform to wait for exactly this number of healthy instances in all attached load balancers on both create and update operations. Takes precedence over `min_elb_capacity` behavior."
  wait_for_elb_capacity = try(each.value.wait_for_elb_capacity, null)

  # "If this block is configured, add a Warm Pool to the specified Auto Scaling group"
  warm_pool = try(each.value.warm_pool, {})

}