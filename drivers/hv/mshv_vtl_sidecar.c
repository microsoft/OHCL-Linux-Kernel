// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2024, Microsoft Corporation.
 *
 */
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/mod_devicetable.h>
#include <linux/mm.h>
#include <uapi/linux/mshv.h>
#include <asm/apic.h>
#include <asm/irq_vectors.h>

struct sidecar_control {
	u32 index;
	u32 base_cpu;
	u32 cpu_count;
	u32 request_vector;
	u32 response_cpu;
	u32 response_vector;
	u32 needs_attention;
	u8 reserved[36];
	u8 cpu_status[4032];
};

#define CPU_STATUS_REMOVED 0
#define CPU_STATUS_IDLE 1
#define CPU_STATUS_RUN 2
#define CPU_STATUS_STOP 3
#define CPU_STATUS_REMOVE 4

static_assert(sizeof(struct sidecar_control) == 4096);

static LIST_HEAD(sidecar_dev_list);

struct sidecar_dev {
	struct device *dev;
	struct sidecar_control *control;
	struct wait_queue_head wait;
	struct resource *shmem_pages;
	u32 base_cpu;
	u32 cpu_count;
	u32 index;
	u32 per_cpu_shmem;
	u8 *vp_state;
	u32 needs_vp_scan;
	u32 num_vps_stopped;
	struct mutex scan_mutex;
	struct miscdevice misc;
	struct list_head list;
};

DEFINE_PER_CPU(struct sidecar_dev *, sidecar_interrupt_dev);

#define VP_STATE_AVAIL 0
#define VP_STATE_SYNC 1
#define VP_STATE_ASYNC 2
#define VP_STATE_ASYNC_STOPPING 3
#define VP_STATE_ASYNC_STOPPED 4
#define VP_STATE_REMOVED 0xff

void mshv_vtl_sidecar_isr(void)
{
	struct sidecar_dev *dev;

	dev = this_cpu_read(sidecar_interrupt_dev);
	if (!dev)
		return;
	if (!READ_ONCE(dev->control->needs_attention))
		return;
	WRITE_ONCE(dev->needs_vp_scan, 1);
	xchg(&dev->control->needs_attention, 0);
	wake_up_poll(&dev->wait, EPOLLIN);
}

static void sidecar_signal(struct sidecar_dev *dev, u32 cpu)
{
	if (dev->control->request_vector)
		__apic_send_IPI(cpu, dev->control->request_vector);
}

static int sidecar_claim(struct sidecar_dev *dev, u32 cpu, u8 state)
{
	u8 last;

	if (cpu < dev->base_cpu || cpu - dev->base_cpu >= dev->cpu_count)
		return -EINVAL;

	last = cmpxchg(&dev->vp_state[cpu - dev->base_cpu], VP_STATE_AVAIL, state);
	if (last == VP_STATE_AVAIL)
		return 0;
	else if (last == VP_STATE_REMOVED)
		return -ENOENT;
	else
		return -EBUSY;
}

static struct sidecar_dev *sidecar_dev_for_cpu(unsigned int cpu)
{
	struct sidecar_dev *dev;

	list_for_each_entry(dev, &sidecar_dev_list, list) {
		if (cpu >= dev->base_cpu && cpu - dev->base_cpu < dev->cpu_count)
			return dev;
	}

	return NULL;
}

static int sidecar_remove(unsigned int cpu)
{
	struct sidecar_dev *dev;
	u8 *slot;
	int ret;
	int cpu_index;

	dev = sidecar_dev_for_cpu(cpu);
	if (!dev)
		return 0;

	cpu_index = cpu - dev->base_cpu;

	ret = sidecar_claim(dev, cpu, VP_STATE_REMOVED);
	if (ret)
		return ret;

	/*
	 * If the cpu was already online, then skip this bit,
	 * because the AP is already running here.
	 */
	if (cpu_online(cpu)) {
		dev_info(dev->dev, "%d already online", cpu);
		return 0;
	}

	dev_info(dev->dev, "removing sidecar cpu %d", cpu);
	slot = &dev->control->cpu_status[cpu_index];
	if (cmpxchg(slot, CPU_STATUS_IDLE, CPU_STATUS_REMOVE) != CPU_STATUS_IDLE)
		BUG();

	sidecar_signal(dev, cpu);
	wait_event(dev->wait, READ_ONCE(*slot) == CPU_STATUS_REMOVE);
	BUG_ON(READ_ONCE(dev->vp_state[cpu_index]) != VP_STATE_REMOVED);
	return 0;

}

static void sidecar_scan_vps(struct sidecar_dev *dev)
{
	u32 count;
	u32 i;
	u8 *slot;
	u8 state;

	if (!READ_ONCE(dev->needs_vp_scan))
		return;
	xchg(&dev->needs_vp_scan, 0);

	mutex_lock(&dev->scan_mutex);
	count = dev->cpu_count;
	for (i = 0; i < count; i++) {
		slot = &dev->control->cpu_status[i];
		if (READ_ONCE(*slot) != CPU_STATUS_IDLE)
			continue;
		state = READ_ONCE(dev->vp_state[i]);
		if (state != VP_STATE_ASYNC_STOPPING && state != VP_STATE_ASYNC)
			continue;

		WRITE_ONCE(dev->vp_state[i], VP_STATE_ASYNC_STOPPED);
		xadd(&dev->num_vps_stopped, 1);
	}
	mutex_unlock(&dev->scan_mutex);
}

static int sidecar_scan_next_stopped(struct sidecar_dev *dev)
{
	u32 count;
	u32 i;
	u8 state;

	sidecar_scan_vps(dev);
	if (READ_ONCE(dev->num_vps_stopped) == 0)
		return -1;

	count = dev->cpu_count;
	for (i = 0; i < count; i++) {
		state = dev->vp_state[i];
		if (state == VP_STATE_ASYNC_STOPPED) {
			xadd(&dev->num_vps_stopped, -1);
			WRITE_ONCE(dev->vp_state[i], VP_STATE_AVAIL);
			return dev->base_cpu + i;
		}
	}

	return -1;
}

static __poll_t sidecar_poll(struct file *filp, poll_table *wait)
{
	struct sidecar_dev *dev;
	__poll_t mask = 0;

	dev = filp->private_data;
	poll_wait(filp, &dev->wait, wait);
	sidecar_scan_vps(dev);
	if (READ_ONCE(dev->num_vps_stopped) > 0)
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static void sidecar_start(struct sidecar_dev *dev, u32 cpu)
{
	u8 *slot;

	slot = &dev->control->cpu_status[cpu - dev->base_cpu];
	if (cmpxchg(slot, CPU_STATUS_IDLE, CPU_STATUS_RUN) != CPU_STATUS_IDLE)
		BUG();

	sidecar_signal(dev, cpu);
}

static int sidecar_ioctl_run(struct sidecar_dev *dev, u32 cpu)
{
	u8 *slot;
	u8 status;
	int ret;
	u32 cpu_index;

	ret = sidecar_claim(dev, cpu, VP_STATE_SYNC);
	if (ret)
		return ret;

	sidecar_start(dev, cpu);

	/* Wait for the request to complete. */
	cpu_index = cpu - dev->base_cpu;
	slot = &dev->control->cpu_status[cpu_index];
	if (!wait_event_interruptible(dev->wait, READ_ONCE(*slot) == CPU_STATUS_IDLE))
		goto release;

	/* Cancel the request. */
	while ((status = READ_ONCE(*slot)) != CPU_STATUS_IDLE) {
		switch (status) {
		case CPU_STATUS_STOP:
			wait_event(dev->wait, READ_ONCE(*slot) != status);
			break;
		case CPU_STATUS_RUN:
			cmpxchg(slot, status, CPU_STATUS_STOP);
			break;
		default:
			BUG();
		}
	}

release:
	WRITE_ONCE(dev->vp_state[cpu_index], VP_STATE_AVAIL);
	return ret;
}

static int sidecar_ioctl_start(struct sidecar_dev *dev, u32 cpu)
{
	int ret;

	ret = sidecar_claim(dev, cpu, VP_STATE_ASYNC);
	if (ret)
		return ret;

	sidecar_start(dev, cpu);
	return 0;
}

static int sidecar_ioctl_stop(struct sidecar_dev *dev, u32 cpu)
{
	u32 cpu_index;
	u8 status;
	u8 state;
	u8 *slot;

	if (cpu < dev->base_cpu || cpu - dev->base_cpu >= dev->control->cpu_count)
		return -EINVAL;

	cpu_index = cpu - dev->base_cpu;
	state = cmpxchg(&dev->vp_state[cpu_index], VP_STATE_ASYNC, VP_STATE_ASYNC_STOPPING);
	switch (state) {
	case VP_STATE_AVAIL:
	case VP_STATE_SYNC:
	case VP_STATE_REMOVED:
		return -EINVAL;
	case VP_STATE_ASYNC:
		break;
	case VP_STATE_ASYNC_STOPPED:
	case VP_STATE_ASYNC_STOPPING:
		return 0;
	default:
		BUG();
	}

	slot = &dev->control->cpu_status[cpu_index];
	status = READ_ONCE(*slot);
	if (status == CPU_STATUS_RUN) {
		status = cmpxchg(slot, CPU_STATUS_RUN, CPU_STATUS_STOP);
		if (status == CPU_STATUS_RUN) {
			sidecar_signal(dev, cpu);
			return 0;
		}
	}

	BUG_ON(status != CPU_STATUS_IDLE);
	return 0;
}

static int sidecar_ioctl_info(struct sidecar_dev *dev, unsigned long arg)
{
	struct mshv_vtl_sidecar_info info = {
		.cpu_count = dev->cpu_count,
		.base_cpu = dev->base_cpu,
		.per_cpu_shmem = dev->per_cpu_shmem,
	};

	if (copy_to_user((void __user *)arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static long sidecar_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct sidecar_dev *dev;

	dev = filp->private_data;
	switch (cmd) {
	case MSHV_VTL_SIDECAR_START:
		return sidecar_ioctl_start(dev, arg);
	case MSHV_VTL_SIDECAR_STOP:
		return sidecar_ioctl_stop(dev, arg);
	case MSHV_VTL_SIDECAR_RUN:
		return sidecar_ioctl_run(dev, arg);
	case MSHV_VTL_SIDECAR_INFO:
		return sidecar_ioctl_info(dev, arg);
	default:
		return -ENOTTY;
	}
}

static ssize_t sidecar_read(struct file *filp, char __user *buf, size_t count, loff_t *pos)
{
	struct sidecar_dev  *dev;
	u32 cpu;
	int ret;

	dev = filp->private_data;
	if (count < sizeof(u32))
		return -EINVAL;

	for (;;) {
		ret = sidecar_scan_next_stopped(dev);
		if (ret >= 0) {
			cpu = ret;
			break;
		}

		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;

		ret = wait_event_interruptible(dev->wait,
			READ_ONCE(dev->num_vps_stopped) > 0 || READ_ONCE(dev->needs_vp_scan));
		if (ret)
			return ret;
	}

	if (put_user(cpu, buf))
		return -EFAULT;

	return sizeof(u32);
}

static int sidecar_open(struct inode *inode, struct file *filp)
{
	filp->private_data = container_of(filp->private_data, struct sidecar_dev, misc);
	return 0;
}

static int sidecar_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct sidecar_dev *dev;
	unsigned long size = vma->vm_end - vma->vm_start;

	dev = filp->private_data;
	if (size != resource_size(dev->shmem_pages) || vma->vm_pgoff != 0)
		return -EINVAL;

	return io_remap_pfn_range(vma, vma->vm_start,
		dev->shmem_pages->start >> PAGE_SHIFT,
		size, vma->vm_page_prot);
}

static const struct file_operations sidecar_file_ops = {
	.owner          = THIS_MODULE,
	.open		= sidecar_open,
	.read           = sidecar_read,
	.poll           = sidecar_poll,
	.mmap           = sidecar_mmap,
	.unlocked_ioctl = sidecar_ioctl,
};

static struct miscdevice sidecar_misc = {
	.fops = &sidecar_file_ops,
	.mode = 0600,
	.minor = MISC_DYNAMIC_MINOR,
};

static int sidecar_probe(struct platform_device *pdev)
{
	int ret;
	resource_size_t total_shmem_size;
	struct sidecar_dev *dev;
	char name[64];
	static bool registered_cpuhp;

	if (!registered_cpuhp) {
		ret = cpuhp_setup_state(CPUHP_BP_PREPARE_DYN, "mshv_vtl_sidecar:remove_for_hotplug",
				sidecar_remove, NULL);
		if (ret < 0)
			return ret;

		registered_cpuhp = true;
	}

	dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->dev = &pdev->dev;
	platform_set_drvdata(pdev, dev);
	dev->control = devm_platform_ioremap_resource_byname(pdev, "ctrl");
	if (IS_ERR(dev->control))
		return PTR_ERR(dev->control);

	init_waitqueue_head(&dev->wait);
	mutex_init(&dev->scan_mutex);
	dev->base_cpu = READ_ONCE(dev->control->base_cpu);
	if (per_cpu(sidecar_interrupt_dev, dev->base_cpu)) {
		dev_err(&pdev->dev, "sidecar already registered for cpu %d", dev->base_cpu);
		return -EBUSY;
	}

	dev->cpu_count = READ_ONCE(dev->control->cpu_count);
	if (!dev->cpu_count)
		return -EINVAL;

	dev->index = READ_ONCE(dev->control->index);
	dev->vp_state = devm_kzalloc(&pdev->dev, dev->cpu_count, GFP_KERNEL);
	if (!dev->vp_state)
		return -ENOMEM;

	dev->shmem_pages = platform_get_resource_byname(pdev, IORESOURCE_MEM, "shmem");
	if (!dev->shmem_pages)
		return -EINVAL;

	total_shmem_size = resource_size(dev->shmem_pages);
	dev->per_cpu_shmem = total_shmem_size / dev->cpu_count;
	if (dev->per_cpu_shmem * dev->cpu_count != total_shmem_size ||
		dev->per_cpu_shmem == 0 ||
		dev->per_cpu_shmem % PAGE_SIZE != 0) {

		dev_err(&pdev->dev, "invalid state size (%#llx) for cpu count (%u)", total_shmem_size, dev->cpu_count);
		return -EINVAL;
	}

	if (!cpu_online(dev->base_cpu)) {
		dev_info(&pdev->dev, "onlining cpu %d to control sidecar node %d", dev->base_cpu, dev->index);
		ret = add_cpu(dev->base_cpu);
		if (ret) {
			dev_err(&pdev->dev, "failed to online cpu %d: %pe", dev->base_cpu, ERR_PTR(ret));
			return ret;
		}
	}

	dev->control->response_cpu = per_cpu(x86_cpu_to_apicid, dev->base_cpu);
	dev->control->response_vector = HYPERVISOR_CALLBACK_VECTOR;
	per_cpu(sidecar_interrupt_dev, dev->base_cpu) = dev;

	dev->misc = sidecar_misc;
	snprintf(name, sizeof(name), "mshv_vtl_sidecar%u", dev->index);
	dev->misc.name = devm_kstrdup_const(&pdev->dev, name, GFP_KERNEL);

	ret = misc_register(&dev->misc);
	if (ret)
		return ret;

	list_add(&dev->list, &sidecar_dev_list);
	return 0;
}

static const struct of_device_id sidecar_match[] = {
	{ .compatible = "microsoft,openhcl-sidecar" },
	{ },
};

static struct platform_driver mshv_vtl_sidecar = {
	.probe = sidecar_probe,
	.driver = {
		.name = "mshv_vtl_sidecar",
		.of_match_table = sidecar_match,
	},
};

int __init mshv_vtl_sidecar_init(void)
{
	return platform_driver_register(&mshv_vtl_sidecar);
}

void mshv_vtl_sidecar_exit(void)
{
	platform_driver_unregister(&mshv_vtl_sidecar);
}
