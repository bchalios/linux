// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * The "Virtual Machine Generation ID" is exposed via ACPI and changes when a
 * virtual machine forks or is cloned. This driver exists for shepherding that
 * information to random.c.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/random.h>
#include "linux/container_of.h"
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>

ACPI_MODULE_NAME("vmgenid");

enum { VMGENID_SIZE = 16 };

struct vmgenid_state {
	u8 *next_id;
	u8 this_id[VMGENID_SIZE];

	phys_addr_t gen_cntr_addr;
	u32 *next_counter;

	int misc_enabled;
	struct miscdevice misc;
};

static int vmgenid_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct vmgenid_state *state = filep->private_data;

	if (vma->vm_pgoff || vma_pages(vma) > 1)
		return -EINVAL;

	if ((vma->vm_flags & VM_WRITE))
		return -EPERM;

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_flags &= ~VM_MAYWRITE;

	return vm_iomap_memory(vma, state->gen_cntr_addr, PAGE_SIZE);
}

static ssize_t vmgenid_read(struct file *filep, char __user *buff, size_t count,
		loff_t *offp)
{
	struct vmgenid_state *state = filep->private_data;

	if (count == 0)
		return 0;

	/* We don't allow partial reads */
	if (count != sizeof(u32))
		return -EINVAL;

	if (put_user(*state->next_counter, (u32 __user *)buff))
		return -EFAULT;

	return sizeof(u32);
}

static int vmgenid_open(struct inode *inode, struct file *filep)
{
	struct vmgenid_state *state =
		container_of(filep->private_data, struct vmgenid_state, misc);

	filep->private_data = state;
	return 0;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = vmgenid_open,
	.read = vmgenid_read,
	.mmap = vmgenid_mmap,
	.llseek = noop_llseek,
};

static struct miscdevice vmgenid_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vmgenid",
	.fops = &fops,
};

static int parse_vmgenid_address(struct acpi_device *device, acpi_string object_name,
		phys_addr_t *phys_addr)
{
	struct acpi_buffer parsed = { ACPI_ALLOCATE_BUFFER };
	acpi_status status;
	union acpi_object *obj;
	int ret = 0;

	status = acpi_evaluate_object(device->handle, object_name, NULL, &parsed);
	if (ACPI_FAILURE(status)) {
		ACPI_EXCEPTION((AE_INFO, status, "Evaluating vmgenid object"));
		return -ENODEV;
	}

	obj = parsed.pointer;
	if (!obj || obj->type != ACPI_TYPE_PACKAGE || obj->package.count != 2 ||
	    obj->package.elements[0].type != ACPI_TYPE_INTEGER ||
	    obj->package.elements[1].type != ACPI_TYPE_INTEGER) {
		ret = -EINVAL;
		goto out;
	}

	*phys_addr = (obj->package.elements[0].integer.value << 0) |
		     (obj->package.elements[1].integer.value << 32);

out:
	ACPI_FREE(parsed.pointer);
	return ret;
}

static int vmgenid_add(struct acpi_device *device)
{
	struct vmgenid_state *state;
	phys_addr_t phys_addr;
	int ret;

	state = devm_kzalloc(&device->dev, sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	ret = parse_vmgenid_address(device, "ADDR", &phys_addr);
	if (ret)
		return ret;

	state->next_id = devm_memremap(&device->dev, phys_addr, VMGENID_SIZE, MEMREMAP_WB);
	if (IS_ERR(state->next_id))
		return PTR_ERR(state->next_id);

	memcpy(state->this_id, state->next_id, sizeof(state->this_id));
	add_device_randomness(state->this_id, sizeof(state->this_id));

	device->driver_data = state;

	/* Backwards compatibility. If CTRA is not there we just don't expose
	 * the char device
	 */
	ret = parse_vmgenid_address(device, "CTRA", &state->gen_cntr_addr);
	if (ret)
		return 0;

	state->next_counter = devm_memremap(&device->dev, state->gen_cntr_addr,
			sizeof(u32), MEMREMAP_WB);
	if (IS_ERR(state->next_counter))
		return 0;

	memcpy(&state->misc, &vmgenid_misc, sizeof(state->misc));
	ret = misc_register(&state->misc);
	if (ret) {
		devm_memunmap(&device->dev, state->next_counter);
		return 0;
	}

	state->misc_enabled = 1;

	return 0;
}

static void vmgenid_notify(struct acpi_device *device, u32 event)
{
	struct vmgenid_state *state = acpi_driver_data(device);
	u8 old_id[VMGENID_SIZE];

	memcpy(old_id, state->this_id, sizeof(old_id));
	memcpy(state->this_id, state->next_id, sizeof(state->this_id));
	if (!memcmp(old_id, state->this_id, sizeof(old_id)))
		return;
	add_vmfork_randomness(state->this_id, sizeof(state->this_id));
}

static int vmgenid_remove(struct acpi_device *device)
{
	struct vmgenid_state *state = device->driver_data;

	if (state->misc_enabled)
		misc_deregister(&state->misc);

	return 0;
}

static const struct acpi_device_id vmgenid_ids[] = {
	{ "VMGENCTR", 0 },
	{ "VM_GEN_COUNTER", 0 },
	{ }
};

static struct acpi_driver vmgenid_driver = {
	.name = "vmgenid",
	.ids = vmgenid_ids,
	.owner = THIS_MODULE,
	.ops = {
		.add = vmgenid_add,
		.notify = vmgenid_notify,
		.remove = vmgenid_remove
	}
};

module_acpi_driver(vmgenid_driver);

MODULE_DEVICE_TABLE(acpi, vmgenid_ids);
MODULE_DESCRIPTION("Virtual Machine Generation ID");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>");
