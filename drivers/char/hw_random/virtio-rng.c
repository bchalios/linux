// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Randomness driver for virtio
 *  Copyright (C) 2007, 2008 Rusty Russell IBM Corporation
 */

#include "asm-generic/errno.h"
#include "linux/gfp.h"
#include "linux/minmax.h"
#include "linux/sysfs.h"
#include <linux/err.h>
#include <linux/hw_random.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <linux/virtio_rng.h>
#include <linux/random.h>
#include <linux/module.h>
#include <linux/slab.h>

static DEFINE_IDA(rng_index_ida);

#ifdef CONFIG_SYSFS
static struct kobject *virtio_rng_kobj;
#endif

struct virtrng_info {
	struct hwrng hwrng;
	struct virtqueue *vq;
	/* Leak queues */
	bool has_leakqs;
	struct virtqueue *leakq[2];
	spinlock_t lock;
	int active_leakq;
#ifdef CONFIG_SYSFS
	struct kobject *kobj;
	struct bin_attribute vm_gen_counter_attr;
	unsigned long map_buffer;
	unsigned long next_vm_gen_counter;
#endif

	char name[25];
	int index;
	bool hwrng_register_done;
	bool hwrng_removed;
	/* data transfer */
	struct completion have_data;
	unsigned int data_avail;
	unsigned int data_idx;
	/* minimal size returned by rng_buffer_size() */
#if SMP_CACHE_BYTES < 32
	u8 data[32];
	u8 leak_data[32];
#else
	u8 data[SMP_CACHE_BYTES];
	u8 leak_data[SMP_CACHE_BYTES];
#endif
};

#ifdef CONFIG_SYSFS
ssize_t virtrng_sysfs_read(struct file *filep, struct kobject *kobj,
		struct bin_attribute *attr, char *buf, loff_t pos, size_t len)
{
	struct virtrng_info *vi = attr->private;
	unsigned long gen_counter = *(unsigned long *)vi->map_buffer;

	if (!len)
		return 0;

	len = min(len, sizeof(gen_counter));
	memcpy(buf, &gen_counter, len);

	return len;
}

int virtrng_sysfs_mmap(struct file *filep, struct kobject *kobj,
		struct bin_attribute *attr, struct vm_area_struct *vma)
{
	struct virtrng_info *vi = attr->private;

	if (vma->vm_pgoff || vma_pages(vma) > 1)
		return -EINVAL;

	if (vma->vm_flags & VM_WRITE)
		return -EPERM;

	vma->vm_flags |= VM_DONTEXPAND;
	vma->vm_flags &= ~VM_MAYWRITE;

	return vm_insert_page(vma, vma->vm_start, virt_to_page(vi->map_buffer));
}
#endif

/* Swaps the queues and returns the new active leak queue. */
static struct virtqueue *swap_leakqs(struct virtrng_info *vi)
{
	vi->active_leakq = 1 - vi->active_leakq;
	return vi->leakq[vi->active_leakq];
}

static struct virtqueue *get_active_leakq(struct virtrng_info *vi)
{
	return vi->leakq[vi->active_leakq];
}

int add_fill_on_leak_request(struct virtrng_info *vi, struct virtqueue *vq, void *data, size_t len)
{
	struct scatterlist sg;
	int ret;

	sg_init_one(&sg, data, len);
	ret = virtqueue_add_inbuf(vq, &sg, 1, data, GFP_KERNEL);
	if (ret)
		goto err;

err:
	return ret;
}

int virtrng_fill_on_leak(struct virtrng_info *vi, void *data, size_t len)
{
	struct virtqueue *vq;
	unsigned long flags;
	int ret;

	if (!vi->has_leakqs)
		return -EOPNOTSUPP;

	spin_lock_irqsave(&vi->lock, flags);

	vq = get_active_leakq(vi);
	ret = add_fill_on_leak_request(vi, vq, data, len);
	if (!ret)
		virtqueue_kick(vq);

	spin_unlock_irqrestore(&vi->lock, flags);

	return ret;
}

int add_copy_on_leak_request(struct virtrng_info *vi, struct virtqueue *vq,
		void *to, void *from, size_t len)
{
	int ret;
	struct scatterlist out, in, *sgs[2];

	sg_init_one(&out, from, len);
	sgs[0] = &out;
	sg_init_one(&in, to, len);
	sgs[1] = &in;

	ret = virtqueue_add_sgs(vq, sgs, 1, 1, to, GFP_KERNEL);
	if (ret)
		goto err;

err:
	return ret;
}

int virtrng_copy_on_leak(struct virtrng_info *vi, void *to, void *from, size_t len)
{
	struct virtqueue *vq;
	unsigned long flags;
	int ret;

	if (!vi->has_leakqs)
		return -EOPNOTSUPP;

	spin_lock_irqsave(&vi->lock, flags);

	vq = get_active_leakq(vi);
	ret = add_copy_on_leak_request(vi, vq, to, from, len);
	if (!ret)
		virtqueue_kick(vq);

	spin_unlock_irqrestore(&vi->lock, flags);

	return ret;
}

static void entropy_leak_detected(struct virtqueue *vq)
{
	struct virtrng_info *vi = vq->vdev->priv;
	struct virtqueue *activeq;
	unsigned int len;
	unsigned long flags;
	void *buffer;
	bool kick_activeq = false;
#ifdef CONFIG_SYSFS
	bool notify_sysfs = false;
#endif

	spin_lock_irqsave(&vi->lock, flags);

	activeq = get_active_leakq(vi);
	/* Drain all the used buffers from the queue */
	while ((buffer = virtqueue_get_buf(vq, &len)) != NULL) {
		if (vq == activeq) {
			pr_debug("%s: entropy leak detected!", vi->name);
			activeq = swap_leakqs(vi);
		}

		if (buffer == vi->leak_data) {
			add_device_randomness(vi->leak_data, sizeof(vi->leak_data));

			/* Ensure we always have a pending request for random bytes on entropy
			 * leak. Do it here, after we have swapped leak queues, so it gets handled
			 * with the next entropy leak event.
			 */
			add_fill_on_leak_request(vi, activeq, vi->leak_data, sizeof(vi->leak_data));
			kick_activeq = true;
		}

#ifdef CONFIG_SYSFS
		if (buffer == (void *)vi->map_buffer) {
			notify_sysfs = true;

			/* Add a request to bump the generation counter on the next leak event.
			 * We have already swapped leak queues, so this will get properly handled
			 * with the next entropy leak event.
			 */
			vi->next_vm_gen_counter++;
			add_copy_on_leak_request(vi, activeq, (void *)vi->map_buffer,
					&vi->next_vm_gen_counter, sizeof(unsigned long));

			kick_activeq = true;
		}
#endif
	}

	if (kick_activeq)
		virtqueue_kick(activeq);

	spin_unlock_irqrestore(&vi->lock, flags);

#ifdef CONFIG_SYSFS
	/* Notify anyone polling on the sysfs file */
	if (notify_sysfs)
		sysfs_notify(vi->kobj, NULL, "vm_gen_counter");
#endif
}

static void random_recv_done(struct virtqueue *vq)
{
	struct virtrng_info *vi = vq->vdev->priv;
	unsigned long flags;

	spin_lock_irqsave(&vi->lock, flags);
	/* We can get spurious callbacks, e.g. shared IRQs + virtio_pci. */
	if (!virtqueue_get_buf(vi->vq, &vi->data_avail))
		goto unlock;

	vi->data_idx = 0;

	complete(&vi->have_data);

unlock:
	spin_unlock_irqrestore(&vi->lock, flags);
}

static void request_entropy(struct virtrng_info *vi)
{
	struct scatterlist sg;
	unsigned long flags;

	reinit_completion(&vi->have_data);
	vi->data_avail = 0;
	vi->data_idx = 0;

	sg_init_one(&sg, vi->data, sizeof(vi->data));

	spin_lock_irqsave(&vi->lock, flags);
	/* There should always be room for one buffer. */
	virtqueue_add_inbuf(vi->vq, &sg, 1, vi->data, GFP_KERNEL);

	virtqueue_kick(vi->vq);
	spin_unlock_irqrestore(&vi->lock, flags);
}

static unsigned int copy_data(struct virtrng_info *vi, void *buf,
			      unsigned int size)
{
	size = min_t(unsigned int, size, vi->data_avail);
	memcpy(buf, vi->data + vi->data_idx, size);
	vi->data_idx += size;
	vi->data_avail -= size;
	if (vi->data_avail == 0)
		request_entropy(vi);
	return size;
}

static int virtio_read(struct hwrng *rng, void *buf, size_t size, bool wait)
{
	int ret;
	struct virtrng_info *vi = (struct virtrng_info *)rng->priv;
	unsigned int chunk;
	size_t read;

	if (vi->hwrng_removed)
		return -ENODEV;

	read = 0;

	/* copy available data */
	if (vi->data_avail) {
		chunk = copy_data(vi, buf, size);
		size -= chunk;
		read += chunk;
	}

	if (!wait)
		return read;

	/* We have already copied available entropy,
	 * so either size is 0 or data_avail is 0
	 */
	while (size != 0) {
		/* data_avail is 0 but a request is pending */
		ret = wait_for_completion_killable(&vi->have_data);
		if (ret < 0)
			return ret;
		/* if vi->data_avail is 0, we have been interrupted
		 * by a cleanup, but buffer stays in the queue
		 */
		if (vi->data_avail == 0)
			return read;

		chunk = copy_data(vi, buf + read, size);
		size -= chunk;
		read += chunk;
	}

	return read;
}

static void virtio_cleanup(struct hwrng *rng)
{
	struct virtrng_info *vi = (struct virtrng_info *)rng->priv;

	complete(&vi->have_data);
}

static int init_virtqueues(struct virtrng_info *vi, struct virtio_device *vdev)
{
	int ret = -ENOMEM, total_vqs = 1;
	struct virtqueue *vqs[3];
	const char *names[3];
	vq_callback_t *callbacks[3];

	if (vi->has_leakqs)
		total_vqs = 3;

	callbacks[0] = random_recv_done;
	names[0] = "input";
	if (vi->has_leakqs) {
		callbacks[1] = entropy_leak_detected;
		names[1] = "leakq.1";
		callbacks[2] = entropy_leak_detected;
		names[2] = "leakq.2";
	}

	ret = virtio_find_vqs(vdev, total_vqs, vqs, callbacks, names, NULL);
	if (ret)
		goto err;

	vi->vq = vqs[0];

	if (vi->has_leakqs) {
		vi->leakq[0] = vqs[1];
		vi->leakq[1] = vqs[2];
	}

err:
	return ret;
}

#ifdef CONFIG_SYSFS
static int setup_sysfs(struct virtrng_info *vi)
{
	int err;

	vi->next_vm_gen_counter = 1;

	/* We have one binary file per device under /sys/virtio-rng/<device>/vm_gen_counter */
	vi->vm_gen_counter_attr.attr.name = "vm_gen_counter";
	vi->vm_gen_counter_attr.attr.mode = 0444;
	vi->vm_gen_counter_attr.read = virtrng_sysfs_read;
	vi->vm_gen_counter_attr.mmap = virtrng_sysfs_mmap;
	vi->vm_gen_counter_attr.private = vi;

	vi->map_buffer = get_zeroed_page(GFP_KERNEL);
	if (!vi->map_buffer)
		return -ENOMEM;

	err = -ENOMEM;
	vi->kobj = kobject_create_and_add(vi->name, virtio_rng_kobj);
	if (!vi->kobj)
		goto err_page;

	err = sysfs_create_bin_file(vi->kobj, &vi->vm_gen_counter_attr);
	if (err)
		goto err_kobj;

	return 0;

err_kobj:
	kobject_put(vi->kobj);
err_page:
	free_pages(vi->map_buffer, 0);
	return err;
}

static void cleanup_sysfs(struct virtrng_info *vi)
{
	sysfs_remove_bin_file(vi->kobj, &vi->vm_gen_counter_attr);
	kobject_put(vi->kobj);
	free_pages(vi->map_buffer, 0);
}
#else
static int setup_sysfs(struct virtrng_info *vi)
{
	return 0;
}

static void cleanup_sysfs(struct virtrng_info *vi)
{
}
#endif

static int probe_common(struct virtio_device *vdev)
{
	int err, index;
	struct virtrng_info *vi = NULL;

	vi = kzalloc(sizeof(struct virtrng_info), GFP_KERNEL);
	if (!vi)
		return -ENOMEM;

	vi->index = index = ida_simple_get(&rng_index_ida, 0, 0, GFP_KERNEL);
	if (index < 0) {
		err = index;
		goto err_ida;
	}
	sprintf(vi->name, "virtio_rng.%d", index);
	init_completion(&vi->have_data);

	vi->hwrng = (struct hwrng) {
		.read = virtio_read,
		.cleanup = virtio_cleanup,
		.priv = (unsigned long)vi,
		.name = vi->name,
		.quality = 1000,
	};
	vdev->priv = vi;

	vi->has_leakqs = virtio_has_feature(vdev, VIRTIO_RNG_F_LEAK);
	if (vi->has_leakqs) {
		spin_lock_init(&vi->lock);
		vi->active_leakq = 0;

		err = setup_sysfs(vi);
		if (err)
			goto err_find;
	}

	err = init_virtqueues(vi, vdev);
	if (err)
		goto err_sysfs;

	virtio_device_ready(vdev);

	/* we always have a pending entropy request */
	request_entropy(vi);

	/* we always have a fill_on_leak request pending */
	virtrng_fill_on_leak(vi, vi->leak_data, sizeof(vi->leak_data));

#ifdef CONFIG_SYSFS
	/* also a copy_on_leak request for the generation counter when we have sysfs
	 * support.
	 */
	virtrng_copy_on_leak(vi, (void *)vi->map_buffer, &vi->next_vm_gen_counter,
			sizeof(unsigned long));
#endif

	return 0;

err_sysfs:
	cleanup_sysfs(vi);
err_find:
	ida_simple_remove(&rng_index_ida, index);
err_ida:
	kfree(vi);
	return err;
}

static void remove_common(struct virtio_device *vdev)
{
	struct virtrng_info *vi = vdev->priv;

	vi->hwrng_removed = true;
	vi->data_avail = 0;
	vi->data_idx = 0;
	complete(&vi->have_data);
	if (vi->hwrng_register_done)
		hwrng_unregister(&vi->hwrng);
	if (vi->has_leakqs)
		cleanup_sysfs(vi);
	virtio_reset_device(vdev);
	vdev->config->del_vqs(vdev);
	ida_simple_remove(&rng_index_ida, vi->index);
	kfree(vi);
}

static int virtrng_probe(struct virtio_device *vdev)
{
	return probe_common(vdev);
}

static void virtrng_remove(struct virtio_device *vdev)
{
	remove_common(vdev);
}

static void virtrng_scan(struct virtio_device *vdev)
{
	struct virtrng_info *vi = vdev->priv;
	int err;

	err = hwrng_register(&vi->hwrng);
	if (!err)
		vi->hwrng_register_done = true;
}

#ifdef CONFIG_PM_SLEEP
static int virtrng_freeze(struct virtio_device *vdev)
{
	remove_common(vdev);
	return 0;
}

static int virtrng_restore(struct virtio_device *vdev)
{
	int err;

	err = probe_common(vdev);
	if (!err) {
		struct virtrng_info *vi = vdev->priv;

		/*
		 * Set hwrng_removed to ensure that virtio_read()
		 * does not block waiting for data before the
		 * registration is complete.
		 */
		vi->hwrng_removed = true;
		err = hwrng_register(&vi->hwrng);
		if (!err) {
			vi->hwrng_register_done = true;
			vi->hwrng_removed = false;
		}
	}

	return err;
}
#endif

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_RNG, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_RNG_F_LEAK,
};

static struct virtio_driver virtio_rng_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virtrng_probe,
	.remove =	virtrng_remove,
	.scan =		virtrng_scan,
#ifdef CONFIG_PM_SLEEP
	.freeze =	virtrng_freeze,
	.restore =	virtrng_restore,
#endif
};

#ifdef CONFIG_SYSFS
static int __init virtio_rng_init(void)
{
	virtio_rng_kobj = kobject_create_and_add("virtio-rng", NULL);
	if (!virtio_rng_kobj)
		return -ENOMEM;

	return 0;
}

static void __exit virtio_rng_fini(void)
{
	kobject_put(virtio_rng_kobj);
}

module_init(virtio_rng_init);
module_exit(virtio_rng_fini);
#endif

module_virtio_driver(virtio_rng_driver);
MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio random number driver");
MODULE_LICENSE("GPL");
