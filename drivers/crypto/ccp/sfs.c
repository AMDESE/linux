// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure Processor Seamless Firmware Servicing support.
 *
 * Copyright (C) 2023-2024 Advanced Micro Devices, Inc.
 *
 * Author: Ashish Kalra <ashish.kalra@amd.com>
 */

#include <linux/firmware.h>

#include "sfs.h"
#include "sev-dev.h"

//#define SFS_DEFAULT_TIMEOUT		(10 * MSEC_PER_SEC)
#define SFS_DEFAULT_TIMEOUT		(5 * 60 * MSEC_PER_SEC)
#define SFS_MAX_PAYLOAD_SIZE		(2 * 1024 * 1024)
#define ORDER_2MB 9

/* SFS Status values */
#define SFS_SUCCESS			0x00
#define SFS_INVALID_PAYLOAD_ADDRESS	0x01
#define SFS_INVALID_TOTAL_SIZE		0x02
#define SFS_INVALID_IMAGE_ADDRESS	0x03
#define SFS_INVALID_PKG_SIZE		0x04
#define SFS_DISABLED			0x05
#define SFS_INVALID_CUST_SIGN		0x06
#define SFS_INVALID_AMD_SIGN		0x07
#define SFS_INTERNAL_ERROR		0x08
#define SFS_CUST_SIGN_NOT_ALLOWED	0x09
#define SFS_INVALID_BASE_PATCH_LVL	0x0A
#define SFS_INVALID_CURR_PATCH_LVL	0x0B
#define SFS_INVALID_NEW_PATCH_LVL	0x0C
#define SFS_INVALID_SUBCOMMAND		0x0D
#define SFS_PROTECTION_FAIL		0x0E
#define SFS_BUSY			0x0F
#define SFS_FW_VERSION_MISMATCH		0x10
#define SFS_SYS_VERSION_MISMATCH	0x11

static bool sfs_initialized;

static int send_sfs_cmd(struct psp_sfs_device *sfs_dev, int msg)
{
	int ret;

	*sfs_dev->result = 0;
	sfs_dev->command_hdr->ext_req.header.sub_cmd_id = msg;

	ret = psp_extended_mailbox_cmd(sfs_dev->psp,
					SFS_DEFAULT_TIMEOUT,
					(struct psp_ext_request *)sfs_dev->command_hdr);
	if (ret == -EIO) {
		dev_dbg(sfs_dev->dev,
			 "msg 0x%x failed with PSP error: 0x%x\n",
			 msg, *sfs_dev->result);
		dev_dbg(sfs_dev->dev,
			 "msg 0x%x extended status: 0x%x\n",
			 msg, *(u32 *)sfs_dev->payload);
	}

	return ret;
}

static int send_sfs_get_fw_versions(struct psp_sfs_device *sfs_dev)
{
	int ret;

	sfs_dev->payload_size = &sfs_dev->command_hdr->ext_req.header.payload_size;
	sfs_dev->result = &sfs_dev->command_hdr->ext_req.header.status;
	sfs_dev->payload = &sfs_dev->command_hdr->ext_req.buf;
	sfs_dev->pkg_hdr = (void *)sfs_dev->command_hdr + PAGE_SIZE;
	sfs_dev->header_size = sizeof(struct psp_ext_req_buffer_hdr);

	/*
	 * SFS_GET_FW_VERSIONS command needs the output buffer to be
	 * initialized to 0xC7 in every byte.
	 */
	memset(sfs_dev->pkg_hdr, 0xc7, PAGE_SIZE);
	*sfs_dev->payload_size = 2 * PAGE_SIZE;

	ret = send_sfs_cmd(sfs_dev, PSP_SFS_GET_FW_VERSIONS);

	return ret;
}

static int send_sfs_update_package(struct psp_sfs_device *sfs_dev, char *payload_name)
{
	char payload_path[PAYLOAD_NAME_SIZE];
	const struct firmware *firmware;
	unsigned long package_size;
	int ret;

	sprintf(payload_path, "amd/%s", payload_name);

	ret = firmware_request_nowarn(&firmware, payload_path, sfs_dev->dev);
	if (ret < 0) {
		pr_info("firmware request fail %d\n", ret);
		return -ENOENT;
	}

	/* SFS Update Package should be 64KB aligned */
	package_size = ALIGN(firmware->size + PAGE_SIZE, 0x10000U);

	/*
	 * SFS command buffer is a pre-allocated 2MB buffer, fail update package
	 * if SFS payload is larger than the pre-allocated command buffer.
	 */
	if (package_size > SFS_MAX_PAYLOAD_SIZE) {
		pr_info("SFS payload size %ld larger than maximum supported payload size of 2MB\n", package_size);
		return -ENOMEM;
	}

	sfs_dev->payload_size = &sfs_dev->command_hdr->ext_req.header.payload_size;
	sfs_dev->result = &sfs_dev->command_hdr->ext_req.header.status;
	sfs_dev->payload = &sfs_dev->command_hdr->ext_req.buf;
	sfs_dev->pkg_hdr = (void *)sfs_dev->command_hdr + PAGE_SIZE;
	sfs_dev->header_size = sizeof(struct psp_ext_req_buffer_hdr);

	/*
	 * Copy firmware data to a kernel allocated contiguous
	 * memory region.
	 */
	memcpy(sfs_dev->pkg_hdr, firmware->data, firmware->size);
	*sfs_dev->payload_size = package_size;

	ret = send_sfs_cmd(sfs_dev, PSP_SFS_UPDATE);

	release_firmware(firmware);
	return ret;
}

void sfs_dev_destroy(struct psp_device *psp)
{
	struct psp_sfs_device *sfs_dev = psp->sfs_data;
	int ret;

	if (!sfs_dev)
		return;

	/*
	 * TODO: free pre-allocated 2MB command buffer,
	 * if SEV-SNP is enabled the command buffer has
	 * been marked HV_Fixed and HV_Fixed pages remain
	 * in that state till system reset, they cannot be
	 * released back to the page allocator.
	 */

	ret = set_memory_wb((unsigned long)page_address(sfs_dev->page), 512);
	if (ret) {
		pr_info("set memory wb failed\n");
	}
	pr_info("%s cmdbuf page va 0x%lx marked as Cacheable\n", __func__, sfs_dev->command_hdr);

	snp_free_hypervisor_fixed_pages(sfs_dev->page);
	misc_deregister(&sfs_dev->char_dev);
	mutex_destroy(&sfs_dev->ioctl_mutex);
	psp->sfs_data = NULL;
}

static long sfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct psp_device *psp_master = psp_get_master_device();
	void __user *argp = (void __user *)arg;
	char payload_name[PAYLOAD_NAME_SIZE];
	struct psp_sfs_device *sfs_dev;
	int ret;

	if (!psp_master || !psp_master->sfs_data)
		return -ENODEV;
	sfs_dev = psp_master->sfs_data;

	mutex_lock(&sfs_dev->ioctl_mutex);

	switch (cmd) {
	case SFSIOCFWVERS:
		pr_info("in SFSIOCFWVERS\n");
		ret = send_sfs_get_fw_versions(sfs_dev);
		if (ret && ret != -EIO)
			goto unlock;
		/*
		 * return SFS status and extended status back to userspace
		 * if PSP status indicated command error.
		 */
		if (copy_to_user(argp, sfs_dev->pkg_hdr, PAGE_SIZE))
			ret = -EFAULT;
		if (copy_to_user(argp + PAGE_SIZE, sfs_dev->result, sizeof(u32)))
			ret = -EFAULT;
		if (copy_to_user(argp + PAGE_SIZE + sizeof(u32), sfs_dev->payload, sizeof(u32)))
			ret = -EFAULT;
		break;
	case SFSIOCUPDATEPKG:
		pr_info("in SFSIOCUPDATEPKG\n");

		if (copy_from_user(payload_name, argp, PAYLOAD_NAME_SIZE)) {
			ret = -EFAULT;
			goto unlock;
		}

		ret = send_sfs_update_package(sfs_dev, payload_name);
		if (ret && ret != -EIO)
			goto unlock;
		/*
		 * return SFS status and extended status back to userspace
		 * if PSP status indicated command error.
		 */
		if (copy_to_user(argp + PAYLOAD_NAME_SIZE, sfs_dev->result, sizeof(u32)))
			ret = -EFAULT;
		if (copy_to_user(argp + PAYLOAD_NAME_SIZE + sizeof(u32), sfs_dev->payload, sizeof(u32)))
			ret = -EFAULT;
		break;
	default:
		ret = -EINVAL;
	}

unlock:
	mutex_unlock(&sfs_dev->ioctl_mutex);

	return ret;
}

static const struct file_operations sfs_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = sfs_ioctl,
};

/*
 * Invoked after sev_pci_init() which would have initialized SNP if
 * SEV-SNP support is enabled in the platform.
 */
void sfs_pci_init(void)
{
	struct psp_device *psp_master = psp_get_master_device();
	struct psp_sfs_device *sfs_dev;
	struct sev_device *sev;
	struct page *page;

	if (!psp_master || !psp_master->sfs_data || !psp_master->sev_data)
		return;

	sfs_dev = psp_master->sfs_data;
	sev = psp_master->sev_data;

	return;

	/*
	 * If SEV-SNP is enabled transition the SFS command buffer to
	 * HV_Fixed page state.
	 */
	if (cpu_feature_enabled(X86_FEATURE_SEV_SNP) && sev->snp_initialized) {
//		ret = rmp_make_hv_fixed(page_to_pfn(sfs_dev->page), 512);
		page = snp_allocate_hypervisor_fixed_pages(512);
		if (!page) {
			pr_info("snp_allocate_hypervisor_fixed_pages failed\n");
			return;
		}
		sfs_dev->page = page;
		sfs_dev->command_hdr = page_address(page);
		pr_info("%s cmdbuf page va 0x%lx, pa 0x%lx 512x HV_Fixed pages\n", __func__, page_address(sfs_dev->page), page_to_pfn(sfs_dev->page));
	}
}

int sfs_dev_init(struct psp_device *psp)
{
	struct device *dev = psp->dev;
	struct psp_sfs_device *sfs_dev;
	struct page *page;
	int ret;

	/*
	 * SFS feature support can be detected on multiple devices but the SFS
	 * FW commands must be issued on the master. During probe, we do not
	 * know the master hence we create /dev/sfs on the first device probe.
	 */
	if (sfs_initialized)
		return 0;

	sfs_dev = devm_kzalloc(dev, sizeof(*sfs_dev), GFP_KERNEL);
	if (!sfs_dev)
		return -ENOMEM;

	BUILD_BUG_ON(sizeof(struct sfs_command) > PAGE_SIZE);

#if 0
	/*
	 * Pre-allocate static 2MB command buffer for all SFS
	 * commands. 2MB command buffer size is a requirement for
	 * transitioning the SFS command buffer and output pages
	 * to HV_Fixed state when SEV-SNP is enabled as the
	 * SNP_PAGE_SET_STATE command only operates on
	 * 2MB-aligned range base addresses.
	 */
	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, ORDER_2MB);
	if (!page)
		return -ENOMEM;
	sfs_dev->page = page;
	sfs_dev->command_hdr = page_address(page);
#endif

	page = snp_allocate_hypervisor_fixed_pages(512);
	if (!page) {
		pr_info("snp_allocate_hypervisor_fixed_pages failed\n");
		return -ENOMEM;
	}
	sfs_dev->page = page;
	sfs_dev->command_hdr = page_address(page);
	pr_info("%s cmdbuf page va 0x%lx, pa 0x%lx 512x HV_Fixed pages\n", __func__, page_address(sfs_dev->page), page_to_pfn(sfs_dev->page));

	ret = set_memory_uc((unsigned long)page_address(page), 512);
	if (ret) {
		pr_info("set memory uc failed\n");
	}
	pr_info("%s cmdbuf page va 0x%lx marked as UnCacheable\n", __func__, sfs_dev->command_hdr);

	psp->sfs_data = sfs_dev;
	sfs_dev->dev = dev;
	sfs_dev->psp = psp;

	dev_dbg(sfs_dev->dev, "seamless firmware serviving support is available\n");

	sfs_dev->char_dev.minor = MISC_DYNAMIC_MINOR;
	sfs_dev->char_dev.name = "sfs";
	sfs_dev->char_dev.fops = &sfs_fops;
	sfs_dev->char_dev.mode = 0600;
	ret = misc_register(&sfs_dev->char_dev);
	if (ret)
		goto cleanup_cmd_hdr;

	mutex_init(&sfs_dev->ioctl_mutex);
	sfs_initialized = true;

	return 0;

cleanup_cmd_hdr:
	free_page((unsigned long)page_address(page));
	psp->sfs_data = NULL;
	devm_kfree(dev, sfs_dev);

	return ret;
}
