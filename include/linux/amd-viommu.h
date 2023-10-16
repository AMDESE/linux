/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 */

#ifndef _LINUX_AMD_VIOMMU_H
#define _LINUX_AMD_VIOMMU_H

#include <uapi/linux/amd_viommu.h>

extern long iommufd_amd_viommu_ioctl(struct file *filp,
				     unsigned int cmd,
				     unsigned long arg);

extern long iommufd_viommu_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg);

extern int amd_viommu_iommu_init(struct amd_viommu_iommu_info *data);
extern int amd_viommu_iommu_destroy(struct amd_viommu_iommu_info *data);
extern int amd_viommu_domain_update(struct amd_viommu_dom_info *data, bool is_set);
extern int amd_viommu_device_update(struct amd_viommu_dev_info *data, bool is_set);
extern int amd_viommu_guest_mmio_write(struct amd_viommu_mmio_data *data);
extern int amd_viommu_guest_mmio_read(struct amd_viommu_mmio_data *data);

#endif /* _LINUX_AMD_VIOMMU_H */
