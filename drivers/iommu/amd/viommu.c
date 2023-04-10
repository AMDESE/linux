#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/iommu.h>
#include <linux/amd-iommu.h>

#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/hashtable.h>
#include <linux/ioctl.h>
#include <linux/iommufd.h>
#include <linux/mem_encrypt.h>
#include <uapi/linux/amd_viommu.h>

#include <asm/iommu.h>
#include <asm/set_memory.h>

#include "amd_iommu.h"
#include "amd_iommu_types.h"
#include "amd_viommu.h"

#define GET_CTRL_BITS(reg, bit, msk)	(((reg) >> (bit)) & (ULL(msk)))
#define SET_CTRL_BITS(reg, bit1, bit2, msk) \
	((((reg) >> (bit1)) & (ULL(msk))) << (bit2))

#define VIOMMU_GID_HASH_BITS	16
static DEFINE_HASHTABLE(viommu_gid_hash, VIOMMU_GID_HASH_BITS);
static DEFINE_SPINLOCK(viommu_gid_hash_lock);
static u32 viommu_next_gid = 0;
static bool next_viommu_gid_wrapped = false;

LIST_HEAD(viommu_devid_map);

extern bool amd_iommu_viommu;

extern struct protection_domain *to_pdomain(struct iommu_domain *dom);
extern struct iommu_domain *amd_iommu_domain_alloc(unsigned type);
extern void amd_iommu_domain_free(struct iommu_domain *dom);
extern void iommu_feature_enable(struct amd_iommu *iommu, u8 bit);
extern void iommu_feature_disable(struct amd_iommu *iommu, u8 bit);
extern u8 __iomem * __init iommu_map_mmio_space(u64 address, u64 end);
extern void set_dte_entry(struct amd_iommu *iommu, u16 devid,
			  struct protection_domain *domain,
			  bool ats, bool ppr);
extern int amd_iommu_v1_map_pages(struct io_pgtable_ops *ops, unsigned long iova,
				  phys_addr_t paddr, size_t pgsize, size_t pgcount,
				  int prot, gfp_t gfp, size_t *mapped);
extern unsigned long amd_iommu_v1_unmap_pages(struct io_pgtable_ops *ops,
					      unsigned long iova,
					      size_t pgsize, size_t pgcount,
					      struct iommu_iotlb_gather *gather);
extern int iommu_flush_dte(struct amd_iommu *iommu, u16 devid);

struct amd_iommu_vminfo {
	u16 gid;
        bool init;
	struct hlist_node hnode;
	u64 *devid_table;
	u64 *domid_table;
};

struct amd_iommu *get_amd_iommu_from_devid(u16 devid)
{
	struct amd_iommu *iommu;

	for_each_iommu(iommu)
		if (iommu->devid == devid)
			return iommu;
	return NULL;
}

static void viommu_enable(struct amd_iommu *iommu)
{
	if (!amd_iommu_viommu)
		return;
	iommu_feature_enable(iommu, CONTROL_VCMD_EN);
	iommu_feature_enable(iommu, CONTROL_VIOMMU_EN);
}

static int viommu_init_pci_vsc(struct amd_iommu *iommu)
{
	iommu->vsc_offset = pci_find_capability(iommu->dev, PCI_CAP_ID_VNDR);
	if (!iommu->vsc_offset)
		return -ENODEV;

	DUMP_printk("device:%s, vsc offset:%04x\n",
		    pci_name(iommu->dev), iommu->vsc_offset);
	return 0;
}

static int __init viommu_vf_vfcntl_init(struct amd_iommu *iommu)
{
	u32 lo, hi;
	u64 vf_phys, vf_cntl_phys;

	/* Setting up VF and VF_CNTL MMIOs */
	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_BAR_LO_OFFSET, &lo);
	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_BAR_HI_OFFSET, &hi);
	vf_phys = hi;
	vf_phys = (vf_phys << 32) | lo;
	if (!(vf_phys & 1)) {
		pr_err(FW_BUG "vf_phys disabled\n");
		return -EINVAL;
	}

	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_CNTL_BAR_LO_OFFSET, &lo);
	pci_read_config_dword(iommu->dev, iommu->vsc_offset + MMIO_VSC_VF_CNTL_BAR_HI_OFFSET, &hi);
	vf_cntl_phys = hi;
	vf_cntl_phys = (vf_cntl_phys << 32) | lo;
	if (!(vf_cntl_phys & 1)) {
		pr_err(FW_BUG "vf_cntl_phys disabled\n");
		return -EINVAL;
	}

	if (!vf_phys || !vf_cntl_phys) {
		pr_err(FW_BUG "AMD-Vi: Unassigned VF resources.\n");
		return -ENOMEM;
	}

	/* Mapping 256MB of VF and 4MB of VF_CNTL BARs */
	vf_phys &= ~1ULL;
	iommu->vf_base = iommu_map_mmio_space(vf_phys, 0x10000000);
	if (!iommu->vf_base) {
		pr_err("Can't reserve vf_base\n");
		return -ENOMEM;
	}

	vf_cntl_phys &= ~1ULL;
	iommu->vfctrl_base = iommu_map_mmio_space(vf_cntl_phys, 0x400000);

	if (!iommu->vfctrl_base) {
		pr_err("Can't reserve vfctrl_base\n");
		return -ENOMEM;
	}

	pr_debug("%s: IOMMU device:%s, vf_base:%#llx, vfctrl_base:%#llx\n",
		 __func__, pci_name(iommu->dev), vf_phys, vf_cntl_phys);
	return 0;
}

static void *alloc_private_region(struct amd_iommu *iommu,
				  u64 base, size_t size)
{
	int ret;
	void *region;

	region  = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						get_order(size));
	if (!region)
		return NULL;

	ret = set_memory_uc((unsigned long)region, size >> PAGE_SHIFT);
	if (ret)
		goto err_out;

	if (amd_iommu_v1_map_pages(&iommu->viommu_pdom->iop.iop.ops, base,
				   iommu_virt_to_phys(region), PAGE_SIZE, (size / PAGE_SIZE),
				   IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL, NULL))
		goto err_out;

	pr_debug("%s: base=%#llx, size=%#lx\n", __func__, base, size);

	return region;

err_out:
	free_pages((unsigned long)region, get_order(size));
	return NULL;
}

static int alloc_private_vm_region(struct amd_iommu *iommu, u64 **entry,
				   u64 base, size_t size, u16 guestId)
{
	int ret;
	u64 addr = base + (guestId * size);

	*entry = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
                                         get_order(size));

	ret = set_memory_uc((unsigned long)*entry, size >> PAGE_SHIFT);
	if (ret)
		return ret;

	pr_debug("%s: entry=%#llx(%#llx), addr=%#llx\n", __func__,
		 (unsigned long  long)*entry, iommu_virt_to_phys(*entry), addr);

	ret = amd_iommu_v1_map_pages(&iommu->viommu_pdom->iop.iop.ops, addr,
				     iommu_virt_to_phys(*entry), PAGE_SIZE, (size / PAGE_SIZE),
				     IOMMU_PROT_IR | IOMMU_PROT_IW, GFP_KERNEL, NULL);
	return ret;
}

static void free_private_vm_region(struct amd_iommu *iommu, u64 **entry,
					u64 base, size_t size, u16 guestId)
{
	size_t ret;
	struct iommu_iotlb_gather gather;
	u64 addr = base + (guestId * size);

	pr_debug("entry=%#llx(%#llx), addr=%#llx\n",
		 (unsigned long  long)*entry,
		 iommu_virt_to_phys(*entry), addr);

	if (!iommu || iommu->viommu_pdom)
		return;
	ret = amd_iommu_v1_unmap_pages(&iommu->viommu_pdom->iop.iop.ops,
				       addr, PAGE_SIZE, (size / PAGE_SIZE), &gather);
	if (ret) {
		amd_iommu_iotlb_sync(&iommu->viommu_pdom->domain, &gather);
	}

	free_pages((unsigned long)*entry, get_order(size));
	*entry = NULL;
}

static int viommu_private_space_init(struct amd_iommu *iommu)
{
	u64 pte_root = 0;
	struct iommu_domain *dom;
	struct protection_domain *pdom;

	/*
	 * Setup page table root pointer, Guest MMIO and
	 * Cmdbuf Dirty Status regions.
	 */
	dom = amd_iommu_domain_alloc(IOMMU_DOMAIN_UNMANAGED);
	if (!dom)
		goto err_out;

	pdom = to_pdomain(dom);
	iommu->viommu_pdom = pdom;
	set_dte_entry(iommu, iommu->devid, pdom, false, false);

	iommu->guest_mmio = alloc_private_region(iommu,
						 VIOMMU_GUEST_MMIO_BASE,
						 VIOMMU_GUEST_MMIO_SIZE);
	if (!iommu->guest_mmio)
		goto err_out;

	iommu->cmdbuf_dirty_mask = alloc_private_region(iommu,
							VIOMMU_CMDBUF_DIRTY_STATUS_BASE,
							VIOMMU_CMDBUF_DIRTY_STATUS_SIZE);
	if (!iommu->cmdbuf_dirty_mask)
		goto err_out;

	pte_root = iommu_virt_to_phys(pdom->iop.root);
	pr_debug("%s: devid=%#x, pte_root=%#llx(%#llx), guest_mmio=%#llx(%#llx), cmdbuf_dirty_mask=%#llx(%#llx)\n",
		 __func__, iommu->devid, (unsigned long long)pdom->iop.root, pte_root,
		 (unsigned long long)iommu->guest_mmio, iommu_virt_to_phys(iommu->guest_mmio),
		 (unsigned long long)iommu->cmdbuf_dirty_mask, iommu_virt_to_phys(iommu->cmdbuf_dirty_mask));

	return 0;
err_out:
	if(iommu->guest_mmio)
		free_pages((unsigned long)iommu->guest_mmio, get_order(VIOMMU_GUEST_MMIO_SIZE));

	if (dom)
		amd_iommu_domain_free(dom);
	return -ENOMEM;
}

/*
 * When IOMMU Virtualization is enabled, host software must:
 *	- allocate system memory for IOMMU private space
 *	- program IOMMU as an I/O device in Device Table
 *	- maintain the I/O page table for IOMMU private addressing to SPA translations.
 *	- specify the base address of the IOMMU Virtual Function MMIO and
 *	  IOMMU Virtual Function Control MMIO region.
 *	- enable Guest Virtual APIC enable (MMIO Offset 0x18[GAEn]).
*/
int __init iommu_init_viommu(struct amd_iommu *iommu)
{
	int ret = -EINVAL;

	if (!amd_iommu_viommu)
		return 0;

	if (!iommu_feature(iommu, FEATURE_VIOMMU))
		goto err_out;

	ret = viommu_init_pci_vsc(iommu);
	if (ret)
		goto err_out;

	ret = viommu_vf_vfcntl_init(iommu);
	if (ret)
		goto err_out;

	ret = viommu_private_space_init(iommu);
	if (ret)
		goto err_out;

	viommu_enable(iommu);

	return ret;

err_out:
	amd_iommu_viommu = false;
	return ret;
}

static void viommu_uninit_one(struct amd_iommu *iommu, struct amd_iommu_vminfo *vminfo, u16 guestId)
{
	free_private_vm_region(iommu, &vminfo->devid_table,
			       VIOMMU_DEVID_MAPPING_BASE,
			       VIOMMU_DEVID_MAPPING_ENTRY_SIZE,
			       guestId);
	free_private_vm_region(iommu, &vminfo->domid_table,
			       VIOMMU_DOMID_MAPPING_BASE,
			       VIOMMU_DOMID_MAPPING_ENTRY_SIZE,
			       guestId);
}

/*
 * Clear the DevID via VFCTRL registers
 * This function will be called during VM destroy via VFIO.
 */
static void clear_device_mapping(struct amd_iommu *iommu, u16 hDevId, u16 guestId,
				 u16 queueId, u16 gDevId/*, int poll*/)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl;

	/*
	 * Clear the DevID in VFCTRL registers
	 */
	tmp1 = gDevId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDevId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001ULL;
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);

	//TODO: CHECK THIS
	val = (~(0xFFFFULL) << 16);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_MISC_CONTROL_OFFSET);
}

/*
 * Clear the DomID via VFCTRL registers
 * This function will be called during VM destroy via VFIO.
 */
static void clear_domain_mapping(struct amd_iommu *iommu, u16 hDomId, u16 guestId,u16 gDomId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);

	tmp1 = gDomId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDomId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001UL;
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);
}

static void viommu_clear_mapping(struct amd_iommu *iommu, u16 guestId)
{
	int i;

	for (i = 0; i < 0x10000; i++) {
		clear_device_mapping(iommu, 0, guestId, 0, i);
	}

	for (i = 0; i < 0x10000; i++) {
		clear_domain_mapping(iommu, 0, guestId, i);
	}
}

static void viommu_clear_dirty_status_mask(struct amd_iommu *iommu, unsigned int gid)
{
	u32 offset, index, bits;
	u64 *group, val;

	if (gid >= 256 * 256)
		return;

	group = (u64 *)(iommu->cmdbuf_dirty_mask +
		(((gid & 0xFF) << 4) | (((gid >> 13) & 0x7) << 2)));
	offset = (gid >> 8) & 0x1F;
	index = offset >> 6;
	bits = offset & 0x3F;

	val = READ_ONCE(group[index]);
	val &= ~(1ULL << bits);
	WRITE_ONCE(group[index], val);
}

/*
 * Allocate pages for the following regions:
 * - Guest MMIO
 * - DeviceID/DomainId Mapping Table
 * - Cmd buffer
 * - Event/PRR (A/B) logs
 */
static int viommu_init_one(struct amd_iommu *iommu, struct amd_iommu_vminfo *vminfo)
{
	int ret;

	ret = alloc_private_vm_region(iommu, &vminfo->devid_table,
				      VIOMMU_DEVID_MAPPING_BASE,
				      VIOMMU_DEVID_MAPPING_ENTRY_SIZE,
				      vminfo->gid);
	if (ret)
		goto err_out;

	ret = alloc_private_vm_region(iommu, &vminfo->domid_table,
				      VIOMMU_DOMID_MAPPING_BASE,
				      VIOMMU_DOMID_MAPPING_ENTRY_SIZE,
				      vminfo->gid);
	if (ret)
		goto err_out;

	viommu_clear_mapping(iommu, vminfo->gid);
	viommu_clear_dirty_status_mask(iommu, vminfo->gid);

	return 0;
err_out:
	viommu_uninit_one(iommu, vminfo, vminfo->gid);
	return -ENOMEM;
}

int viommu_gid_alloc(struct amd_iommu *iommu, struct amd_iommu_vminfo *vminfo)
{
	u32 gid;
	struct amd_iommu_vminfo *tmp;
	unsigned long flags;

	spin_lock_irqsave(&viommu_gid_hash_lock, flags);
again:
	gid = viommu_next_gid = (viommu_next_gid + 1) & 0xFFFF;

	if (gid == 0) { /* id is 1-based, zero is not allowed */
		next_viommu_gid_wrapped = 1;
		goto again;
	}
	/* Is it still in use? Only possible if wrapped at least once */
	if (next_viommu_gid_wrapped) {
		hash_for_each_possible(viommu_gid_hash, tmp, hnode, gid) {
			if (tmp->gid == gid)
				goto again;
		}
	}

	pr_debug("%s: gid=%u\n", __func__, gid);
	vminfo->gid = gid;
	hash_add(viommu_gid_hash, &vminfo->hnode, vminfo->gid);
	spin_unlock_irqrestore(&viommu_gid_hash_lock, flags);
	return 0;
}

static void viommu_gid_free(struct amd_iommu *iommu,
			    struct amd_iommu_vminfo *vminfo)
{
	unsigned long flags;

	pr_debug("%s: gid=%u\n", __func__, vminfo->gid);
	spin_lock_irqsave(&viommu_gid_hash_lock, flags);
	hash_del(&vminfo->hnode);
	spin_unlock_irqrestore(&viommu_gid_hash_lock, flags);
}

struct amd_iommu_vminfo *get_vminfo(struct amd_iommu *iommu, int gid)
{
	unsigned long flags;
	struct amd_iommu_vminfo *tmp, *ptr = NULL;

	spin_lock_irqsave(&viommu_gid_hash_lock, flags);
	hash_for_each_possible(viommu_gid_hash, tmp, hnode, gid) {
		if (tmp->gid == gid) {
			ptr = tmp;
			break;
		}
	}
	if (!ptr)
		pr_debug("%s : gid=%u not found\n", __func__, gid);
	spin_unlock_irqrestore(&viommu_gid_hash_lock, flags);
	return ptr;
}

int amd_viommu_iommu_init(struct amd_viommu_iommu_info *data)
{
	int ret;
	struct amd_iommu_vminfo *vminfo;
	unsigned int iommu_id = data->iommu_id;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(iommu_id);

	if (!iommu)
		return -ENODEV;

	vminfo = kzalloc(sizeof(*vminfo), GFP_KERNEL);
	if (!vminfo)
		return -ENOMEM; 

	ret = viommu_gid_alloc(iommu, vminfo);
	if (ret)
		goto err_out;
	
	ret = viommu_init_one(iommu, vminfo);
	if (ret)
		goto err_out;

	vminfo->init = true;
	data->gid = vminfo->gid;
	pr_debug("%s: iommu_id=%#x, gid=%#x\n", __func__,
		pci_dev_id(iommu->dev), vminfo->gid);

	return ret;

err_out:
	viommu_gid_free(iommu, vminfo);
	kfree(vminfo);
	return ret;
}
EXPORT_SYMBOL(amd_viommu_iommu_init);

int amd_viommu_iommu_destroy(struct amd_viommu_iommu_info *data)
{
	unsigned int gid = data->gid;
	struct amd_iommu_vminfo *vminfo;
	unsigned int iommu_id = data->iommu_id;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(iommu_id);

	if (!iommu)
		return -ENODEV;

	vminfo = get_vminfo(iommu, gid);
	if (!vminfo)
		return -EINVAL;

	viommu_uninit_one(iommu, vminfo, gid);

	if (vminfo->init)
		vminfo->init = false;
	return 0;

}
EXPORT_SYMBOL(amd_viommu_iommu_destroy);

/*
 * Program the DomID via VFCTRL registers
 * This function will be called during VM init via VFIO.
 */
static void set_domain_mapping(struct amd_iommu *iommu, u16 guestId, u16 hDomId, u16 gDomId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);

	pr_debug("%s: iommu_id=%#x, gid=%#x, dom_id=%#x, gdom_id=%#x, val=%#llx\n",
		 __func__, pci_dev_id(iommu->dev), guestId, hDomId, gDomId, val);

	tmp1 = gDomId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDomId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001UL;
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL1_OFFSET);
	wbinvd_on_all_cpus();
}

u64 get_domain_mapping(struct amd_iommu *iommu, u16 gid, u16 gdom_id)
{
	void *addr;
	u64 offset, val;
	struct amd_iommu_vminfo *vminfo;

	vminfo = get_vminfo(iommu, gid);
	if (!vminfo)
		return -EINVAL;

	addr = vminfo->domid_table;
	offset = gdom_id << 3;
	val = *((u64 *)(addr + offset));

	return val;
}

void dump_domain_mapping(struct amd_iommu *iommu, u16 gid, u16 gdom_id)
{
	void *addr;
	u64 offset, val;
	struct amd_iommu_vminfo *vminfo;

	vminfo = get_vminfo(iommu, gid);
	if (!vminfo)
		return;

	addr = vminfo->domid_table;
	offset = gdom_id << 3;
	val = *((u64 *)(addr + offset));

	pr_debug("%s: offset=%#llx(val=%#llx)\n", __func__,
		(unsigned long long)offset,
		(unsigned long long)val);
}

static u16 viommu_get_hdev_id(struct amd_iommu *iommu, u16 guestId, u16 gdev_id)
{
	struct amd_iommu_vminfo *vminfo;
	void *addr;
	u64 offset;

	vminfo = get_vminfo(iommu, guestId);
	if (!vminfo)
		return -1;

	addr = vminfo->devid_table;
	offset = gdev_id << 4;
	return (*((u64 *)(addr + offset)) >> 24) & 0xFFFF;
}

int amd_viommu_domain_update(struct amd_viommu_dom_info *data, bool is_set)
{
	u16 hdom_id, hdev_id;
	int gid = data->gid;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(data->iommu_id);
	struct dev_table_entry *dev_table = get_dev_table(iommu);

	if (!iommu)
		return -ENODEV;

	hdev_id = viommu_get_hdev_id(iommu, gid, data->gdev_id);
	hdom_id = dev_table[hdev_id].data[1] & 0xFFFFULL;

	if (is_set) {
		set_domain_mapping(iommu, gid, hdom_id, data->gdom_id);
		dump_domain_mapping(iommu, 0, data->gdom_id);
	} else
		clear_domain_mapping(iommu, gid, hdom_id, data->gdom_id);

	return 0;
}
EXPORT_SYMBOL(amd_viommu_domain_update);

static void set_dte_viommu(struct amd_iommu *iommu, u16 hDevId, u16 gid, u16 gDevId)
{
	u64 tmp, dte;
	struct dev_table_entry *dev_table = get_dev_table(iommu);

	// vImuEn
	dte = dev_table[hDevId].data[3];
	dte |= (1ULL << DTE_VIOMMU_EN_SHIFT);

	// GDeviceID
	tmp = gDevId & DTE_VIOMMU_GUESTID_MASK;
	dte |= (tmp << DTE_VIOMMU_GUESTID_SHIFT);

	// GuestID
	tmp = gid & DTE_VIOMMU_GUESTID_MASK;
	dte |= (tmp << DTE_VIOMMU_GDEVICEID_SHIFT);

	dev_table[hDevId].data[3] = dte;

	dte = dev_table[hDevId].data[0];
	dte |= DTE_FLAG_GV;
	dev_table[hDevId].data[0] = dte;

	iommu_flush_dte(iommu, hDevId);
}

void dump_device_mapping(struct amd_iommu *iommu, u16 guestId, u16 gdev_id)
{
	void *addr;
	u64 offset, val;
	struct amd_iommu_vminfo *vminfo;

	vminfo = get_vminfo(iommu, guestId);
	if (!vminfo)
		return;

	addr = vminfo->devid_table;
	offset = gdev_id << 4;
	val = *((u64 *)(addr + offset));

	pr_debug("%s: guestId=%#x, gdev_id=%#x, base=%#llx, offset=%#llx(val=%#llx)\n", __func__,
		 guestId, gdev_id, (unsigned long long)iommu_virt_to_phys(vminfo->devid_table),
		 (unsigned long long)offset, (unsigned long long)val);
}

/*
 * Program the DevID via VFCTRL registers
 * This function will be called during VM init via VFIO.
 */
static void set_device_mapping(struct amd_iommu *iommu, u16 hDevId, u16 guestId, u16 queueId, u16 gDevId)
{
	u64 val, tmp1, tmp2;
	u8 __iomem *vfctrl;

	pr_debug("%s: iommu_id=%#x, gid=%#x, hDevId=%#x, gDevId=%#x\n",
		__func__, pci_dev_id(iommu->dev), guestId, hDevId, gDevId);

	set_dte_viommu(iommu, hDevId, guestId, gDevId);

	tmp1 = gDevId;
	tmp1 = ((tmp1 & 0xFFFFULL) << 46);
	tmp2 = hDevId;
	tmp2 = ((tmp2 & 0xFFFFULL) << 14);
	val = tmp1 | tmp2 | 0x8000000000000001ULL;
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, guestId);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_DID_MAP_CONTROL0_OFFSET);
	wbinvd_on_all_cpus();

	tmp1 = hDevId;
	val = ((tmp1 & 0xFFFFULL) << 16);
	writeq(val, vfctrl + VIOMMU_VFCTRL_GUEST_MISC_CONTROL_OFFSET);
}

static void clear_dte_viommu(struct amd_iommu *iommu, u16 hDevId)
{
	struct dev_table_entry *dev_table = get_dev_table(iommu);
	u64 dte = dev_table[hDevId].data[3];

	dte &= ~(1ULL << DTE_VIOMMU_EN_SHIFT);
	dte &= ~(0xFFFFULL << DTE_VIOMMU_GUESTID_SHIFT);
	dte &= ~(0xFFFFULL << DTE_VIOMMU_GDEVICEID_SHIFT);

	dev_table[hDevId].data[3] = dte;

	dte = dev_table[hDevId].data[0];
	dte &= ~DTE_FLAG_GV;
	dev_table[hDevId].data[0] = dte;

	iommu_flush_dte(iommu, hDevId);
}

int amd_viommu_device_update(struct amd_viommu_dev_info *data, bool is_set)
{
	struct pci_dev *pdev;
	struct iommu_domain *dom;
	int gid = data->gid;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(data->iommu_id);

	if (!iommu)
		return -ENODEV;

	clear_dte_viommu(iommu, data->hdev_id);

	if (is_set) {
		set_device_mapping(iommu, data->hdev_id, gid,
				   data->queue_id, data->gdev_id);

		pdev = pci_get_domain_bus_and_slot(0, PCI_BUS_NUM(data->hdev_id),
						   data->hdev_id & 0xff);
		dom = iommu_get_domain_for_dev(&pdev->dev);
		if (!dom) {
			pr_err("%s: Domain not found (devid=%#x)\n",
			       __func__, pci_dev_id(pdev));
			return -EINVAL;
		}

		/* TODO: Only support pasid 0 for now */
		amd_iommu_flush_tlb(dom, 0);
		dump_device_mapping(iommu, gid, data->gdev_id);

	} else {
		clear_device_mapping(iommu, data->hdev_id, gid,
				     data->queue_id, data->gdev_id);
	}

	return 0;
}
EXPORT_SYMBOL(amd_viommu_device_update);

int amd_viommu_guest_mmio_read(struct amd_viommu_mmio_data *data)
{
	u8 __iomem *vfctrl, *vf;
	u64 val, tmp = 0;
	int gid = data->gid;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(data->iommu_id);

	if (!iommu)
		return -ENODEV;

	vf = VIOMMU_VF_MMIO_BASE(iommu, gid);
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	switch (data->offset) {
	case MMIO_CONTROL_OFFSET:
	{
		/* VFCTRL offset 20h */
		val = readq(vfctrl + 0x20);
		tmp |= SET_CTRL_BITS(val, 8, CONTROL_CMDBUF_EN, 1); // [12]
		tmp |= SET_CTRL_BITS(val, 9, CONTROL_COMWAIT_EN, 1); // [4]

		/* VFCTRL offset 28h */
		val = readq(vfctrl + 0x28);
		tmp |= SET_CTRL_BITS(val, 8, CONTROL_EVT_LOG_EN, 1); // [2]
		tmp |= SET_CTRL_BITS(val, 9, CONTROL_EVT_INT_EN, 1); // [3]
		tmp |= SET_CTRL_BITS(val, 10, CONTROL_DUALEVTLOG_EN, 3); // [33:32]

		/* VFCTRL offset 30h */
		val = readq(vfctrl + 0x30);
		tmp |= SET_CTRL_BITS(val, 8, CONTROL_PPRLOG_EN, 1); // [13]
		tmp |= SET_CTRL_BITS(val, 9, CONTROL_PPRINT_EN, 1); // [14]
		tmp |= SET_CTRL_BITS(val, 10, CONTROL_PPR_EN, 1); // [15]
		tmp |= SET_CTRL_BITS(val, 11, CONTROL_DUALPPRLOG_EN, 3); // [31:30]
		tmp |= SET_CTRL_BITS(val, 13, CONTROL_PPR_AUTO_RSP_EN, 1); // [39]
		tmp |= SET_CTRL_BITS(val, 14, CONTROL_BLKSTOPMRK_EN, 1); // [41]
		tmp |= SET_CTRL_BITS(val, 15, CONTROL_PPR_AUTO_RSP_AON, 1); // [42]

		data->value = tmp;
		break;
	}
	case MMIO_CMD_BUF_OFFSET:
	{
		val = readq(vfctrl + 0x20);
		/* CmdLen [59:56] */
		tmp |= SET_CTRL_BITS(val, 0, 56, 0xF);
		data->value = tmp;
		break;
	}
	case MMIO_EVT_BUF_OFFSET:
	{
		val = readq(vfctrl + 0x28);
		/* EventLen [59:56] */
		tmp |= SET_CTRL_BITS(val, 0, 56, 0xF);
		data->value = tmp;
		break;
	}
	case MMIO_EVTB_LOG_OFFSET:
	{
		val = readq(vfctrl + 0x28);
		/* EventLenB [59:56] */
		tmp |= SET_CTRL_BITS(val, 4, 56, 0xF);
		data->value = tmp;
		break;
	}
	case MMIO_PPR_LOG_OFFSET:
	{
		val = readq(vfctrl + 0x30);
		/* PPRLogLen [59:56] */
		tmp |= SET_CTRL_BITS(val, 0, 56, 0xF);
		data->value = tmp;
		break;
	}
	case MMIO_PPRB_LOG_OFFSET:
	{
		val = readq(vfctrl + 0x30);
		/* PPRLogLenB [59:56] */
		tmp |= SET_CTRL_BITS(val, 4, 56, 0xF);
		data->value |= tmp;
		break;
	}
	case MMIO_CMD_HEAD_OFFSET:
	{
		val = readq(vf + 0x0);
		data->value = (val & 0x7FFF0);
		break;
	}
	case MMIO_CMD_TAIL_OFFSET:
	{
		val = readq(vf + 0x8);
		data->value = (val & 0x7FFF0);
		break;
	}
	case MMIO_EXT_FEATURES:
	{
		/* TODO: We need to set all the necessary features */
		data->value = FEATURE_GIOSUP | FEATURE_GT | FEATURE_PPR;
		break;
	}
	default:
		break;
	}

	pr_debug("%s: iommu_id=%#x, gid=%u, offset=%#x, value=%#llx, mmio_size=%u, is_write=%u\n",
		 __func__, data->iommu_id, gid, data->offset,
		 data->value, data->mmio_size, data->is_write);
	return 0;
}
EXPORT_SYMBOL(amd_viommu_guest_mmio_read);

/* Note:
 * This function maps the guest MMIO write to AMD IOMMU MMIO registers
 * into vIOMMU VFCTRL register bits.
 */
int amd_viommu_guest_mmio_write(struct amd_viommu_mmio_data *data)
{
	u8 __iomem *vfctrl, *vf;
	int gid = data->gid;
	u64 val, tmp, ctrl = data->value;
	struct amd_iommu *iommu = get_amd_iommu_from_devid(data->iommu_id);

	if (!iommu)
		return -ENODEV;

	pr_debug("%s: iommu_id=%#x, gid=%u, offset=%#x, value=%#llx, mmio_size=%u, is_write=%u\n",
		 __func__, data->iommu_id, gid, data->offset,
		 ctrl, data->mmio_size, data->is_write);

	vf = VIOMMU_VF_MMIO_BASE(iommu, gid);
	vfctrl = VIOMMU_VFCTRL_MMIO_BASE(iommu, gid);

	switch (data->offset) {
	case MMIO_CONTROL_OFFSET:
	{
		/* VFCTRL offset 20h */
		val = readq(vfctrl + 0x20);
		val &= ~(0x3ULL << 8);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_CMDBUF_EN, 1); // [12]
		val |= (tmp << 8);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_COMWAIT_EN, 1); // [4]
		val |= (tmp << 9);
		writeq(val, vfctrl + 0x20);

		/* VFCTRL offset 28h */
		val = readq(vfctrl + 0x28);
		val &= ~(0xFULL << 8);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_EVT_LOG_EN, 1); // [2]
		val |= (tmp << 8);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_EVT_INT_EN, 1); // [3]
		val |= (tmp << 9);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_DUALEVTLOG_EN, 3); // [33:32]
		val |= (tmp << 10);
		writeq(val, vfctrl + 0x28);

		/* VFCTRL offset 30h */
		val = readq(vfctrl + 0x30);
		val &= ~(0xFFULL << 8);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_PPRLOG_EN, 1); // [13]
		val |= (tmp << 8);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_PPRINT_EN, 1); // [14]
		val |= (tmp << 9);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_PPR_EN, 1); // [15]
		val |= (tmp << 10);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_DUALPPRLOG_EN, 3); // [31:30]
		val |= (tmp << 11);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_PPR_AUTO_RSP_EN, 1); // [39]
		val |= (tmp << 13);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_BLKSTOPMRK_EN, 1); // [41]
		val |= (tmp << 14);
		tmp = GET_CTRL_BITS(ctrl, CONTROL_PPR_AUTO_RSP_AON, 1); // [42]
		val |= (tmp << 15);
		writeq(val, vfctrl + 0x30);
		break;
	}
	case MMIO_CMD_BUF_OFFSET:
	{
		val = readq(vfctrl + 0x20);
		val &= ~(0xFULL);
		/* CmdLen [59:56] */
		tmp = GET_CTRL_BITS(ctrl, 56, 0xF);
		val |= tmp;
		writeq(val, vfctrl + 0x20);
		break;
	}
	case MMIO_EVT_BUF_OFFSET:
	{
		val = readq(vfctrl + 0x28);
		val &= ~(0xFULL);
		/* EventLen [59:56] */
		tmp = GET_CTRL_BITS(ctrl, 56, 0xF);
		val |= tmp;
		writeq(val, vfctrl + 0x28);
		break;
	}
	case MMIO_EVTB_LOG_OFFSET:
	{
		val = readq(vfctrl + 0x28);
		val &= ~(0xF0ULL);
		/* EventLenB [59:56] */
		tmp = GET_CTRL_BITS(ctrl, 56, 0xF);
		val |= (tmp << 4);
		writeq(val, vfctrl + 0x28);
		break;
	}
	case MMIO_PPR_LOG_OFFSET:
	{
		val = readq(vfctrl + 0x30);
		val &= ~(0xFULL);
		/* PPRLogLen [59:56] */
		tmp = GET_CTRL_BITS(ctrl, 56, 0xF);
		val |= tmp;
		writeq(val, vfctrl + 0x30);
		break;
	}
	case MMIO_PPRB_LOG_OFFSET:
	{
		val = readq(vfctrl + 0x30);
		val &= ~(0xF0ULL);
		/* PPRLogLenB [59:56] */
		tmp = GET_CTRL_BITS(ctrl, 56, 0xF);
		val |= (tmp << 4);
		writeq(val, vfctrl + 0x30);
		break;
	}
	case MMIO_CMD_HEAD_OFFSET:
	{
		val = readq(vf + 0x0);
		val &= ~(0x7FFFULL << 4);
		tmp = GET_CTRL_BITS(ctrl, 4, 0x7FFF);
		val |= (tmp << 4);
		writeq(val, vf + 0x0);
		break;
	}
	case MMIO_CMD_TAIL_OFFSET:
	{
		val = readq(vf + 0x8);
		val &= ~(0x7FFFULL << 4);
		tmp = GET_CTRL_BITS(ctrl, 4, 0x7FFF);
		val |= (tmp << 4);
		writeq(val, vf + 0x8);
		break;
	}
	default:
		break;
	}

	pr_debug("%s: offset=%#x, val=%#llx, ctrl=%#llx\n",
		 __func__, data->offset, val, ctrl);
	return 0;
}
EXPORT_SYMBOL(amd_viommu_guest_mmio_write);
