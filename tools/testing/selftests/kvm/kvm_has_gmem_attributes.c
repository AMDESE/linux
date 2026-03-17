// SPDX-License-Identifier: GPL-2.0-only
/*
 * Utility to check if KVM supports guest_memfd attributes.
 *
 * Copyright (C) 2025, Google LLC.
 */

#include <stdio.h>

#include "kvm_util.h"

int main(void)
{
	printf("%u\n", kvm_check_cap(KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES) > 0);

	return 0;
}
