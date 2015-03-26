/*
 * Copyright (c) 2015, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef OPTEE_OPTEE_H
#define OPTEE_OPTEE_H

#include <linux/types.h>

/* Number of buffers used in RPC communication */
#define OPTEE_RPC_NUM_BUFS 2

struct optee_cmd_prefix {
	__u32 smc_id;
	__u32 pad;
};

#endif /* OPTEE_OPTEE_H */
