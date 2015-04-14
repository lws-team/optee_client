/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TEESMC_OPTEE_H
#define TEESMC_OPTEE_H

#define TEESMC_OPTEE_RETURN_NOTAVAIL	0x5700

/*
 * Get Shared Memory Config
 *
 * Returns the Secure/Non-secure shared memory config.
 *
 * Call register usage:
 * r0	SMC Function ID, TEESMC32_OPTEE_FASTCALL_GET_SHM_CONFIG
 * r1-6	Not used
 * r7	Hypervisor Client ID register
 *
 * Have config return register usage:
 * r0	TEESMC_RETURN_OK
 * r1	Physical address of start of SHM
 * r2	Size of of SHM
 * r3	1 if SHM is cached, 0 if uncached.
 * r4-7	Preserved
 *
 * Not available register usage:
 * r0	TEESMC_OPTEE_RETURN_NOTAVAIL
 * r1-3 Not used
 * r4-7	Preserved
 */
#define TEESMC_OPTEE_FUNCID_GET_SHM_CONFIG	0x5700
#define TEESMC32_OPTEE_FASTCALL_GET_SHM_CONFIG \
	TEESMC_CALL_VAL(TEESMC_32, TEESMC_FAST_CALL, TEESMC_OWNER_TRUSTED_OS, \
			TEESMC_OPTEE_FUNCID_GET_SHM_CONFIG)

/*
 * Configures L2CC mutex
 *
 * Disables, enables usage of L2CC mutex. Returns or sets physical address
 * of L2CC mutex.
 *
 * Call register usage:
 * r0	SMC Function ID, TEESMC32_OPTEE_FASTCALL_L2CC_MUTEX
 * r1	TEESMC_OPTEE_L2CC_MUTEX_GET_ADDR Get physical address of mutex
 *	TEESMC_OPTEE_L2CC_MUTEX_SET_ADDR Set physical address of mutex
 *	TEESMC_OPTEE_L2CC_MUTEX_ENABLE	 Enable usage of mutex
 *	TEESMC_OPTEE_L2CC_MUTEX_DISABLE	 Disable usage of mutex
 * r2	if r1 == TEESMC_OPTEE_L2CC_MUTEX_SET_ADDR, physical address of mutex
 * r3-6	Not used
 * r7	Hypervisor Client ID register
 *
 * Have config return register usage:
 * r0	TEESMC_RETURN_OK
 * r1	Preserved
 * r2	if r1 == 0, physical address of L2CC mutex
 * r3-7	Preserved
 *
 * Error return register usage:
 * r0	TEESMC_OPTEE_RETURN_NOTAVAIL	Physical address not available
 *	TEESMC_RETURN_EBADADDR		Bad supplied physical address
 *	TEESMC_RETURN_EBADCMD		Unsupported value in r1
 * r1-7	Preserved
 */
#define TEESMC_OPTEE_L2CC_MUTEX_GET_ADDR	0
#define TEESMC_OPTEE_L2CC_MUTEX_SET_ADDR	1
#define TEESMC_OPTEE_L2CC_MUTEX_ENABLE	2
#define TEESMC_OPTEE_L2CC_MUTEX_DISABLE	3
#define TEESMC_OPTEE_FUNCID_L2CC_MUTEX	0x5701
#define TEESMC32_OPTEE_FASTCALL_L2CC_MUTEX \
	TEESMC_CALL_VAL(TEESMC_32, TEESMC_FAST_CALL, TEESMC_OWNER_TRUSTED_OS, \
			TEESMC_OPTEE_FUNCID_L2CC_MUTEX)

/*
 * Overriding default UID of the API since the it has OP-TEE extensions
 * 384fb3e0-e7f8-11e3-af63-0002a5d5c51b.
 */
#define TEESMC_OPTEE_UID_R0		0x384fb3e0
#define TEESMC_OPTEE_UID_R1		0xe7f811e3
#define TEESMC_OPTEE_UID_R2		0xaf630002
#define TEESMC_OPTEE_UID_R3		0xa5d5c51b

#define TEESMC_OPTEE_REVISION_MAJOR	2
#define TEESMC_OPTEE_REVISION_MINOR	0

/*
 * UUID for OP-TEE
 * 486178e0-e7f8-11e3-bc5e-0002a5d5c51b
 */
#define TEESMC_OS_OPTEE_UUID_R0		0x486178e0
#define TEESMC_OS_OPTEE_UUID_R1		0xe7f811e3
#define TEESMC_OS_OPTEE_UUID_R2		0xbc5e0002
#define TEESMC_OS_OPTEE_UUID_R3		0xa5d5c51b

#define TEESMC_OS_OPTEE_REVISION_MAJOR	1
#define TEESMC_OS_OPTEE_REVISION_MINOR	0

#endif /*TEESMC_OPTEE_H*/
