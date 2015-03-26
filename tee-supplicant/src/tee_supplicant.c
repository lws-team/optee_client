/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 * Copyright (c) 2015, Linaro Limited
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <teec_trace.h>
#include <teec_rpc.h>
#include <teec_ta_load.h>
#include <tee_supp_fs.h>

#include <linux/types.h>
#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/sec-hw/optee/teesmc.h>
#include <linux/sec-hw/optee/teesmc_optee.h>
#include <linux/sec-hw/optee/optee.h>
#include <linux/sec-hw/tee.h>


#define RPC_CMD_WRITE	0
#define RPC_CMD_READ	1

struct tee_rpc_invoke {
	struct optee_cmd_prefix cmd_prefix;
	uint64_t buf[TEESMC_GET_ARG_SIZE(OPTEE_RPC_NUM_BUFS) /
		     sizeof(uint64_t)];
};

struct tee_rpc_ta {
	TEEC_UUID uuid;
	uint32_t supp_ta_handle;
};

static int read_request(int fd, struct tee_rpc_invoke *request);
static int write_response(int fd, struct tee_rpc_invoke *request);
static void free_param(TEEC_SharedMemory *shared_mem);

/* Get parameter allocated by secure world */
static int get_param(struct teesmc_arg *arg, const uint32_t idx,
		     TEEC_SharedMemory *shm)
{
	struct teesmc_param *params;

	if (idx >= arg->num_params)
		return -1;

	params = TEESMC_GET_PARAMS(arg);

	switch (params[idx].attr & TEESMC_ATTR_TYPE_MASK) {
	case TEESMC_ATTR_TYPE_MEMREF_INPUT:
	case TEESMC_ATTR_TYPE_MEMREF_OUTPUT:
	case TEESMC_ATTR_TYPE_MEMREF_INOUT:
		break;
	default:
		return -1;
	}


	memset(shm, 0, sizeof(*shm));
	shm->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shm->size = params[idx].u.memref.size;
	shm->fd = params[idx].u.memref.shm_ref;
	if (shm->fd == -1)
		return 0;
	shm->buffer = mmap(NULL, shm->size, PROT_READ | PROT_WRITE, MAP_SHARED,
			   shm->fd, params[idx].u.memref.buf_ptr);
	params[idx].u.memref.shm_ref = -1; /* fd taken */
	if (shm->buffer == (void *)MAP_FAILED) {
		EMSG("failed to mmap parameter (fd %d, offs 0x%llx, idx %d): %s",
		     shm->fd, params[idx].u.memref.buf_ptr, idx, strerror(errno));
		close(shm->fd);
		shm->fd = -1;
		return -1;
	}
	return 0;
}

/* Release parameter recieved from get_param or alloc_param */
static void free_param(TEEC_SharedMemory *shared_mem)
{
	if (!shared_mem->buffer)
		return;
	if (munmap(shared_mem->buffer, shared_mem->size) != 0)
		EMSG("munmap(%p, %zu) failed - Error = %s",
		     shared_mem->buffer, shared_mem->size,
		     strerror(errno));
	close(shared_mem->fd);
}

static void process_fs(struct teesmc_arg *arg)
{
	TEEC_SharedMemory shared_mem;

	INMSG();
	if (get_param(arg, 0, &shared_mem)) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	tee_supp_fs_process(shared_mem.buffer, shared_mem.size);
	arg->ret = TEEC_SUCCESS;;

	free_param(&shared_mem);
	OUTMSG();
}

static void load_ta(struct teesmc_arg *arg)
{
	int ta_found = 0;
	size_t size = 0;
	struct tee_rpc_ta *cmd;
	TEEC_SharedMemory shm_cmd = { 0 };
	TEEC_SharedMemory shm_ta = { 0 };

	if (get_param(arg, 0, &shm_cmd) || get_param(arg, 1, &shm_ta)) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}
	cmd = (struct tee_rpc_ta *)shm_cmd.buffer;

	size = shm_ta.size;
	ta_found = TEECI_LoadSecureModule("teetz", &cmd->uuid, shm_ta.buffer,
					  &size);
	if (ta_found == TA_BINARY_FOUND) {
		struct teesmc_param *params = TEESMC_GET_PARAMS(arg);

		params[1].u.memref.size = size;
		arg->ret = TEEC_SUCCESS;
	} else {
		EMSG("  TA not found");
		arg->ret = TEEC_ERROR_ITEM_NOT_FOUND;
	}

	free_param(&shm_cmd);
	free_param(&shm_ta);
}

static void get_ree_time(struct teesmc_arg *arg)
{
	struct timeval tv;
	struct teesmc_param *params;

	if (arg->num_params < 1) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	params = TEESMC_GET_PARAMS(arg);

	if (params->attr != TEESMC_ATTR_TYPE_VALUE_OUTPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	gettimeofday(&tv, NULL);

	params->u.value.a = tv.tv_sec;
	params->u.value.b = tv.tv_usec / 1000;

	DMSG("%ds:%dms", (int)params->u.value.a, (int)params->u.value.b);

	arg->ret = TEEC_SUCCESS;
}

static int tee_cmd(int fd, void *buf, size_t size)
{
	struct tee_ioctl_cmd_data data;

	data.buf_ptr = (uintptr_t)buf;
	data.buf_len = size;
	return ioctl(fd, TEE_IOC_CMD, &data);
}


static int cmd_get_uuid(int fd, uint32_t cmd_id, TEEC_UUID *uuid)
{
	struct uuid_data {
		struct optee_cmd_prefix cmd_prefix;
		TEEC_UUID uuid;
	} data;

	data.cmd_prefix.smc_id = cmd_id;

	if (tee_cmd(fd, &data, sizeof(data)))
		return -1;
	if (data.uuid.timeLow == 0xffffffff)
		return -1;      /* SMC id not implemented */
	*uuid = data.uuid;
	return 0;
}


/* How many device sequence numbers will be tried before giving up */
#define MAX_DEV_SEQ	10

static int open_dev(const char *devname)
{
	struct tee_ioctl_version vers;
	int fd;
	TEEC_UUID uuid;
	static const uint32_t optee_calls_uuid[] = {
		TEESMC_OPTEE_UID_R0,
		TEESMC_OPTEE_UID_R1,
		TEESMC_OPTEE_UID_R2,
		TEESMC_OPTEE_UID32_R3,
	};

	fd = open(devname, O_RDWR);
	if (fd < 0)
		return -1;

	if (ioctl(fd, TEE_IOC_VERSION, &vers))
		goto err;

	if (vers.gen_version != TEE_SUBSYS_VERSION ||
	    vers.spec_version != TEESMC_OPTEE_REVISION_MAJOR)
		goto err;

	if (cmd_get_uuid(fd, TEESMC32_CALLS_UID, &uuid))
		goto err;
	if (memcmp(&uuid, optee_calls_uuid, sizeof(uuid)) != 0)
		goto err;

	DMSG("using device \"%s\"", devname);
	return fd;
err:
	if (fd >= 0)
		close(fd);
	return -1;
}

static int get_dev_fd(void)
{
	int fd;
	char name[PATH_MAX];
	size_t n;

	for (n = 0; n < MAX_DEV_SEQ; n++) {
		snprintf(name, sizeof(name), "/dev/teepriv%zu", n);
		fd = open_dev(name);
		if (fd >= 0)
			return fd;
	}
	return -1;
}

static void usage(void)
{
	fprintf(stderr, "usage: tee-supplicant [<device-name>]");
	exit(1);
}

int main(int argc, char *argv[])
{
	int fd;
	struct tee_rpc_invoke request;
	struct teesmc_arg *arg = (struct teesmc_arg *)request.buf;
	int ret;

	if (argc > 2)
		usage();
	if (argc == 2) {
		fd = open_dev(argv[1]);
		if (fd < 0) {
			EMSG("failed to open \"%s\"", argv[1]);
			exit(EXIT_FAILURE);
		}
	} else {
		fd = get_dev_fd();
		if (fd < 0) {
			EMSG("failed to find an OP-TEE supplicant device");
			exit(EXIT_FAILURE);
		}
	}

	if (tee_supp_fs_init() != 0) {
		EMSG("error tee_supp_fs_init");
		exit(EXIT_FAILURE);
	}

	/* major failure on read kills supplicant, malformed data will not */
	do {
		DMSG("looping");
		ret = read_request(fd, &request);
		if (ret == 0 && arg->num_params <= OPTEE_RPC_NUM_BUFS) {
			switch (arg->cmd) {
			case TEE_RPC_LOAD_TA:
				load_ta(arg);
				break;

			case TEE_RPC_GET_TIME:
				get_ree_time(arg);
				break;

			case TEE_RPC_FS:
				process_fs(arg);
				break;
			default:
				EMSG("Cmd [0x%" PRIx32 "] not supported",
				     arg->cmd);
				/* Not supported. */
				break;
			}

			ret = write_response(fd, &request);
		}
	} while (ret >= 0);

	close(fd);

	return EXIT_FAILURE;
}

static int read_request(int fd, struct tee_rpc_invoke *request)
{
	struct tee_ioctl_cmd_data data;

	request->cmd_prefix.smc_id = RPC_CMD_READ;
	data.buf_ptr = (uintptr_t)request;
	data.buf_len = sizeof(*request);
	if (ioctl(fd, TEE_IOC_CMD, &data)) {
		EMSG("error reading from device: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static int write_response(int fd, struct tee_rpc_invoke *request)
{
	struct tee_ioctl_cmd_data data;
	struct teesmc_arg *arg = (struct teesmc_arg *)request->buf;
	struct teesmc_param *params;
	size_t n;

	/* Close file descriptors not claimed */
	params = TEESMC_GET_PARAMS(arg);
	for (n = 0; n < OPTEE_RPC_NUM_BUFS; n++) {
		switch (params[n].attr & TEESMC_ATTR_TYPE_MASK) {
		case TEESMC_ATTR_TYPE_MEMREF_INPUT:
		case TEESMC_ATTR_TYPE_MEMREF_OUTPUT:
		case TEESMC_ATTR_TYPE_MEMREF_INOUT:
			if ((int)params[n].u.memref.shm_ref != -1)
				close(params[n].u.memref.shm_ref);
			params[n].u.memref.shm_ref = -1;
			break;
		default:
			break;
		}
	}


	request->cmd_prefix.smc_id = RPC_CMD_WRITE;
	data.buf_ptr = (uintptr_t)request;
	data.buf_len = sizeof(*request);
	if (ioctl(fd, TEE_IOC_CMD, &data)) {
		EMSG("error writing to device: %s", strerror(errno));
		return -1;
	}
	return 0;
}
