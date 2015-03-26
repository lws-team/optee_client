/*
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
#include <tee_client_api.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include <linux/types.h>
#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/sec-hw/optee/teesmc.h>
#include <linux/sec-hw/optee/teesmc_optee.h>
#include <linux/sec-hw/optee/optee.h>
#include <linux/sec-hw/tee.h>

#include <teec_trace.h>
#include <err.h>

/* How many device sequence numbers will be tried before giving up */
#define TEEC_MAX_DEV_SEQ	10

static pthread_mutex_t teec_mutex = PTHREAD_MUTEX_INITIALIZER;

static void teec_mutex_lock(pthread_mutex_t *mu)
{
	pthread_mutex_lock(mu);
}

static void teec_mutex_unlock(pthread_mutex_t *mu)
{
	pthread_mutex_unlock(mu);
}


static int teec_get_version(int fd, struct tee_ioctl_version *vers)
{
	return ioctl(fd, TEE_IOC_VERSION, vers);
}

static int teec_cmd(int fd, void *buf, size_t size)
{
	struct tee_ioctl_cmd_data data;

	data.buf_ptr = (uintptr_t)buf;
	data.buf_len = size;
	return ioctl(fd, TEE_IOC_CMD, &data);
}

static int teec_cmd_get_uuid(int fd, uint32_t smc_id, TEEC_UUID *uuid)
{
	struct uuid_data {
		struct optee_cmd_prefix cmd_prefix;
		TEEC_UUID uuid;
	} data;

	data.cmd_prefix.smc_id = smc_id;

	if (teec_cmd(fd, &data, sizeof(data)))
		return -1;
	if (data.uuid.timeLow == 0xffffffff)
		return -1;	/* SMC id not implemented */
	*uuid = data.uuid;
	return 0;
}

static int teec_open_dev(const char *devname)
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

	if (teec_get_version(fd, &vers))
		goto err;

	if (vers.gen_version != TEE_SUBSYS_VERSION ||
	    vers.spec_version != TEESMC_OPTEE_REVISION_MAJOR)
		goto err;

	if (teec_cmd_get_uuid(fd, TEESMC32_CALLS_UID, &uuid))
		goto err;
	if (memcmp(&uuid, optee_calls_uuid, sizeof(uuid)) != 0)
		goto err;

	return fd;
err:
	if (fd >= 0)
		close(fd);
	return -1;
}

static int teec_shm_alloc(int fd, size_t size)
{
	struct tee_ioctl_shm_alloc_data data = { 0 };

	data.size = size;
	if (ioctl(fd, TEE_IOC_SHM_ALLOC, &data))
		return -1;
	return data.fd;
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *ctx)
{
	char devname[PATH_MAX];
	int fd;

	if (!ctx)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (name) {
		snprintf(devname, sizeof(devname), "/dev/%s", name);
		fd = teec_open_dev(devname);
		if (fd < 0)
			return TEEC_ERROR_ITEM_NOT_FOUND;
		goto out;
	} else {
		size_t n;

		for (n = 0; n < TEEC_MAX_DEV_SEQ; n++) {
			snprintf(devname, sizeof(devname), "/dev/tee%zu", n);
			fd = teec_open_dev(devname);
			if (fd >= 0)
				break;
		}
	}

out:
	if (fd < 0)
		return TEEC_ERROR_ITEM_NOT_FOUND;
	ctx->fd = fd;
	return TEEC_SUCCESS;
}

void TEEC_FinalizeContext(TEEC_Context *ctx)
{
	if (ctx)
		close(ctx->fd);
}


static TEEC_Result teec_pre_process_tmpref(TEEC_Context *ctx,
			uint32_t param_type, TEEC_TempMemoryReference *tmpref,
			struct teesmc_param *param,
			TEEC_SharedMemory *shm)
{
	TEEC_Result res;

	switch (param_type) {
	case TEEC_MEMREF_TEMP_INPUT:
		param->attr = TEESMC_ATTR_TYPE_MEMREF_INPUT;
		shm->flags = TEEC_MEM_INPUT;
		break;
	case TEEC_MEMREF_TEMP_OUTPUT:
		param->attr = TEESMC_ATTR_TYPE_MEMREF_OUTPUT;
		shm->flags = TEEC_MEM_OUTPUT;
		break;
	case TEEC_MEMREF_TEMP_INOUT:
		param->attr = TEESMC_ATTR_TYPE_MEMREF_INOUT;
		shm->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	shm->size = tmpref->size;

	res = TEEC_AllocateSharedMemory(ctx, shm);
	if (res != TEEC_SUCCESS)
		return res;

	memcpy(shm->buffer, tmpref->buffer, tmpref->size);
	param->u.memref.size = tmpref->size;
	param->u.memref.shm_ref = shm->fd;
	return TEEC_SUCCESS;
}

static TEEC_Result teec_pre_process_whole(
			TEEC_RegisteredMemoryReference *memref,
			struct teesmc_param *param)
{
	const uint32_t inout = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	uint32_t flags = memref->parent->flags & inout;
	TEEC_SharedMemory *shm;

	if (flags == inout)
		param->attr = TEESMC_ATTR_TYPE_MEMREF_INOUT;
	else if (flags & TEEC_MEM_INPUT)
		param->attr = TEESMC_ATTR_TYPE_MEMREF_INPUT;
	else if (flags & TEEC_MEM_OUTPUT)
		param->attr = TEESMC_ATTR_TYPE_MEMREF_OUTPUT;
	else
		return TEEC_ERROR_BAD_PARAMETERS;

	shm = memref->parent;
	/*
	 * We're using a shadow buffer in this reference, copy the real buffer
	 * into the shadow buffer if needed. We'll copy it back once we've
	 * returned from the call to secure world.
	 */
	if (shm->shadow_buffer && (flags & TEEC_MEM_INPUT))
		memcpy(shm->shadow_buffer, shm->buffer, shm->size);

	param->u.memref.shm_ref = shm->fd;
	param->u.memref.size = shm->size;
	return TEEC_SUCCESS;
}

static TEEC_Result teec_pre_process_partial(uint32_t param_type,
			TEEC_RegisteredMemoryReference *memref,
			struct teesmc_param *param)
{
	uint32_t req_shm_flags;
	TEEC_SharedMemory *shm;

	switch (param_type) {
	case TEEC_MEMREF_PARTIAL_INPUT:
		req_shm_flags = TEEC_MEM_INPUT;
		param->attr = TEESMC_ATTR_TYPE_MEMREF_INPUT;
		break;
	case TEEC_MEMREF_PARTIAL_OUTPUT:
		req_shm_flags = TEEC_MEM_OUTPUT;
		param->attr = TEESMC_ATTR_TYPE_MEMREF_INPUT;
		break;
	case TEEC_MEMREF_PARTIAL_INOUT:
		req_shm_flags = TEEC_MEM_OUTPUT | TEEC_MEM_INPUT;
		param->attr = TEESMC_ATTR_TYPE_MEMREF_INOUT;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	shm = memref->parent;

	if ((shm->flags & req_shm_flags) != req_shm_flags)
		return TEEC_ERROR_BAD_PARAMETERS;

	/*
	 * We're using a shadow buffer in this reference, copy the real buffer
	 * into the shadow buffer if needed. We'll copy it back once we've
	 * returned from the call to secure world.
	 */
	if (shm->shadow_buffer && param_type != TEEC_MEMREF_PARTIAL_OUTPUT)
		memcpy((char *)shm->shadow_buffer + memref->offset,
		       (char *)shm->buffer + memref->offset, shm->size);

	param->u.memref.shm_ref = shm->fd;
	param->u.memref.buf_ptr = memref->offset;
	param->u.memref.size = memref->size;
	return TEEC_SUCCESS;
}

static bool is_memref(struct teesmc_param *param)
{
	switch (param->attr & TEESMC_ATTR_TYPE_MASK) {
	case TEESMC_ATTR_TYPE_MEMREF_INPUT:
	case TEESMC_ATTR_TYPE_MEMREF_OUTPUT:
	case TEESMC_ATTR_TYPE_MEMREF_INOUT:
		return true;
	default:
		return false;
	}
}


static TEEC_Result teec_pre_process_operation(TEEC_Context *ctx,
			TEEC_Operation *operation,
			struct teesmc_param *params,
			TEEC_SharedMemory *shms)
{
	TEEC_Result res;
	size_t n;

	if (!operation) {
		memset(params, 0, sizeof(struct teesmc_param) *
				  TEEC_CONFIG_PAYLOAD_REF_COUNT);
		for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++)
			if (is_memref(params + n))
				params[n].u.memref.shm_ref = -1;
		return TEEC_SUCCESS;
	}

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t param_type;

		param_type = TEEC_PARAM_TYPE_GET(operation->paramTypes, n);
		switch (param_type) {
		case TEEC_NONE:
			params[n].attr = param_type;
			break;
		case TEEC_VALUE_INPUT:
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:
			params[n].attr = param_type;
			params[n].u.value.a = operation->params[n].value.a;
			params[n].u.value.b = operation->params[n].value.b;
			break;
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:
			res = teec_pre_process_tmpref(ctx, param_type,
				&operation->params[n].tmpref, params + n,
				shms + n);
			if (res != TEEC_SUCCESS)
				return res;
			break;
		case TEEC_MEMREF_WHOLE:
			res = teec_pre_process_whole(
					&operation->params[n].memref,
					params + n);
			if (res != TEEC_SUCCESS)
				return res;
			break;
		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:
			res = teec_pre_process_partial(param_type,
				&operation->params[n].memref, params + n);
			if (res != TEEC_SUCCESS)
				return res;
			break;
		default:
			return TEEC_ERROR_BAD_PARAMETERS;
		}
	}

	return TEEC_SUCCESS;
}

static void teec_post_process_tmpref(uint32_t param_type,
			TEEC_TempMemoryReference *tmpref,
			struct teesmc_param *param,
			TEEC_SharedMemory *shm)
{
	if (param_type != TEEC_MEMREF_TEMP_INPUT) {
		if (param->u.memref.size <= tmpref->size && tmpref->buffer)
			memcpy(tmpref->buffer, shm->buffer,
			       param->u.memref.size);

		tmpref->size = param->u.memref.size;
	}
	TEEC_ReleaseSharedMemory(shm);
}

static void teec_post_process_whole(TEEC_RegisteredMemoryReference *memref,
			struct teesmc_param *param)
{
	TEEC_SharedMemory *shm = memref->parent;

	if (shm->flags & TEEC_MEM_OUTPUT) {

		/*
		 * We're using a shadow buffer in this reference, copy back
		 * the shadow buffer into the real buffer now that we've
		 * returned from secure world.
		 */
		if (shm->shadow_buffer && param->u.memref.size <= memref->size)
			memcpy(shm->buffer, shm->shadow_buffer,
			       param->u.memref.size);

		memref->size = param->u.memref.size;
	}
}

static void teec_post_process_partial(uint32_t param_type,
			TEEC_RegisteredMemoryReference *memref,
			struct teesmc_param *param)
{
	if (param_type != TEEC_MEMREF_PARTIAL_INPUT) {
		TEEC_SharedMemory *shm = memref->parent;

		/*
		 * We're using a shadow buffer in this reference, copy back
		 * the shadow buffer into the real buffer now that we've
		 * returned from secure world.
		 */
		if (shm->shadow_buffer && param->u.memref.size <= memref->size)
			memcpy((char *)shm->buffer + memref->offset,
			       (char *)shm->shadow_buffer + memref->offset,
			       param->u.memref.size);

		memref->size = param->u.memref.size;
	}
}

static void teec_post_process_operation(TEEC_Operation *operation,
			struct teesmc_param *params,
			TEEC_SharedMemory *shms)
{
	size_t n;

	if (!operation)
		return;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t param_type;

		param_type = TEEC_PARAM_TYPE_GET(operation->paramTypes, n);
		switch (param_type) {
		case TEEC_VALUE_INPUT:
			break;
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:
			operation->params[n].value.a = params[n].u.value.a;
			operation->params[n].value.b = params[n].u.value.b;
			break;
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:
			teec_post_process_tmpref(param_type,
				&operation->params[n].tmpref, params + n,
				shms + n);
			break;
		case TEEC_MEMREF_WHOLE:
			teec_post_process_whole(&operation->params[n].memref,
						params + n);
			break;
		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:
			teec_post_process_partial(param_type,
				&operation->params[n].memref, params + n);
		default:
			break;
		}
	}
}

TEEC_Result TEEC_OpenSession(TEEC_Context *ctx, TEEC_Session *session,
			const TEEC_UUID *destination,
			uint32_t connection_method, const void *connection_data,
			TEEC_Operation *operation, uint32_t *ret_origin)
{
#define OPEN_SESSION_NUM_PARAMS	(TEEC_CONFIG_PAYLOAD_REF_COUNT + 1)
#define BUF_SIZE (sizeof(struct optee_cmd_prefix) + \
		  TEESMC_GET_ARG_SIZE(OPEN_SESSION_NUM_PARAMS))
	uint64_t buf[(BUF_SIZE + 1) / sizeof(uint64_t)] = { 0 };
	struct optee_cmd_prefix *cpfx;
	struct teesmc_arg *arg;
	struct teesmc_param *params;
	struct teesmc_meta_open_session *meta;
	TEEC_Result res;
	uint32_t eorig;
	TEEC_SharedMemory shm[OPEN_SESSION_NUM_PARAMS] = { };

	(void)&connection_data;

	if (!ctx || !session) {
		eorig = TEEC_ORIGIN_API;
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (connection_method != TEEC_LOGIN_PUBLIC) {
		eorig = TEEC_ORIGIN_API;
		res = TEEC_ERROR_NOT_SUPPORTED;
		goto out;
	}


	cpfx = (struct optee_cmd_prefix *)buf;
	arg = (struct teesmc_arg *)(uintptr_t)(cpfx + 1);
	arg->num_params = OPEN_SESSION_NUM_PARAMS;
	params = TEESMC_GET_PARAMS(arg);

	cpfx->smc_id = TEESMC32_CALL_WITH_ARG;
	arg->cmd = TEESMC_CMD_OPEN_SESSION;

	shm[0].size = sizeof(struct teesmc_meta_open_session);
	shm[0].flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(ctx, shm);
	if (res != TEEC_SUCCESS) {
		eorig = TEEC_ORIGIN_API;
		goto out;
	}

	meta = shm[0].buffer;
	memcpy(meta->uuid, destination, sizeof(TEEC_UUID));
	memset(meta->clnt_uuid, 0, sizeof(meta->clnt_uuid));
	meta->clnt_login = TEEC_LOGIN_PUBLIC;

	params[0].attr = TEESMC_ATTR_TYPE_MEMREF_INPUT | TEESMC_ATTR_META;
	params[0].u.memref.size = shm[0].size;
	params[0].u.memref.shm_ref = shm[0].fd;

	res = teec_pre_process_operation(ctx, operation, params + 1, shm + 1);
	if (res != TEEC_SUCCESS) {
		eorig = TEEC_ORIGIN_API;
		goto out;
	}

	if (teec_cmd(ctx->fd, buf, BUF_SIZE)) {
		eorig = TEEC_ORIGIN_COMMS;
		res = TEEC_ERROR_BAD_STATE;
		goto out;
	}
out:
	if (shm->buffer)
		TEEC_ReleaseSharedMemory(shm);
	if (res == TEEC_SUCCESS) {
		res = arg->ret;
		eorig = arg->ret_origin;
		if (res == TEEC_SUCCESS) {
			session->ctx = ctx;
			session->session_id = arg->session;
		}
	}
	teec_post_process_operation(operation, params + 1, shm + 1);

	if (ret_origin)
		*ret_origin = eorig;
	return res;
}

void TEEC_CloseSession(TEEC_Session *session)
{
	uint64_t buf[(sizeof(struct optee_cmd_prefix) +
		     sizeof(struct teesmc_arg)) / sizeof(uint64_t)] = { };
	struct optee_cmd_prefix *cpfx;
	struct teesmc_arg *arg;

	if (!session)
		return;

	cpfx = (struct optee_cmd_prefix *)buf;
	arg = (struct teesmc_arg *)(uintptr_t)(cpfx + 1);

	cpfx->smc_id = TEESMC32_CALL_WITH_ARG;
	arg->cmd = TEESMC_CMD_CLOSE_SESSION;
	arg->session = session->session_id;

	if (teec_cmd(session->ctx->fd, buf, sizeof(buf)))
		EMSG("Failed to close session 0x%x", session->session_id);
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t cmd_id,
			TEEC_Operation *operation, uint32_t *error_origin)
{
	uint64_t buf[(sizeof(struct optee_cmd_prefix) +
		      TEESMC_GET_ARG_SIZE(TEEC_CONFIG_PAYLOAD_REF_COUNT)) /
			sizeof(uint64_t)] = { };
	struct optee_cmd_prefix *cpfx;
	struct teesmc_arg *arg;
	struct teesmc_param *params;
	TEEC_Result res;
	uint32_t eorig;
	TEEC_SharedMemory shm[OPEN_SESSION_NUM_PARAMS] = { };

	if (!session) {
		eorig = TEEC_ORIGIN_API;
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	cpfx = (struct optee_cmd_prefix *)buf;
	arg = (struct teesmc_arg *)(uintptr_t)(cpfx + 1);
	arg->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;
	params = TEESMC_GET_PARAMS(arg);

	cpfx->smc_id = TEESMC32_CALL_WITH_ARG;
	arg->cmd = TEESMC_CMD_INVOKE_COMMAND;
	arg->session = session->session_id;
	arg->ta_func = cmd_id;

	if (operation) {
		teec_mutex_lock(&teec_mutex);
		operation->session = session;
		teec_mutex_unlock(&teec_mutex);
	}

	res = teec_pre_process_operation(session->ctx, operation, params, shm);
	if (res != TEEC_SUCCESS) {
		eorig = TEEC_ORIGIN_API;
		goto out;
	}

	if (teec_cmd(session->ctx->fd, buf, sizeof(buf))) {
		eorig = TEEC_ORIGIN_COMMS;
		res = TEEC_ERROR_BAD_STATE;
		goto out;
	}

out:
	if (res == TEEC_SUCCESS) {
		res = arg->ret;
		eorig = arg->ret_origin;
	}
	teec_post_process_operation(operation, params, shm);

	if (error_origin)
		*error_origin = eorig;
	return res;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	uint64_t buf[(sizeof(struct optee_cmd_prefix) +
		      sizeof(struct teesmc_arg)) / sizeof(uint64_t)] = { 0 };
	struct optee_cmd_prefix *cpfx;
	struct teesmc_arg *arg;
	TEEC_Session *session;

	if (!operation)
		return;

	teec_mutex_lock(&teec_mutex);
	session = operation->session;
	teec_mutex_unlock(&teec_mutex);

	if (!session)
		return;

	cpfx = (struct optee_cmd_prefix *)buf;
	arg = (struct teesmc_arg *)(uintptr_t)(cpfx + 1);

	cpfx->smc_id = TEESMC32_CALL_WITH_ARG;
	arg->cmd = TEESMC_CMD_CANCEL;
	arg->session = session->session_id;

	if (teec_cmd(session->ctx->fd, buf, sizeof(buf)))
		DMSG("teec_cmd: %s", strerror(errno));
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm)
{
	size_t s;

	if (!ctx || !shm)
		return TEEC_ERROR_BAD_PARAMETERS;

	s = shm->size;
	if (!s)
		s = 8;

	shm->fd = teec_shm_alloc(ctx->fd, s);
	if (shm->fd < 0)
		return TEEC_ERROR_OUT_OF_MEMORY;

	shm->shadow_buffer = mmap(NULL, s, PROT_READ | PROT_WRITE, MAP_SHARED,
				  shm->fd, 0);
	if (shm->shadow_buffer == (void *)MAP_FAILED) {
		close(shm->fd);
		shm->fd = -1;
		return TEEC_ERROR_OUT_OF_MEMORY;
	}
	shm->alloced_size = s;
	return TEEC_SUCCESS;
}


TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm)
{
	size_t s;

	if (!ctx || !shm)
		return TEEC_ERROR_BAD_PARAMETERS;

	s = shm->size;
	if (!s)
		s = 8;

	shm->fd = teec_shm_alloc(ctx->fd, s);
	if (shm->fd < 0)
		return TEEC_ERROR_OUT_OF_MEMORY;

	shm->buffer = mmap(NULL, s, PROT_READ | PROT_WRITE, MAP_SHARED,
			   shm->fd, 0);
	if (shm->buffer == (void *)MAP_FAILED) {
		close(shm->fd);
		shm->fd = -1;
		return TEEC_ERROR_OUT_OF_MEMORY;
	}
	shm->shadow_buffer = NULL;
	shm->alloced_size = s;
	return TEEC_SUCCESS;
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *shm)
{
	void *buf;

	if (!shm || shm->fd == -1)
		return;
	close(shm->fd);
	shm->fd = -1;

	if (shm->shadow_buffer)
		buf = shm->shadow_buffer;
	else
		buf = shm->buffer;
	munmap(buf, shm->alloced_size);

	shm->shadow_buffer = NULL;
	shm->buffer = NULL;
}
