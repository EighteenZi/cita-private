#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_exec_t {
	sgx_status_t ms_retval;
	uint8_t ms_opt;
	uint32_t ms_param;
	uint32_t* ms_res;
} ms_exec_t;

typedef struct ms_t_global_init_ecall_t {
	uint64_t ms_id;
	uint8_t* ms_path;
	size_t ms_len;
} ms_t_global_init_ecall_t;

typedef struct ms_u_stdin_ocall_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_nbytes;
} ms_u_stdin_ocall_t;

typedef struct ms_u_stdout_ocall_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_nbytes;
} ms_u_stdout_ocall_t;

typedef struct ms_u_stderr_ocall_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_nbytes;
} ms_u_stderr_ocall_t;

typedef struct ms_u_backtrace_open_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_pathname;
	int ms_flags;
} ms_u_backtrace_open_ocall_t;

typedef struct ms_u_backtrace_close_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_backtrace_close_ocall_t;

typedef struct ms_u_backtrace_fcntl_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_cmd;
	int ms_arg;
} ms_u_backtrace_fcntl_ocall_t;

typedef struct ms_u_backtrace_mmap_ocall_t {
	void* ms_retval;
	int* ms_error;
	void* ms_start;
	size_t ms_length;
	int ms_prot;
	int ms_flags;
	int ms_fd;
	int64_t ms_offset;
} ms_u_backtrace_mmap_ocall_t;

typedef struct ms_u_backtrace_munmap_ocall_t {
	int ms_retval;
	int* ms_error;
	void* ms_start;
	size_t ms_length;
} ms_u_backtrace_munmap_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_exec(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_exec_t));
	ms_exec_t* ms = SGX_CAST(ms_exec_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint32_t* _tmp_res = ms->ms_res;


	ms->ms_retval = exec(ms->ms_opt, ms->ms_param, _tmp_res);


	return status;
}

static sgx_status_t SGX_CDECL sgx_t_global_init_ecall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_global_init_ecall_t));
	ms_t_global_init_ecall_t* ms = SGX_CAST(ms_t_global_init_ecall_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_path = ms->ms_path;
	size_t _tmp_len = ms->ms_len;
	size_t _len_path = _tmp_len;
	uint8_t* _in_path = NULL;

	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);

	if (_tmp_path != NULL && _len_path != 0) {
		_in_path = (uint8_t*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_path, _tmp_path, _len_path);
	}
	t_global_init_ecall(ms->ms_id, (const uint8_t*)_in_path, _tmp_len);
err:
	if (_in_path) free((void*)_in_path);

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_global_exit_ecall(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	t_global_exit_ecall();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_exec, 0},
		{(void*)(uintptr_t)sgx_t_global_init_ecall, 0},
		{(void*)(uintptr_t)sgx_t_global_exit_ecall, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[13][3];
} g_dyn_entry_table = {
	13,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL u_stdin_ocall(size_t* retval, void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stdin_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stdin_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stdin_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stdin_ocall_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memset(ms->ms_buf, 0, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(0, ms);

	if (retval) *retval = ms->ms_retval;
	if (buf) memcpy((void*)buf, ms->ms_buf, _len_buf);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stdout_ocall(size_t* retval, const void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stdout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stdout_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stdout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stdout_ocall_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stderr_ocall(size_t* retval, const void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stderr_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stderr_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stderr_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stderr_ocall_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buf);
		memcpy((void*)ms->ms_buf, buf, _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_open_ocall(int* retval, int* error, const char* pathname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_backtrace_open_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_open_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_open_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_open_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_error);
		memset(ms->ms_error, 0, _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		memcpy((void*)ms->ms_pathname, pathname, _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;
	if (error) memcpy((void*)error, ms->ms_error, _len_error);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_close_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_backtrace_close_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_close_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_close_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_close_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_error);
		memset(ms->ms_error, 0, _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;
	if (error) memcpy((void*)error, ms->ms_error, _len_error);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_fcntl_ocall(int* retval, int* error, int fd, int cmd, int arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_backtrace_fcntl_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_fcntl_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_fcntl_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_fcntl_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_error);
		memset(ms->ms_error, 0, _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	ms->ms_arg = arg;
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;
	if (error) memcpy((void*)error, ms->ms_error, _len_error);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_mmap_ocall(void** retval, int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_backtrace_mmap_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_mmap_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_mmap_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_mmap_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_error);
		memset(ms->ms_error, 0, _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_start = SGX_CAST(void*, start);
	ms->ms_length = length;
	ms->ms_prot = prot;
	ms->ms_flags = flags;
	ms->ms_fd = fd;
	ms->ms_offset = offset;
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;
	if (error) memcpy((void*)error, ms->ms_error, _len_error);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_munmap_ocall(int* retval, int* error, void* start, size_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_backtrace_munmap_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_munmap_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_munmap_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_munmap_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_error);
		memset(ms->ms_error, 0, _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_start = SGX_CAST(void*, start);
	ms->ms_length = length;
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;
	if (error) memcpy((void*)error, ms->ms_error, _len_error);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memset(ms->ms_cpuinfo, 0, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(8, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(11, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(12, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

