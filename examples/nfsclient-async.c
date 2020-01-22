/* 
   Copyright (C) by Ronnie Sahlberg <ronniesahlberg@gmail.com> 2010
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

/* Example program using the highlevel async interface.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <win32/win32_compat.h>
#pragma comment(lib, "ws2_32.lib")
WSADATA wsaData;
#else
#include <sys/stat.h>
#endif
 
#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define SERVER "localhost"
#define EXPORT "/mnt/sharedfolder/"
#define NFSFILE "/BOOKS/Classics/Dracula.djvu"
#define NFSDIR "/BOOKS/Classics/"

#if 0
#define DEBUG_PRINT(...) \
	fprintf(stderr, __VA_ARGS__)

#else 
#define DEBUG_PRINT(...) 
#endif

#define FAIL(...) { \
	fprintf(stderr, __VA_ARGS__); \
	exit(1); \
}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <execinfo.h>
#include <stdio.h>
#include "libnfs.h"
#include "libnfs-raw.h"
#include "libnfs-raw-mount.h"
#define TARAS_DISABLE_OS_LINUX 1
#include "fio.h"
#include "optgroup.h"
struct rpc_context *mount_context;

struct client {
       char *server;
       char *export;
       uint32_t mount_port;
       struct nfsfh *nfsfh;
};

enum nfs_op_type {
	NFS_READ_WRITE = 0,
	NFS_STAT_MKDIR_RMDIR,
};

/*
 * The io engine can define its own options within the io engine source.
 * The option member must not be at offset 0, due to the way fio parses
 * the given option. Just add a padding pointer unless the io engine has
 * something usable.
 */
struct fio_skeleton_options {
	struct nfsfh *nfsfh;
	struct nfs_context *context;	
	char *nfs_server;
	enum nfs_op_type op_type;
	int (*read)(struct fio_skeleton_options *o, struct io_u *io_u);
	int (*write)(struct fio_skeleton_options *o, struct io_u *io_u);
	int (*trim)(struct fio_skeleton_options *o, struct io_u *io_u);
	int outstanding_events; // IOs issued to libnfs, that have not returned yet
	int prev_requested_event_index; // event last returned via fio_skeleton_event
	int next_buffered_event; // round robin-pointer within events[] 
	int buffered_event_count; // IOs completed by libnfs faiting for FIO
	int free_event_buffer_index; // next empty buffer
	unsigned int queue_depth; // nfs_callback needs this info, but doesn't have fio td structure to pull it from
	struct io_u* events[0];
};

static int str_server_cb(void *data, const char *input);

static struct fio_option options[] = {
	{
		.name     = "nfs_server",
		.lname    = "nfs_server",
		.type     = FIO_OPT_STR_STORE,
		.help	= "NFS server hostname",
		.off1     = offsetof(struct fio_skeleton_options, nfs_server),
		.def	  = "localhost",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "hostname",
		.lname	= "net engine hostname",
		.type	= FIO_OPT_STR_STORE,
		.cb	= str_server_cb,
		.help	= "Hostname for net IO engine",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name     = NULL,
	},
};


/*
 * The ->event() hook is called to match an event number with an io_u.
 * After the core has called ->getevents() and it has returned eg 3,
 * the ->event() hook must return the 3 events that have completed for
 * subsequent calls to ->event() with [0-2]. Required.
 */
static struct io_u *fio_skeleton_event(struct thread_data *td, int event)
{
	DEBUG_PRINT("fio_skeleton_event %d\n", event);
	struct fio_skeleton_options *o = td->eo;
	struct io_u *io_u = o->events[o->next_buffered_event];
	assert(o->events[o->next_buffered_event]);
	o->events[o->next_buffered_event] = NULL;
	o->next_buffered_event = (o->next_buffered_event + 1) % td->o.iodepth;
	// validate our state machine
	assert(o->buffered_event_count);
	o->buffered_event_count--;
	assert(io_u);
	// we need to assert that fio_skeleton_event is being called in sequential fashion
	DEBUG_PRINT("before o->prev_requested_event_index:%d event:%d\n", o->prev_requested_event_index, event);
	assert(event == 0 || o->prev_requested_event_index + 1 == event);
	if (o->buffered_event_count == 0) {
		o->prev_requested_event_index = -1;
	} else {
		o->prev_requested_event_index = event;
	}
	DEBUG_PRINT("after o->prev_requested_event_index:%d event:%d\n", o->prev_requested_event_index, event);

	return io_u;
}

static int nfs_event_loop(struct thread_data *td, bool flush) {
	struct fio_skeleton_options *o = td->eo;
	DEBUG_PRINT("+nfs_event_loop o->buffered_event_count:%d\n", o->buffered_event_count);
	// we already have stuff queued for fio, no need to waste cpu on poll()
	if (o->buffered_event_count) {
		DEBUG_PRINT("why bother me?\n");
		return o->buffered_event_count;
	}
	
	struct pollfd pfds[1]; /* nfs:0 */

#define SHOULD_WAIT() (o->outstanding_events == td->o.iodepth || (flush && o->outstanding_events))
	
	do {
		int timeout = SHOULD_WAIT() ? -1 : 0;
		pfds[0].fd = nfs_get_fd(o->context);
		pfds[0].events = nfs_which_events(o->context);
		int ret = poll(&pfds[0], 1, timeout);
		DEBUG_PRINT("poll(timeout=%d)=%d full=%d outstanding=%d flush=%d\n",
			timeout, ret, o->outstanding_events == td->o.iodepth,  o->outstanding_events, flush);
		if (ret < 0) {
			FAIL("Poll failed");
		}

		if (nfs_service(o->context, pfds[0].revents) < 0) {
			FAIL("nfs_service failed\n");
		}
	} while (SHOULD_WAIT());
	DEBUG_PRINT("-nfs_event_loop %d\n", o->buffered_event_count);
	// my_backtrace();
	return o->buffered_event_count;
}
#undef SHOULD_WAIT
/*
 * The ->getevents() hook is used to reap completion events from an async
 * io engine. It returns the number of completed events since the last call,
 * which may then be retrieved by calling the ->event() hook with the event
 * numbers. Required.
 */
static int fio_skeleton_getevents(struct thread_data *td, unsigned int min,
				  unsigned int max, const struct timespec *t)
{
	return nfs_event_loop(td, false);
}

/*
 * The ->cancel() hook attempts to cancel the io_u. Only relevant for
 * async io engines, and need not be supported.
 */
static int fio_skeleton_cancel(struct thread_data *td, struct io_u *io_u)
{
	DEBUG_PRINT("fio_skeleton_cancel\n");
	
	return 0;
}

static void nfs_callback(int res, struct nfs_context *nfs, void *data,
                       void *private_data)
{
	struct io_u *io_u = private_data;
	struct fio_skeleton_options *o = io_u->file->engine_data;
	DEBUG_PRINT("nfs_cb@%llu=%d io_u=%p\n", io_u->offset, res, io_u);
	if (res < 0) {
		FAIL("Failed NFS operation: %s\n", nfs_get_error(o->context));
	}
	if (io_u->ddir == DDIR_READ && o->op_type == NFS_READ_WRITE) {
		memcpy(io_u->buf, data, res);
		if (res == 0) {
			FAIL("Got EOF, this is probably not expected\n");
		}
	}
	// I guess fio uses resid to track remaining data
	io_u->resid =  o->op_type == NFS_READ_WRITE ? (io_u->xfer_buflen - res) : 0;

	assert(!o->events[o->free_event_buffer_index]);
	o->events[o->free_event_buffer_index] = io_u;
	o->free_event_buffer_index = (o->free_event_buffer_index + 1) % o->queue_depth;
	o->outstanding_events--;
	o->buffered_event_count++;
}

static int queue_write(struct fio_skeleton_options *o, struct io_u *io_u) {
	return nfs_pwrite_async(o->context, o->nfsfh,
                           io_u->offset, io_u->buflen, io_u->buf, nfs_callback,
                           io_u);
}

static int queue_read(struct fio_skeleton_options *o, struct io_u *io_u) {
	return nfs_pread_async(o->context, o->nfsfh, io_u->offset, io_u->buflen, nfs_callback,  io_u);
}

// todo: reverse numbers to improve name distribution
#define NFS_FILENAME(io_u, buf) \
	char buf[256]; \
	sprintf(buf, "%s/%llx", io_u->file->file_name, io_u->offset);

static int queue_stat(struct fio_skeleton_options *o, struct io_u *io_u) {
	NFS_FILENAME(io_u, buf)
	return nfs_stat64_async(o->context, buf, nfs_callback, io_u);
}

static int queue_mkdir(struct fio_skeleton_options *o, struct io_u *io_u) {
	NFS_FILENAME(io_u, buf)
	return nfs_mkdir_async(o->context, buf, nfs_callback, io_u);
}

static int queue_rmdir(struct fio_skeleton_options *o, struct io_u *io_u) {
	NFS_FILENAME(io_u, buf)
	return nfs_rmdir_async(o->context, buf, nfs_callback, io_u);
}

#undef NFS_FILENAME
/*
 * The ->queue() hook is responsible for initiating io on the io_u
 * being passed in. If the io engine is a synchronous one, io may complete
 * before ->queue() returns. Required.
 *
 * The io engine must transfer in the direction noted by io_u->ddir
 * to the buffer pointed to by io_u->xfer_buf for as many bytes as
 * io_u->xfer_buflen. Residual data count may be set in io_u->resid
 * for a short read/write.
 */
static enum fio_q_status fio_skeleton_queue(struct thread_data *td,
					    struct io_u *io_u)
{
	struct nfs_context *nfs = (struct nfs_context *)io_u->file->engine_data;
	struct fio_skeleton_options *o = td->eo;
	int err;
	DEBUG_PRINT("fio_skeleton_queue %s @%llu size:%llu\n",
		(io_u->ddir == DDIR_READ ? "read" : "write"),
		io_u->offset, io_u->buflen);

	switch(io_u->ddir) {
		case DDIR_WRITE:
			err = o->write(o, io_u);
			break;
		case DDIR_READ:
			err = o->read(o, io_u);
			break;
		case DDIR_TRIM:
			err = o->trim(o, io_u);
			break;
		default:
			FAIL("fio_skeleton_queue unhandled io %d\n", io_u->ddir);
	}
	if (err) {
		FAIL("Failed to queue nfs op: %s\n", nfs_get_error(nfs));
		td->error = 1;
		return FIO_Q_COMPLETED;
	}
	o->outstanding_events++;

	/*
	 * Double sanity check to catch errant write on a readonly setup
	 */
	// fio_ro_check(td, io_u);

	// td->error = 0;
	/*
	 * Could return FIO_Q_QUEUED for a queued request,
	 * FIO_Q_COMPLETED for a completed request, and f
	 * if we could queue no more at this point (you'd have to
	 * define ->commit() to handle that.
	 */
	return FIO_Q_QUEUED;
}

/*
 * The ->prep() function is called for each io_u prior to being submitted
 * with ->queue(). This hook allows the io engine to perform any
 * preparatory actions on the io_u, before being submitted. Not required.
 */
// static int fio_skeleton_prep(struct thread_data *td, struct io_u *io_u)
// {
// 	DEBUG_PRINT("fio_skeleton_prep\n");
// 	return 0;
// }

/*
 * The init function is called once per thread/process, and should set up
 * any structures that this io engine requires to keep track of io. Not
 * required.
 */
// static int fio_skeleton_init(struct thread_data *td)
// {
// 	DEBUG_PRINT("fio_skeleton_init %p\n", td->eo);
// 	return 0;
// }

/*
 * The init function is called once per thread/process, and should set up
 * any structures that this io engine requires to keep track of io. Not
 * required.
 */
static int fio_skeleton_setup(struct thread_data *td)
{

	DEBUG_PRINT("fio_skeleton_setup td=%p eo=%p \n", td, td->eo);
	td->o.use_thread = 0;
	return 0;
}
/*
 * This is paired with the ->init() function and is called when a thread is
 * done doing io. Should tear down anything setup by the ->init() function.
 * Not required.
 */
// static void fio_skeleton_cleanup(struct thread_data *td)
// {
// 	DEBUG_PRINT("fio_skeleton_cleanup\n");
// }

/*
 * Hook for opening the given file. Unless the engine has special
 * needs, it usually just provides generic_open_file() as the handler.
 */
static int fio_skeleton_open(struct thread_data *td, struct fio_file *f)
{
	int ret;
	struct client client;
	DEBUG_PRINT("fio_skeleton_open(%s) eo=%p td->o.iodepth=%d\n", f->file_name,
		td->eo, td->o.iodepth);
	struct nfs_context *nfs;

	client.server = getenv("NFS_SERVER");
	client.export = getenv("NFS_EXPORT");
	if (!client.server || !client.export) {
		FAIL("Must set env vars: NFS_SERVER, NFS_EXPORT\n");
	}

	unsigned long option_size = sizeof(struct fio_skeleton_options) + sizeof(struct io_u **) * td->o.iodepth;
	struct fio_skeleton_options *options = malloc(option_size);
	memset(options, 0, option_size);
	options->prev_requested_event_index = -1;
	options->queue_depth = td->o.iodepth;

	options->context = nfs = nfs_init_context();
	if (nfs == NULL) {
		FAIL("failed to init nfs context\n");
	}

	ret = nfs_mount(nfs, client.server, client.export);
	DEBUG_PRINT("nfsmount(%s, %s)\n",  client.server, client.export);
	if (ret != 0) {
		FAIL("Failed to start async nfs mount\n");
	}
	if (strstr(f->file_name, "stat_mkdir_rmdir")) {
		// TODO move these to subdir
		options->read = queue_stat;
		options->write = queue_mkdir;
		options->trim = queue_rmdir;
		options->op_type = NFS_STAT_MKDIR_RMDIR;
		ret = nfs_mkdir(nfs, f->file_name);
		if (ret != 0) {
			FAIL("Failed to mkdir: %s\n", nfs_get_error(nfs));
		}
	} else {
		ret = nfs_open(nfs, f->file_name, O_CREAT | O_WRONLY | O_TRUNC, &options->nfsfh);
		if (ret != 0) {
			FAIL("Failed to open nfs file: %s\n", nfs_get_error(nfs));
		}
		options->read = queue_read;
		options->write = queue_write;
		options->op_type = NFS_READ_WRITE;
	}
	f->fd = nfs_get_fd(nfs);
	f->engine_data = options;
	td->eo = options;
	return ret;
}

/*
 * Hook for doing so. See fio_skeleton_open().
 */
static int fio_skeleton_close(struct thread_data *td, struct fio_file *f)
{
	DEBUG_PRINT("fio_skeleton_close\n");
	struct fio_skeleton_options *o = td->eo;
	int ret = 0;
	if (o->nfsfh) {
		ret = nfs_close(o->context, o->nfsfh);
		ret = generic_close_file(td, f);
	}
	nfs_umount(o->context);
	nfs_destroy_context(o->context);
	free(o);
	td->eo = NULL;
	f->fd = -1;
	return ret;
}

static int fio_skeleton_init(struct thread_data *td) {
	DEBUG_PRINT("fio_skeleton_init td->eo:%p\n", td->eo);
	return 0;
}

/*
 * Hook for writing out outstanding data.
 */
static int fio_skeleton_commit(struct thread_data *td) {
	DEBUG_PRINT("fio_skeleton_commit\n");
	nfs_event_loop(td, true);
	return 0;
}

/*
 * Note that the structure is exported, so that fio can get it via
 * dlsym(..., "ioengine"); for (and only for) external engines.
 */
struct ioengine_ops ioengine = {
	.name		= "external",
	.version	= FIO_IOOPS_VERSION,
	.setup		= fio_skeleton_setup,
	.init		= fio_skeleton_init,
	// .prep		= fio_skeleton_prep,
	.queue		= fio_skeleton_queue,
	.cancel		= fio_skeleton_cancel,
	.getevents	= fio_skeleton_getevents,
	.event		= fio_skeleton_event,
	// .cleanup	= fio_skeleton_cleanup,
	.open_file	= fio_skeleton_open,
	.close_file	= fio_skeleton_close,
	.commit     = fio_skeleton_commit,
	.flags      = FIO_DISKLESSIO | FIO_NOEXTEND | FIO_NODISKUTIL,
	.options	= options,
	.option_struct_size	= sizeof(struct fio_skeleton_options),
};

// ioengine=ioengine=external:./nfsclient-async

static int str_server_cb(void *data, const char *input)
{
	struct fio_skeleton_options *o = data;
	o->nfs_server = strdup(input);
	DEBUG_PRINT("str_server_cb %s %p\n", input, o);
	return 0;
}
