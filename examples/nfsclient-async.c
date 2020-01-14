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
       int is_finished;
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
	int event_count;
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
	fprintf(stderr, "fio_skeleton_event %d\n", event);
	struct fio_skeleton_options *o = td->eo;
	struct io_u *io_u = o->events[event];
	return io_u;
}

void my_backtrace() {
     void* callstack[128];
     int i, frames = backtrace(callstack, 128);
     char** strs = backtrace_symbols(callstack, frames);
     for (i = 0; i < frames; ++i) {
         printf("%s\n", strs[i]);
     }
     free(strs);
}
/*
 * The ->getevents() hook is used to reap completion events from an async
 * io engine. It returns the number of completed events since the last call,
 * which may then be retrieved by calling the ->event() hook with the event
 * numbers. Required.
 */
static int fio_skeleton_getevents(struct thread_data *td, unsigned int min,
				  unsigned int max, const struct timespec *t)
{
	fprintf(stderr, "+fio_skeleton_getevents\n");
	struct fio_skeleton_options *o = td->eo;

	int num_fds;
	struct pollfd pfds[1]; /* nfs:0 */

	pfds[0].fd = nfs_get_fd(o->context);
	pfds[0].events = nfs_which_events(o->context);
	num_fds = 1;
	
	// count events within callback
	o->event_count = 0;
	while (o->event_count < td->o.iodepth) {
		int ret = poll(&pfds[0], 1, -1);
		fprintf(stderr, "poll=%d\n", ret);
		if (ret < 0) {
			printf("Poll failed");
			exit(10);
		}

		if (nfs_service(o->context, pfds[0].revents) < 0) {
			printf("nfs_service failed\n");
			return 0;
		}
	}
	fprintf(stderr, "-fio_skeleton_getevents %d\n", o->event_count);
	// my_backtrace();
	return o->event_count;
}

/*
 * The ->cancel() hook attempts to cancel the io_u. Only relevant for
 * async io engines, and need not be supported.
 */
static int fio_skeleton_cancel(struct thread_data *td, struct io_u *io_u)
{
	fprintf(stderr, "fio_skeleton_cancel\n");
	
	return 0;
}

static void nfs_callback(int ret, struct nfs_context *nfs, void *data,
                       void *private_data)
{
	fprintf(stderr, "nfs_cb %d\n", ret);
	struct io_u *io_u = private_data;
	struct fio_skeleton_options *o = io_u->file->engine_data;
	if (ret < 0) {
		fprintf(stderr, "Failed to write to nfs file: %s\n", nfs_get_error(o->context));
		return;
	}
	io_u->resid = io_u->xfer_buflen - ret;
	o->events[o->event_count++] = io_u;
}
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
	
	// io_u->engine_data = o;
	switch(io_u->ddir) {
		case DDIR_WRITE:
			fprintf(stderr, "fio_skeleton_queue %d @%llu size:%llu\n", io_u->ddir, io_u->offset, io_u->buflen);
			int err = nfs_pwrite_async(o->context, o->nfsfh,
                           io_u->offset, io_u->buflen, io_u->buf, nfs_callback,
                           io_u);
			if (err) {
				printf("Failed to write to nfs file: %s\n", nfs_get_error(nfs));
				td->error = 1;
				return FIO_Q_COMPLETED;
			}
			o->events[0] = io_u; 
		break;
		default:
			fprintf(stderr,  "fio_skeleton_queue unhandled io\n");
			assert(false);
	}
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
// 	fprintf(stderr, "fio_skeleton_prep\n");
// 	return 0;
// }

/*
 * The init function is called once per thread/process, and should set up
 * any structures that this io engine requires to keep track of io. Not
 * required.
 */
// static int fio_skeleton_init(struct thread_data *td)
// {
// 	fprintf(stderr, "fio_skeleton_init %p\n", td->eo);
// 	return 0;
// }

/*
 * The init function is called once per thread/process, and should set up
 * any structures that this io engine requires to keep track of io. Not
 * required.
 */
static int fio_skeleton_setup(struct thread_data *td)
{

	fprintf(stderr, "fio_skeleton_setup td=%p eo=%p \n", td, td->eo);
	td->o.use_thread = 1;
	return 0;
}
/*
 * This is paired with the ->init() function and is called when a thread is
 * done doing io. Should tear down anything setup by the ->init() function.
 * Not required.
 */
// static void fio_skeleton_cleanup(struct thread_data *td)
// {
// 	fprintf(stderr, "fio_skeleton_cleanup\n");
// }

/*
 * Hook for opening the given file. Unless the engine has special
 * needs, it usually just provides generic_open_file() as the handler.
 */
static int fio_skeleton_open(struct thread_data *td, struct fio_file *f)
{
	int ret;
	struct client client;
	fprintf(stderr, "fio_skeleton_open eo=%p td->o.iodepth=%d\n", td->eo, td->o.iodepth);
	struct fio_skeleton_options *o = td->eo;
	struct nfs_context *nfs;

	client.server = SERVER;
	client.export = EXPORT;
	client.is_finished = 0;

	unsigned long option_size = sizeof(struct fio_skeleton_options) + sizeof(struct io_u **) * td->o.iodepth;
	struct fio_skeleton_options *options = malloc(option_size);
	memset(options, 0, option_size);

	options->context = nfs = nfs_init_context();
	if (nfs == NULL) {
		printf("failed to init nfs context\n");
		return -1;
	}

	ret = nfs_mount(nfs, client.server, client.export);
	fprintf(stderr, "nfsmount(%s, %s)\n",  client.server, client.export);
	if (ret != 0) {
		printf("Failed to start async nfs mount\n");
		return -1;
	}
	ret = nfs_open(nfs, f->file_name, O_CREAT | O_WRONLY | O_TRUNC, &options->nfsfh);
	if (ret != 0) {
		printf("Failed to open nfs file: %s\n", nfs_get_error(nfs));
		return -1;
	}

	f->fd = nfs_get_fd(nfs);
	f->engine_data = options;
	assert(!td->eo && "Some bug in fio causing ->eo member to be passed in as null");
	td->eo = options;
	return ret;
}

/*
 * Hook for writing out outstanding data.
 */
// static int fio_skeleton_commit(struct thread_data *td, struct fio_file *f)
// {
// 	fprintf(stderr, "fio_skeleton_commit\n");
// 	return 0; //generic_close_file(td, f);
// }

/*
 * Hook for doing so. See fio_skeleton_open().
 */
static int fio_skeleton_close(struct thread_data *td, struct fio_file *f)
{
	fprintf(stderr, "fio_skeleton_close\n");
	struct fio_skeleton_options *o = td->eo;
	nfs_close(o->context, o->nfsfh);
	nfs_umount(o->context);
	nfs_destroy_context(o->context);
	free(o);
	td->eo = NULL;
	return generic_close_file(td, f);
}
/*
 * Note that the structure is exported, so that fio can get it via
 * dlsym(..., "ioengine"); for (and only for) external engines.
 */
struct ioengine_ops ioengine = {
	.name		= "external",
	.version	= FIO_IOOPS_VERSION,
	.setup		= fio_skeleton_setup,
	// .init		= fio_skeleton_init,
	// .prep		= fio_skeleton_prep,
	.queue		= fio_skeleton_queue,
	.cancel		= fio_skeleton_cancel,
	.getevents	= fio_skeleton_getevents,
	.event		= fio_skeleton_event,
	// .cleanup	= fio_skeleton_cleanup,
	.open_file	= fio_skeleton_open,
	.close_file	= fio_skeleton_close,
	// .commit     = fio_skeleton_commit,
	.flags      = FIO_DISKLESSIO | FIO_NOEXTEND | FIO_NODISKUTIL,
	.options	= options,
	.option_struct_size	= sizeof(struct fio_skeleton_options),
};

// ioengine=ioengine=external:./nfsclient-async

static int str_server_cb(void *data, const char *input)
{
	struct fio_skeleton_options *o = data;
	o->nfs_server = strdup(input);
	fprintf(stderr, "str_server_cb %s %p\n", input, o);
	return 0;
}