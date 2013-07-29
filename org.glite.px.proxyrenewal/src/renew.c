/*
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright
 * holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "renewal_locl.h"
#include "renewd_locl.h"

#include "voms/voms_apic.h"

#ident "$Header$"

#define RENEWAL_COUNTS_MAX	1000	/* the slave daemon exits after that many attemtps */

extern char *repository;
extern char *cadir;
extern char *vomsdir;
extern int voms_enabled;
static int received_signal = -1, die = 0;

static void
check_renewal(glite_renewal_core_context ctx, char *datafile, int force_renew, int *num_renewed);

static int
renew_proxy(glite_renewal_core_context ctx, proxy_record *record, char *basename, char **new_proxy);

static void
register_signal(int signal);

static void
register_signal(int signal)
{
      received_signal = signal;
      switch ((received_signal = signal)) {
	 case SIGINT:
	 case SIGTERM:
	 case SIGQUIT:
	    die = signal;
	    break;
	 default:
	    break;
      }
}

static int
renew_proxy(glite_renewal_core_context ctx, proxy_record *record, char *basename, char **new_proxy)
{
   char repository_file[FILENAME_MAX];
   int ret = -1;
   char *p = NULL;
   char *server = NULL;
   unsigned int port = 0;

   snprintf(repository_file, sizeof(repository_file),"%s.%d",
	    basename, record->suffix);

   if (record->myproxy_server)
      server = strdup(record->myproxy_server);

   if (server && (p = strchr(server, ':'))) {
      *p++ = '\0';
      ret = edg_wlpr_DecodeInt(p, &port);
   }

   ret = glite_renewal_core_renew(ctx, server, port, repository_file, new_proxy);
   if (ret) {
      edg_wlpr_Log(ctx, LOG_ERR, "Failed to renew proxy %s: %s",
                   repository_file,
                   glite_renewal_core_get_err(ctx));
      goto end;
   }

   edg_wlpr_Log(ctx, LOG_DEBUG, "Proxy %s succesfully renewed", repository_file);
   ret = 0;

end:
   if (server)
      free(server);

   return ret;
}

static void
check_renewal(glite_renewal_core_context ctx, char *datafile, int force_renew, int *num_renewed)
{
   proxy_record record;
   char *p;
   int ret, i;
   time_t current_time;
   FILE *meta_fd = NULL;
   char basename[FILENAME_MAX];
   edg_wlpr_Request request;
   edg_wlpr_Response response;
   char *new_proxy = NULL;
   char *entry = NULL;
   char **tmp;
   int num = 0;
   char *line = ctx->buffer;

   assert(datafile != NULL);

   *num_renewed = 0;

   memset(&record, 0, sizeof(record));
   memset(basename, 0, sizeof(basename));
   memset(&request, 0, sizeof(request));
   memset(&response, 0, sizeof(response));
   
   strncpy(basename, datafile, sizeof(basename) - 1);
   p = basename + strlen(basename) - strlen(".data");
   if (strcmp(p, ".data") != 0) {
      edg_wlpr_Log(ctx, LOG_ERR, "Meta filename doesn't end with '.data'");
      return;
   }
   *p = '\0';

   request.command = EDG_WLPR_COMMAND_UPDATE_DB;
   request.proxy_filename = strdup(basename);

   meta_fd = fopen(datafile, "r");
   if (meta_fd == NULL) {
      edg_wlpr_Log(ctx, LOG_ERR, "Cannot open meta file %s (%s)",
	           datafile, strerror(errno));
      return;
   }

   current_time = time(NULL);

   while (fgets(line, ctx->bufsize, meta_fd) != NULL) {
      glite_renewal_core_reset_err(ctx);
      free_record(ctx, &record);
      p = strchr(line, '\n');
      if (p)
	 *p = '\0';
      ret = decode_record(ctx, basename, line, &record);
      if (ret)
	 continue; /* XXX exit? */
      if (record.jobids.len == 0) /* no jobid registered for this proxy */
	 continue;
      if (current_time + RENEWAL_CLOCK_SKEW >= record.end_time ||
	  record.next_renewal <= current_time ||
	  force_renew) {
	 ret = EDG_WLPR_PROXY_EXPIRED;
	 if ( record.end_time + RENEWAL_CLOCK_SKEW >= current_time) {
	    /* only try renewal if the proxy hasn't already expired */
	    ret = renew_proxy(ctx, &record, basename, &new_proxy);
         }

	 /* if the proxy wasn't renewed have the daemon planned another renewal */
	 asprintf(&entry, "%d:%s", record.suffix, (ret == 0) ? new_proxy : "");
	 if (new_proxy) {
	    free(new_proxy); new_proxy = NULL;
	 }

	 tmp = realloc(request.entries, (num + 2) * sizeof(*tmp));
	 if (tmp == NULL) {
	    free_record(ctx, &record);
	    return;
	 }
	 request.entries = tmp;
	 request.entries[num] = entry;
	 request.entries[num+1] = NULL;
	 num++;
      }
   }
   free_record(ctx, &record);

   if (num > 0) {
      ret = edg_wlpr_RequestSend(&request, &response);
      if (ret != 0)
	 edg_wlpr_Log(ctx, LOG_ERR,
	              "Failed to send update request to master (%d)", ret);
      else if (response.response_code != 0)
	 edg_wlpr_Log(ctx, LOG_ERR,
	              "Master failed to update database (%d)", response.response_code);

      /* delete all tmp proxy files which may survive */
      for (i = 0; i < num; i++) {
	 p = strchr(request.entries[i], ':');
	 if (p+1)
	    unlink(p+1);
      }
   }
   fclose(meta_fd);

   edg_wlpr_CleanResponse(&response);
   edg_wlpr_CleanRequest(&request);

   *num_renewed = num;

   return;
}

int renewal(glite_renewal_core_context ctx, int force_renew, int *num_renewed)
{
   DIR *dir = NULL;
   struct dirent *file;
   FILE *fd;
   int num = 0;

   *num_renewed = 0;

   if (chdir(repository)) {
      edg_wlpr_Log(ctx, LOG_ERR, "Cannot access repository directory %s (%s)",
	           repository, strerror(errno));
      return errno;
   }

   dir = opendir(repository);
   if (dir == NULL) {
      edg_wlpr_Log(ctx, LOG_ERR, "Cannot open repository directory %s (%s)",
	           repository, strerror(errno));
      return errno;
   }

   while ((file = readdir(dir))) {
      /* read files of format `md5sum`.data, where md5sum() is of fixed length
	 32 chars */
      if (file->d_name == NULL || strlen(file->d_name) != 37 ||
	  strcmp(file->d_name + 32, ".data") != 0)
	 continue;
      fd = fopen(file->d_name, "r");
      if (fd == NULL) {
	 edg_wlpr_Log(ctx, LOG_ERR, "Cannot open meta file %s (%s)",
	              file->d_name, strerror(errno));
	 continue;
      }
      check_renewal(ctx, file->d_name, force_renew, &num);
      *num_renewed += num;
      fclose(fd);
   }
   closedir(dir);
   edg_wlpr_Log(ctx, LOG_DEBUG,
                "Renewal attempt finished, %u attempts performed", *num_renewed);
   return 0;
}

void
watchdog_start(glite_renewal_core_context ctx)
{
   struct sigaction sa;
   int force_renewal;
   int count = 0, num;
   sigset_t mask;
   
   memset(&sa,0,sizeof(sa));
   sa.sa_handler = register_signal;
   sigaction(SIGUSR1, &sa, NULL);
   sigaction(SIGINT,&sa,NULL);
   sigaction(SIGQUIT,&sa,NULL);
   sigaction(SIGTERM,&sa,NULL);
   sigaction(SIGPIPE,&sa,NULL);

   sigemptyset(&mask);
   sigaddset(&mask, SIGUSR1);
   sigaddset(&mask, SIGINT);
   sigaddset(&mask, SIGQUIT);
   sigaddset(&mask, SIGTERM);
   sigaddset(&mask, SIGPIPE);
   sigprocmask(SIG_UNBLOCK, &mask, NULL);

   while (count < RENEWAL_COUNTS_MAX && !die) {
       received_signal = -1;
       sleep(60 * 5);
       force_renewal = (received_signal == SIGUSR1) ? 1 : 0;
       if (die)
	  break;
       /* XXX uninstall signal handler ? */
       renewal(ctx, force_renewal, &num);
       count += num;
   }
   edg_wlpr_Log(ctx, LOG_NOTICE, "Terminating after %d renewal attempts", count);
   exit(0);
}
