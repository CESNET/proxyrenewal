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

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <glite/security/proxyrenewal/renewal_core.h>

static struct option const long_options[] = {
   { "server",   required_argument, 0, 's' },
   { "proxy",    required_argument, 0, 'p' },
   { "help",     no_argument,       0, 'h' },
   { NULL, 0, NULL, 0}
};

static char short_options[] = "s:p:h";

int
main(int argc, char *argv[])
{
   char *server = NULL;
   char *proxy = NULL;
   char *new_proxy = NULL;
   extern int optind;
   char arg;
   glite_renewal_core_context ctx = NULL;
   int ret;

   while ((arg = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF) {
      switch(arg) {
	case 's':
	   server = optarg; break;
	case 'p':
	   proxy = optarg; break;
	case 'h':
	   fprintf(stdout, "Usage: %s --server <myproxy server> --proxy <filename>\n", argv[0]);
	   exit(1);
      }
   }

   if (server == NULL || proxy == NULL) {
      fprintf(stderr, "both server and proxy parameters must be given\n");
      exit(1);
   }

   ret = glite_renewal_core_init_ctx(&ctx);
   if (ret) {
      fprintf(stderr, "glite_renewal_core_init_ctx() failed\n");
      exit(1);
   }

   ctx->log_dst = GLITE_RENEWAL_LOG_NONE;

   ret = glite_renewal_core_renew(ctx, server, 0, proxy, &new_proxy);
   if (ret) {
      fprintf(stderr, "%s: glite_renewal_core_renew() failed: %s",
              argv[0], ctx->err_message);
      exit(1);
   }

   ret = glite_renewal_core_destroy_ctx(ctx);

   printf("%s\n", new_proxy);

   return 0;
}
