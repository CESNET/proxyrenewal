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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "renewal.h"

static const char rcsid[] = "$Header$";

static struct option const long_options[] = {
   { "help",     no_argument,       0, 'h' },
   { "version",  no_argument,       0, 'v' },
   { "server",   required_argument, 0, 's' },
   { "port",     required_argument, 0, 'p' },
   { "file",     required_argument, 0, 'f' },
   { "jobid",    required_argument, 0, 'j' },
   { NULL, 0, NULL, 0}
};

static char short_options[] = "hvs:p:f:j:";

static void
usage(exit_code)
{
   fprintf(stdout, "Usage: edg-wl-renew [option] operation\n"
	   "\t-s myproxy_server [-p port] -f filename -j jobid start |\n"
	   "\t-j jobid [-f filename] stop |\n"
	   "\t-j jobid get\n"
	   "-h, --help                 display this help and exit\n"
	   "-v, --version              output version information and exit\n"
	   "-s, --server <fqdn>        address of myproxy server\n"
	   "-p, --port <num>           port of myproxy server\n"
	   "-f, --file <file>          filename with proxy\n"
	   "-j, --jobid <str>          datagrid jobid\n");
   exit(exit_code);
}

int
main(int argc, char *argv[])
{
   char *server = NULL;
   int port = 0;
   char *proxyfile = NULL;
   char *jobid_str = NULL;
   char *repository_filename = NULL;
   int ret;
   int arg;
   extern int optind;

   while ((arg = getopt_long(argc, argv,
	                     short_options, long_options, (int *) 0)) != EOF)
      switch(arg) {
	 case 'h':
	    usage(0); break;
	 case 'v':
	    fprintf(stdout, "%s:\t%s\n", argv[0], rcsid); exit(0);
	 case 's':
	    server = strdup(optarg); break;
	 case 'p':
	    port = atoi(optarg); break;
	 case 'f':
	    proxyfile = strdup(optarg); break;
	 case 'j':
	    jobid_str = strdup(optarg); break;
	 default:
	    usage(1); break;
      }

   if (optind >= argc)
      usage(1);

   if (strcmp(argv[optind], "start") == 0) {
      if (proxyfile == NULL || server == NULL || jobid_str == NULL)
	 usage(1);
      ret = glite_renewal_RegisterProxy(proxyfile, server, port, jobid_str, 0,
	 			        &repository_filename);
      if (ret) {
	 fprintf(stderr, "Registering proxy failed: %s\n",
	         edg_wlpr_GetErrorText(ret));
	 exit(1);
      }
      printf("%s\n", repository_filename);
      free(repository_filename);
      exit(0);
   }
   else if (strcmp(argv[optind], "stop") == 0) {
      if (jobid_str == NULL)
	 usage(1);
      ret = glite_renewal_UnregisterProxy(jobid_str, proxyfile);
      if (ret) {
	 fprintf(stderr, "Unregistering proxy failed: %s\n",
	         edg_wlpr_GetErrorText(ret));
	 exit(1);
      }
   }
   else if (strcmp(argv[optind], "get") == 0) {
      if (jobid_str == NULL)
	 usage(1);
      ret = glite_renewal_GetProxy(jobid_str, &proxyfile);
      if (ret) {
	 fprintf(stderr, "GET request failed: %s\n",
	         edg_wlpr_GetErrorText(ret));
	 exit(1);
      }
      printf("%s\n", proxyfile);
      free(proxyfile);
   }
   else 
      usage(1);

   return 0;
}
