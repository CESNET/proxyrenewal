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
