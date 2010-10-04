#include "renewal_locl.h"
#include "renewd_locl.h"

static const char rcsid[] = "$Header$";

#define SEPARATORS "\n"
/* GRIDMANAGER_CHECKPROXY_INTERVAL + GRIDMANAGER_MINIMUM_PROXY_TIME */
#define CONDOR_MINIMUM_PROXY_TIME (1800)

int debug = 0;
char *repository = NULL;
time_t condor_limit = CONDOR_MINIMUM_PROXY_TIME;
char *cadir = NULL;
char *vomsdir = NULL;
int voms_enabled = 0;
char *cert = NULL;
char *key = NULL;
char *vomsconf = NULL;

static volatile int die = 0, child_died = 0;
double default_timeout = 0;

static struct option opts[] = {
   { "help",       no_argument,       NULL,  'h' },
   { "version",    no_argument,       NULL,  'v' },
   { "debug",      no_argument,       NULL,  'd' },
   { "repository", required_argument, NULL,  'r' },
   { "condor-limit", required_argument, NULL, 'c' }, 
   { "CAdir",      required_argument, NULL,  'C' },
   { "VOMSdir",    required_argument, NULL,  'V' },
   { "enable-voms", no_argument,     NULL,  'A' },
   { "voms-config", required_argument, NULL, 'G' },
   { "cert",        required_argument, NULL, 't' },
   { "key",         required_argument, NULL, 'k' },
   { NULL, 0, NULL, 0 }
};

typedef struct {
   edg_wlpr_Command code;
   void (*handler) (glite_renewal_core_context ctx, edg_wlpr_Request *request, edg_wlpr_Response *response);
} command_table;

static command_table commands[] = {
   { EDG_WLPR_COMMAND_REG,     register_proxy,     },
   { EDG_WLPR_COMMAND_UNREG,   unregister_proxy,   },
   { EDG_WLPR_COMMAND_GET,     get_proxy,          },
#if 0
   { EDG_WLPR_COMMAND_LIST,    list_proxies,       },
   { EDG_WLPR_COMMAND_STATUS,  status_proxy,       },
#endif
   { EDG_WLPR_COMMAND_UPDATE_DB, update_db,        },
   { 0, NULL },
};

/* static prototypes */
static void
usage(glite_renewal_core_context ctx, char *progname);

static int
do_listen(glite_renewal_core_context ctx, char *socket_name, int *sock);

static int
encode_response(glite_renewal_core_context ctx, edg_wlpr_Response *response, char **msg);

static command_table *
find_command(glite_renewal_core_context ctx, edg_wlpr_Command code);

static int
proto(glite_renewal_core_context ctx, int sock);

static int
doit(glite_renewal_core_context ctx, int sock);

static int
decode_request(glite_renewal_core_context ctx, const char *msg, const size_t msg_len, edg_wlpr_Request *request);

int
start_watchdog(glite_renewal_core_context ctx, pid_t *pid);

static void
catchsig(int sig)
{
   switch (sig) {
      case SIGINT:
      case SIGTERM:
      case SIGQUIT:
	 die = sig;
	 break;
      case SIGCHLD:
	 child_died = 1;
	 break;
      default:
	 break;
   }
}

static command_table *
find_command(glite_renewal_core_context ctx, edg_wlpr_Command code)
{
   command_table *c;

   for (c = commands; c->code; c++) {
      if (c->code == code)
          return c;
   }
   return NULL;
}

static int
proto(glite_renewal_core_context ctx, int sock)
{
   char  *buf = NULL;
   size_t  buf_len;
   int  ret;
   edg_wlpr_Response  response;
   edg_wlpr_Request  request;
   command_table  *command;
   struct timeval timeout;

   memset(&request, 0, sizeof(request));
   memset(&response, 0, sizeof(response));

   timeout.tv_sec = (long) default_timeout;
   timeout.tv_usec = (long) ((default_timeout - timeout.tv_sec) * 1e6);

   ret = edg_wlpr_Read(sock, &timeout, &buf, &buf_len);
   if (ret) {
      glite_renewal_log(ctx, LOG_ERR, "Error reading from client: %s",
                   edg_wlpr_GetErrorString(ret));
      return ret;
   }

   ret = decode_request(ctx, buf, buf_len, &request);
   free(buf);
   if (ret)
      goto end;

   /* XXX check request (protocol version, ...) */

   command = find_command(ctx, request.command);
   if (command == NULL) {
      ret = EDG_WLPR_ERROR_UNKNOWN_COMMAND;
      glite_renewal_log(ctx, LOG_ERR, "Received unknown command (%d)", request.command);
      goto end;
   }

   glite_renewal_log(ctx, LOG_INFO, "Received command code %d for proxy %s and jobid %s",
                request.command,
		request.proxy_filename ? request.proxy_filename : "(unspecified)",
		request.jobid ? request.jobid : "(unspecified)");

   command->handler(ctx, &request, &response);

   ret = encode_response(ctx, &response, &buf);
   if (ret)
      goto end;

   ret = edg_wlpr_Write(sock, &timeout, buf, strlen(buf) + 1);
   free(buf);
   if (ret) {
      glite_renewal_log(ctx, LOG_ERR, "Error sending response to client: %s",
                   edg_wlpr_GetErrorString(ret));
      goto end;
   }

end:
   edg_wlpr_CleanRequest(&request);
   edg_wlpr_CleanResponse(&response);

   return ret;
}

static int
doit(glite_renewal_core_context ctx, int sock)
{
   int newsock;
   struct sockaddr_un client_addr;
   int client_addr_len = sizeof(client_addr);
   int flags;

   while (!die) {

      if (child_died) {
	 int pid, newpid, ret;

	 while ((pid=waitpid(-1,NULL,WNOHANG))>0)
	    ;
	 ret = start_watchdog(ctx, &newpid);
	 if (ret)
	    return ret;
	 glite_renewal_log(ctx, LOG_DEBUG, "Renewal slave process re-started");
	 child_died = 0;
	 continue;
      }

      newsock = accept(sock, (struct sockaddr *) &client_addr, &client_addr_len);
      if (newsock == -1) {
	 if (errno != EINTR)
	    glite_renewal_log(ctx, LOG_ERR, "accept() failed");
         continue;
      }
      glite_renewal_log(ctx, LOG_DEBUG, "Got connection");

      flags = fcntl(newsock, F_GETFL, 0);
      if (fcntl(newsock, F_SETFL, flags | O_NONBLOCK) < 0) {
	 glite_renewal_log(ctx, LOG_ERR, "Can't set O_NONBLOCK mode (%s), closing.\n",
	              strerror(errno));
	 close(newsock);
	 continue;
      }
	 
      proto(ctx, newsock);

      glite_renewal_log(ctx, LOG_DEBUG, "Connection closed");
      close(newsock);
   }
   glite_renewal_log(ctx, LOG_DEBUG, "Terminating on signal %d\n",die);
   return 0;
}

static int
decode_request(glite_renewal_core_context ctx, const char *msg, const size_t msg_len, edg_wlpr_Request *request)
{
   char *value = NULL;
#if 0
   char *p;
   int port;
#endif
   int ret;
   int index;
   
   /* XXX add an ending zero '\0' */

   assert(msg != NULL);
   assert(request != NULL);
   
   memset(request, 0, sizeof(*request));

   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_VERSION, SEPARATORS,
	 		   0, &request->version);
   if (ret) {
      glite_renewal_log(ctx, LOG_ERR, "Protocol error reading protocol specification: %s",
                   edg_wlpr_GetErrorString(ret));
      return ret;
   }
   
   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_COMMAND, SEPARATORS,
	 		   0, &value);
   if (ret) {
      glite_renewal_log(ctx, LOG_ERR, "Protocol error reading command specification: %s",
                   edg_wlpr_GetErrorString(ret));
      goto err;
   }

   ret = edg_wlpr_DecodeInt(value, (int *)(&request->command));
   if (ret) {
      glite_renewal_log(ctx, LOG_ERR, "Received non-numeric command specification (%s)",
                   value);
      free(value);
      goto err;
   }
   free(value);

   if (find_command(ctx, request->command) == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Received unknown command (%d)", request->command);
      ret = EDG_WLPR_ERROR_UNKNOWN_COMMAND;
      goto err;
   }

   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_MYPROXY_SERVER,
	 		   SEPARATORS, 0, &request->myproxy_server);
   if (ret && ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND) {
      glite_renewal_log(ctx, LOG_ERR, "Protocol error reading myproxy server specification: %s",
                   edg_wlpr_GetErrorString(ret));
      goto err;
   }

#if 0
   request->myproxy_port = EDG_WLPR_MYPROXY_PORT; /* ??? */
   if (request->myproxy_server && (p = strchr(request->myproxy_server, ':'))) {
      *p = '\0';
      port = atol(p+1); /* XXX see myproxy for err check */
      request->myproxy_port = port;
   }
#endif

   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_PROXY, SEPARATORS, 
	 		   0, &request->proxy_filename);
   if (ret && ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND) {
      glite_renewal_log(ctx, LOG_ERR, "Protocol error reading proxy specification: %s",
                   edg_wlpr_GetErrorString(ret));
      goto err;
   }

#if 0
   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_UNIQUE_PROXY, 
	 		   SEPARATORS, 0, &value);
   if (ret && ret != EDG_WLPR_ERROR_PARSE_NOT_FOUND)
      goto err;
   if (ret == 0 && strcasecmp(value, "yes") == 0)
      request->unique = 1;
   free(value);
#endif

   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_JOBID, SEPARATORS,
	 		   0, &request->jobid);
   if (ret && ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND) {
      glite_renewal_log(ctx, LOG_ERR, "Protocol error reading JobId : %s",
	    	   edg_wlpr_GetErrorString(ret));
      goto err;
   }

   index = 0;
   while ((ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_ENTRY,
	       			   SEPARATORS, index, &value)) == 0) {
      char **tmp;

      tmp = realloc(request->entries, (index + 2) * sizeof(*tmp));
      if (tmp == NULL) {
	 ret = ENOMEM;
	 goto err;
      }
      request->entries = tmp;
      request->entries[index] = value;
      index++;
   }
   if (ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND)
      goto err;
   if (request->entries)
      request->entries[index] = NULL;

   return 0;

err:
   edg_wlpr_CleanRequest(request);
   return ret;
}

static int
encode_response(glite_renewal_core_context ctx, edg_wlpr_Response *response, char **msg)
{
   char *buf;
   size_t buf_len;
   int ret;

   buf_len = EDG_WLPR_BUF_SIZE;
   buf = malloc(buf_len);
   if (buf == NULL)
      return ENOMEM;
   buf[0] = '\0';

   ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_VERSION,
	 		     EDG_WLPR_VERSION, SEPARATORS);
   if (ret)
      goto err;

   ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_RESPONSE,
                             edg_wlpr_EncodeInt(response->response_code),
			     SEPARATORS);
   if (ret)
      goto err;

   if (response->myproxy_server) {
      char host[1024];

#if 0
      snprintf(host, sizeof(host), "%s:%d", response->myproxy_server,
               (response->myproxy_port) ? response->myproxy_port : EDG_WLPR_MYPROXY_PORT);
#endif
      ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_MYPROXY_SERVER,
                                host, SEPARATORS);
      if (ret)
         goto err;
   }

   if (response->start_time) {
      ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_START_TIME,
                                edg_wlpr_EncodeInt(response->start_time),
				SEPARATORS);
      if (ret)
         goto err;
   }

   if (response->end_time) {
      ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_END_TIME,
                                edg_wlpr_EncodeInt(response->end_time),
				SEPARATORS);
      if (ret)
         goto err;
   }

   if (response->next_renewal_time) {
      ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_RENEWAL_TIME,
                                edg_wlpr_EncodeInt(response->next_renewal_time),
				SEPARATORS);
      if (ret)
         goto err;
   }

   if (response->filenames) {
      char **p = response->filenames;
      while (*p) {
         ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_PROXY, *p,
	       			   SEPARATORS);
         if (ret)
            goto err;
         p++;
      }
   }

   buf[strlen(buf)] = '\0';
   *msg = buf;
   return 0;

err:
   free(buf);
   *msg = NULL;
   return ret;
}


static void
usage(glite_renewal_core_context ctx, char *progname)
{
   fprintf(stderr,"usage: %s [option]\n"
	   "\t-h, --help           display this help and exit\n"
	   "\t-v, --version        output version information and exit\n"
	   "\t-d, --debug          don't fork, print out debugging information\n"
	   "\t-r, --repository     repository directory\n"
	   "\t-c, --condor-limit   how long before expiration the proxy must be renewed\n"
	   "\t-C, --CAdir          trusted certificates directory\n"
	   "\t-V, --VOMSdir        trusted VOMS servers certificates directory\n"
	   "\t-A, --enable-voms    renew also VOMS certificates in proxies\n"
	   "\t-G, --voms-config    location of the vomses configuration file\n",
	   progname);
}

static int
do_listen(glite_renewal_core_context ctx, char *socket_name, int *sock)
{
   struct sockaddr_un my_addr;
   int s;
   int ret;

   assert(sock != NULL);

   memset(&my_addr, 0, sizeof(my_addr));
   my_addr.sun_family = AF_UNIX;
   strncpy(my_addr.sun_path, socket_name, sizeof(my_addr.sun_path));
   unlink(socket_name);
   umask(0177);

   s = socket(AF_UNIX, SOCK_STREAM, 0);
   if (s == -1) {
      glite_renewal_log(ctx, LOG_ERR, "socket(): %s", strerror(errno));
      return errno;
   }

   ret = bind(s, (struct sockaddr *)&my_addr, sizeof(my_addr));
   if (ret == -1) {
      glite_renewal_log(ctx, LOG_ERR, "bind(): %s", strerror(errno));
      close(s);
      return errno;
   }

   ret = listen(s, 50);
   if (ret == -1) {
      glite_renewal_log(ctx, LOG_ERR, "listen(): %s", strerror(errno));
      close(s);
      return errno;
   }

   *sock = s;
   return 0;
}

int
start_watchdog(glite_renewal_core_context ctx, pid_t *pid)
{
   pid_t p;

   switch ((p = fork())) {
      case -1:
	 glite_renewal_log(ctx, LOG_ERR, "fork() failed: %s",
	              strerror(errno));
	 return errno;
      case 0:
	 watchdog_start(ctx);
	 exit(0); 
	 break;
      default:
	 *pid = p;
	 return 0;
   }
   /* not reachable */
   exit(0);
}

int main(int argc, char *argv[])
{
   int   sock;
   char  *progname;
   int   opt;
   int   fd;
   char  sockname[PATH_MAX];
   int   ret;
   pid_t pid;
   struct sigaction	sa;
   const char *s = NULL;
   glite_renewal_core_context ctx = NULL;

   progname = strrchr(argv[0],'/');
   if (progname) progname++; 
   else progname = argv[0];

   repository = EDG_WLPR_REPOSITORY_ROOT;
   debug = 0;

   while ((opt = getopt_long(argc, argv, "hvdr:c:C:V:AG:t:k:", opts, NULL)) != EOF)
      switch (opt) {
	 case 'h': usage(ctx, progname); exit(0);
	 case 'v': fprintf(stdout, "%s:\t%s\n", progname, rcsid); exit(0);
	 case 'd': debug = 1; break;
         case 'r': repository = optarg; break;
	 case 'c': condor_limit = atoi(optarg); break;
	 case 'C': cadir = optarg; break;
	 case 'V': vomsdir = optarg; break;
	 case 'A': voms_enabled = 1; break;
	 case 'G': vomsconf = optarg; break;
	 case 't': cert = optarg; break;
	 case 'k': key = optarg; break;
	 case '?': usage(ctx, progname); return 1;
      }

   if (optind < argc) {
      usage(ctx, progname);
      exit(1);
   }

   ret = glite_renewal_core_init_ctx(&ctx);
   if (ret) {
      fprintf(stderr, "Cannot initialize context\n");
      exit(1);
   }
   if (debug) {
      ctx->log_level = LOG_DEBUG;
      ctx->log_dst = GLITE_RENEWAL_LOG_STDOUT;
   }
   ctx->voms_conf = vomsconf;

   if (chdir(repository)) {
      glite_renewal_log(ctx, LOG_ERR, "Cannot access repository directory %s (%s)",
	           repository, strerror(errno));
      exit(1);
   }

   globus_module_activate(GLOBUS_GSI_CERT_UTILS_MODULE);
   globus_module_activate(GLOBUS_GSI_PROXY_MODULE);

   if (!debug) {
      /* chdir ? */
      if (daemon(1,0) == -1) {
	 perror("deamon()");
	 exit(1);
      }
      openlog(progname, LOG_PID, LOG_DAEMON);
   }

   if (cert)
      setenv("X509_USER_CERT", cert, 1);

   if (key)
      setenv("X509_USER_KEY", key, 1);

   if (cadir)
      setenv("X509_CERT_DIR", cadir, 1);

   s = getenv("GLITE_PR_TIMEOUT");
   default_timeout = s ? atof(s) : GLITE_PR_TIMEOUT_DEFAULT;

   memset(&sa,0,sizeof(sa));
   sa.sa_handler = catchsig;
   sigaction(SIGINT,&sa,NULL);
   sigaction(SIGQUIT,&sa,NULL);
   sigaction(SIGTERM,&sa,NULL);
   sigaction(SIGCHLD,&sa,NULL);
   sigaction(SIGPIPE,&sa,NULL);

   ret = start_watchdog(ctx, &pid);
   if (ret)
      return 1;
  
   umask(0177);
   snprintf(sockname, sizeof(sockname), "%s%d",
	    DGPR_REG_SOCKET_NAME_ROOT, getuid());
   /* XXX check that the socket is not already active */
   ret = do_listen(ctx, sockname, &sock);
   if (ret)
      return 1;
   glite_renewal_log(ctx, LOG_DEBUG, "Listening at %s", sockname);

   ret = doit(ctx, sock);

   close(sock);
   return ret;
}
