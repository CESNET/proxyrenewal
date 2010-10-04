#include "renewal.h"
#include "renewal_locl.h"

#ident "$Header$"

#define SEPARATORS "\n"

/* prototypes of static routines */
static int
encode_request(edg_wlpr_Request *request, char **msg);

static int
decode_response(const char *msg, const size_t msg_len, edg_wlpr_Response *response);

static int
do_connect(char *socket_name, struct timeval *timeout, int *sock);

static int
send_request(int sock, struct timeval *timeout, edg_wlpr_Request *request, edg_wlpr_Response *response);

static int 
encode_request(edg_wlpr_Request *request, char **msg)
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

   ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_COMMAND,
	                     edg_wlpr_EncodeInt(request->command),
			     SEPARATORS);
   if (ret)
      goto err;

   if (request->myproxy_server) {
      char host[1024];

#if 0
      snprintf(host, sizeof(host), "%s:%d", request->myproxy_server, 
	       (request->myproxy_port) ? request->myproxy_port : EDG_WLPR_MYPROXY_PORT); /* XXX let server decide ? */
#else
      snprintf(host, sizeof(host), "%s", request->myproxy_server);
#endif
      ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_MYPROXY_SERVER,
	                        host, SEPARATORS);
      if (ret)
	 goto err;
   }

   if (request->proxy_filename) {
      ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_PROXY,
	                        request->proxy_filename, SEPARATORS);
      if (ret)
	 goto err;
   }

   if (request->jobid) {
      ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_JOBID,
	    			request->jobid, SEPARATORS);
      if (ret)
	 goto err;
   }

   if (request->entries) {
      char **p = request->entries;
      while (*p) {
	 ret = edg_wlpr_StoreToken(&buf, &buf_len, EDG_WLPR_PROTO_ENTRY,
	       			   *p, SEPARATORS);
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

static int
decode_response(const char *msg, const size_t msg_len, edg_wlpr_Response *response)
{
   int ret;
   char *value = NULL;
   /* char *p; */
   int i;
   int current_size = 0;

   /* XXX add an ending zero '\0' */

   assert(msg != NULL);
   assert(response != NULL);

   memset(response, 0, sizeof(*response));

   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_VERSION, SEPARATORS,
	                   0, &response->version);
   if (ret)
      goto err;

   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_RESPONSE, SEPARATORS,
	 		   0, &value);
   if (ret)
      goto err;

   ret = edg_wlpr_DecodeInt(value, (int *)(&response->response_code));
   free(value);
   if (ret)
      goto err;

   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_MYPROXY_SERVER,
	 		   SEPARATORS, 0, &response->myproxy_server);
   if (ret && ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND)
      goto err;

#if 0
   response->myproxy_port = EDG_WLPR_MYPROXY_PORT; /* ??? */
   if (response->myproxy_server && (p = strchr(response->myproxy_server, ':'))) {
      int port;
      *p = '\0';
      port = atol(p+1); /* XXX */
      response->myproxy_port = port;
   }
#endif

   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_START_TIME, SEPARATORS, 
	 		   0, &value);
   if (ret && ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND)
      goto err;
   if (ret == 0) {
      ret = edg_wlpr_DecodeInt(value, (int *)(&response->start_time));
      free(value);
      if (ret)
         goto err;
   }

   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_END_TIME, SEPARATORS,
	 		   0, &value);
   if (ret && ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND)
      goto err;
   if (ret == 0) { 
      ret = edg_wlpr_DecodeInt(value, (int *)(&response->end_time));
      free(value);
      if (ret)
	 goto err;
   }

   ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_RENEWAL_TIME,
	 		   SEPARATORS, 0, &value);
   if (ret && ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND)
      goto err;
   if (ret == 0) {
      ret = edg_wlpr_DecodeInt(value, (int *)(&response->next_renewal_time));
      free(value);
      if (ret)
	 goto err;
   }

   /* XXX Counter */

   i = 0;
   while ((ret = edg_wlpr_GetToken(msg, msg_len, EDG_WLPR_PROTO_PROXY,
	       			   SEPARATORS, i, &value)) == 0) {
      if (i >= current_size) {
	 char **tmp;

	 tmp = realloc(response->filenames, 
	               (current_size + 16 + 1) * sizeof(*tmp));
	 if (tmp == NULL) {
	    ret = ENOMEM;
	    goto err;
	 }
	 response->filenames = tmp;
	 current_size += 16;
      }
      response->filenames[i] = value;
      i++;
   }
   if (ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND)
      goto err;
   if (response->filenames)
      response->filenames[i] = NULL;

   return 0;

err:
   edg_wlpr_CleanResponse(response);

   return ret;
}

static int
do_connect(char *socket_name, struct timeval *timeout, int *sock)
{
   struct sockaddr_un my_addr;
   int s;
   int ret;
   struct timeval before,after;
   int sock_err;
   socklen_t err_len;

   assert(sock != NULL);
   memset(&my_addr, 0, sizeof(my_addr));

   s = socket(AF_UNIX, SOCK_STREAM, 0);
   if (s == -1) {
      return errno;
   }

   if (timeout) {
      int flags = fcntl(s, F_GETFL, 0);
      if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0)
	 return errno;
   }

   my_addr.sun_family = AF_UNIX;
   strncpy(my_addr.sun_path, socket_name, sizeof(my_addr.sun_path));

   ret = connect(s, (struct sockaddr *) &my_addr, sizeof(my_addr));
   if (ret == -1) {
      if (errno == EINPROGRESS) {
	 struct pollfd pollfds[1];

	 pollfds[0].fd = s;
	 pollfds[0].events = POLLOUT;
	 
	 gettimeofday(&before,NULL);
	 switch (poll(pollfds, 1, timeout->tv_sec*1000+timeout->tv_usec/1000)) {
	    case -1: close(s);
		     return errno;
	    case 0: close(s);
		    return EDG_WLPR_ERROR_TIMEOUT;
	 }
	 gettimeofday(&after,NULL);
	 if (edg_wlpr_DecrementTimeout(timeout, before, after)) {
	    close (s);
	    return EDG_WLPR_ERROR_TIMEOUT;
	 }

	 err_len = sizeof sock_err;
	 if (getsockopt(s,SOL_SOCKET,SO_ERROR,&sock_err,&err_len)) {
	    close(s);
	    return errno;
	 }
	 if (sock_err) {
	    close(s);
	    errno = sock_err;
	    return errno;
	 }
      } else {
	 close(s);
   	 return errno;
      }
   }

   *sock = s;
   return 0;
}

static int
send_request(int sock, struct timeval *timeout, edg_wlpr_Request *request, edg_wlpr_Response *response)
{
   int ret;
   char *buf = NULL;
   size_t buf_len;

   /* timeouts ?? */

   ret = encode_request(request, &buf);
   if (ret)
      return ret;

   ret = edg_wlpr_Write(sock, timeout, buf, strlen(buf) + 1);
   free(buf);
   if (ret)
      return ret;

   ret = edg_wlpr_Read(sock, timeout, &buf, &buf_len);
   if (ret)
      return ret;

   ret = decode_response(buf, buf_len, response);
   free(buf);
   if (ret)
      return ret;

   return 0;
}

int
edg_wlpr_RequestSend(edg_wlpr_Request *request, edg_wlpr_Response *response)
{
   char sockname[1024];
   int ret;
   int sock;
   struct timeval timeout;
   const char *s = NULL;
   double d;

   s = getenv("GLITE_PR_TIMEOUT");
   d = s ? atof(s) : GLITE_PR_TIMEOUT_DEFAULT;
   timeout.tv_sec = (long) d;
   timeout.tv_usec = (long) ((d-timeout.tv_sec) * 1e6);

   snprintf(sockname, sizeof(sockname), "%s%d",
	    DGPR_REG_SOCKET_NAME_ROOT, getuid());
   ret = do_connect(sockname, &timeout, &sock);
   if (ret)
      return ret;

   ret = send_request(sock, &timeout, request, response);

   close(sock);
   return ret;
}

int
glite_renewal_RegisterProxy(const char *filename, const char * server,
                            unsigned int port,
                            const char *jobid, int flags,
                            char **repository_filename)
{
   edg_wlpr_Request request;
   edg_wlpr_Response response;
   int ret;

   memset(&request, 0, sizeof(request));
   memset(&response, 0, sizeof(response));

   if (jobid == NULL)
      return EINVAL;

   request.command = EDG_WLPR_COMMAND_REG;
   request.myproxy_server = server;
   request.proxy_filename = filename;
   request.jobid = strdup(jobid);
   if (request.jobid == NULL)
      return ENOMEM;

   ret = edg_wlpr_RequestSend(&request, &response);
   free(request.jobid);
   if (ret == 0 && response.response_code == 0 && repository_filename &&
       response.filenames && response.filenames[0] )
      *repository_filename = strdup(response.filenames[0]);

   if (ret == 0)
      ret = response.response_code;

   edg_wlpr_CleanResponse(&response);
   
   return ret;
}

#ifdef RENEWAL_HAVE_JOBID
int
edg_wlpr_RegisterProxyExt(const char *filename, const char * server,
			  unsigned int port,
                          edg_wlc_JobId jobid, int flags,
			  char **repository_filename)
{
   char *ji;
   int ret;

   ji = edg_wlc_JobIdUnparse(jobid);
   if (ji == NULL)
      return EINVAL;

   ret = glite_renewal_RegisterProxy(filename, server, port, ji, flags,
		     		     repository_filename);
   free(ji);
   return ret;
}
#endif /* RENEWAL_HAVE_JOBID */

#if 0
int
edg_wlpr_RegisterProxy(const char *filename, const char *jdl,
                       int flags, char **repository_filename)
{
   char server[1024];
   size_t server_len;
   unsigned int port = 0;
   char *p, *q;
   
   memset(server, 0, sizeof(server));
   
   /* parse JDL and find information about myproxy server */
   p = strstr(jdl, JDL_MYPROXY);
   if (p == NULL)
      return 0; /* XXX */
   q = strchr(p, '\n'); /* XXX */
   if (q)
      server_len = q - p;
   else 
      server_len = jdl + strlen(jdl) - p;
   if (server_len >= sizeof(server))
      return EINVAL; /* XXX */
   strncmp(server, p, sizeof(server));

   return (edg_wlpr_RegisterProxyExt(filename, server, port, NULL, flags, 
	                             repository_filename));
}
#endif

int
glite_renewal_UnregisterProxy(const char *jobid, const char *repository_filename)
{
   edg_wlpr_Request request;
   edg_wlpr_Response response;
   int ret;

   memset(&request, 0, sizeof(request));
   memset(&response, 0, sizeof(response));

   if (jobid == NULL)
      return EINVAL;

   request.command = EDG_WLPR_COMMAND_UNREG;
   request.proxy_filename = repository_filename;
   request.jobid = strdup(jobid);
   if (request.jobid == NULL)
      return ENOMEM;

   ret = edg_wlpr_RequestSend(&request, &response);
   free(request.jobid);
   
   if (ret == 0)
      ret = response.response_code;
   edg_wlpr_CleanResponse(&response);

   return ret;
}

#ifdef RENEWAL_HAVE_JOBID
int
edg_wlpr_UnregisterProxy(edg_wlc_JobId jobid, const char *repository_filename)
{
   char *ji;
   int ret;

   ji = edg_wlc_JobIdUnparse(jobid);
   if (ji == NULL)
      return EINVAL;
   ret = glite_renewal_UnregisterProxy(ji, repository_filename);
   free(ji);
   return ret;
}
#endif /* RENEWAL_HAVE_JOBID */

int
edg_wlpr_GetList(int *count, char **list)
{
   return ENOSYS; /* XXX */
}

int
edg_wlpr_GetStatus(const char *filename, char **info)
{
   return ENOSYS; /* XXX */
}

static const char* const errTexts[] = {
   "Unexpected EOF from peer",
   "Generic error",
   "Protocol parse error",
   "Compulsory element not found in message",
   "Unknown protocol command",
   "SSL error",
   "Error from Myproxy server",
   "Proxy not registered",
   "Proxy expired",
   "VOMS error",
   "Operation timed out",
   "System error"
};

const char *
edg_wlpr_GetErrorText(int code)
{
   return code ?
           (code <= EDG_WLPR_ERROR_BASE ?
	            strerror(code) :
		    errTexts[code - EDG_WLPR_ERROR_BASE - 1]
	   ) :
	   NULL;
}

int
glite_renewal_GetProxy(const char *jobid, char **repository_filename)
{
   edg_wlpr_Request request;
   edg_wlpr_Response response;
   int ret;

   memset(&request, 0, sizeof(request));
   memset(&response, 0, sizeof(response));

   if (jobid == NULL)
      return EINVAL;

   request.command = EDG_WLPR_COMMAND_GET;
   request.jobid = strdup(jobid);
   if (request.jobid == NULL)
      return ENOMEM;

   ret = edg_wlpr_RequestSend(&request, &response);
   free(request.jobid);

   if (ret == 0 && response.response_code == 0 && repository_filename &&
       response.filenames && response.filenames[0] )
      *repository_filename = strdup(response.filenames[0]);
   
   if (ret == 0)
      ret = response.response_code;
   edg_wlpr_CleanResponse(&response);

   return ret;
}

#ifdef RENEWAL_HAVE_JOBID
int
edg_wlpr_GetProxy(edg_wlc_JobId jobid, char **repository_filename)
{
   char *ji;
   int ret;

   ji = edg_wlc_JobIdUnparse(jobid);
   if (ji == NULL)
      return EINVAL;

   ret = glite_renewal_GetProxy(ji, repository_filename);
   free(ji);
   return ret;
}
#endif /* RENEWAL_HAVE_JOBID */
