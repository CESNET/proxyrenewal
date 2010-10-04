#include "renewal_locl.h"

#ident "$Header$"

/* nread() and nwrite() never return partial data */
static int
nread(int sock, struct timeval *to, char *buf, size_t buf_len, size_t *read_len)
{
   int count;
   size_t remain = buf_len;
   char *cbuf = buf;
   struct pollfd pollfds[1];
   struct timeval before,after;
   int ret;

   if (to) {
      gettimeofday(&before,NULL);
   }

   while (remain > 0) {
      pollfds[0].fd = sock;
      pollfds[0].events = POLLIN;
      switch (poll(pollfds, 1, to ? (to->tv_sec*1000+to->tv_usec/1000) : INFTIM)) {
	 case 0:
	    ret = EDG_WLPR_ERROR_TIMEOUT;
	    goto end;
	 case -1:
	    ret = EDG_WLPR_ERROR_ERRNO;
	    goto end;
      }
      
      count = read(sock, cbuf, remain);
      if (count < 0) {
	 if (errno == EINTR)
	    continue;
	 else {
	    ret = EDG_WLPR_ERROR_ERRNO;
	    goto end;
	 }
      } else
	 if (count == 0) {
	    *read_len = 0;
	    return 0;
	 }
      cbuf += count;
      remain -= count;
   }
   *read_len = buf_len;
   ret = 0;

end:
   if (to) {
      gettimeofday(&after,NULL);
      edg_wlpr_DecrementTimeout(to, before, after);
      if (to->tv_sec < 0) {
	 to->tv_sec = 0;
	 to->tv_usec = 0;
      }
   }

   return ret;
}

static int
nwrite(int sock, struct timeval *to, const char *buf, size_t buf_len)
{
   const char *cbuf = buf;
   int count;
   size_t remain = buf_len;
   struct pollfd pollfds[1];
   struct timeval before,after;
   int ret;

   if (to) {
      gettimeofday(&before,NULL);
   }

   while (remain > 0) {
      pollfds[0].fd = sock;
      pollfds[0].events = POLLOUT;
      switch (poll(pollfds, 1, to ? (to->tv_sec*1000+to->tv_usec/1000) : INFTIM)) {
	 case 0: ret = EDG_WLPR_ERROR_TIMEOUT;
		 goto end;
	 case -1: ret = EDG_WLPR_ERROR_ERRNO;
		  goto end;
      }
		 
      count = write(sock, cbuf, remain);
      if (count < 0) {
	 if (errno == EINTR)
	    continue;
	 else {
	    ret = EDG_WLPR_ERROR_ERRNO;
	    goto end;
	 }
      }
      cbuf += count;
      remain -= count;
   }
   ret = 0;

end:
   if (to) {
      gettimeofday(&after,NULL);
      edg_wlpr_DecrementTimeout(to, before, after);
      if (to->tv_sec < 0) {
	 to->tv_sec = 0;
	 to->tv_usec = 0;
      }
   }

   return ret;
}

int
edg_wlpr_Read(int sock, struct timeval *timeout, char **buf, size_t *buf_len)
{
   int ret;
   unsigned char length[4];
   size_t len;

   ret = nread(sock, timeout, length, 4, &len);
   if (ret) {
      *buf_len = 0;
      return ret;
   }
   if (len != 4) {
      *buf_len = 0;
      return EDG_WLPR_ERROR_UNEXPECTED_EOF; /* XXX vraci i kdyz peer spadne a zavre trubku */
   }
   *buf_len = (length[0] << 24) | 
              (length[1] << 16) | 
	      (length[2] << 8 ) | 
	      (length[3] << 0);

   *buf = malloc(*buf_len);
   if (*buf == NULL)
      return ENOMEM;

   ret = nread(sock, timeout, *buf, *buf_len, &len);
   if (ret)
      return ret;

   if (len != *buf_len) {
      free(*buf);
      *buf_len = 0;
      return EDG_WLPR_ERROR_UNEXPECTED_EOF; /* XXX */
   }

   return 0;
}

int
edg_wlpr_Write(int sock, struct timeval *timeout, char *buf, size_t buf_len)
{
   unsigned char length[4];
   int ret;

   length[0] = (buf_len >> 24) & 0xFF;
   length[1] = (buf_len >> 16) & 0xFF;
   length[2] = (buf_len >> 8)  & 0xFF;
   length[3] = (buf_len >> 0)  & 0xFF;

   if ((ret = nwrite(sock, timeout, length, 4)) != 0 ||
       (ret = nwrite(sock, timeout, buf, buf_len)) != 0) 
       return ret;
   
   return 0;
}

int
edg_wlpr_GetToken(const char *msg, const size_t msg_len, 
                  const char *key, const char *separators,
		  int req_index, char **value)
{
   char *p;
   size_t len;
   int index;

   assert(separators != NULL);

   /* Add ending zero ? */

   index = 0;
   p = (char *)msg;
   while (p && (p = strstr(p, key))) {
     if (index == req_index)
	break;
     index++;
     p += strlen(key);
   }
   if (p == NULL)
      return EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND;

   p = strchr(p, '=');
   if (p == NULL)
      return EDG_WLPR_ERROR_PROTO_PARSE_ERROR;

   len = strcspn(p+1, separators);
   if (len == 0)
      return EDG_WLPR_ERROR_PROTO_PARSE_ERROR;

   *value = malloc(len + 1);
   if (*value == NULL)
      return ENOMEM;

   memcpy(*value, p+1, len);
   (*value)[len] = '\0';

   return 0;
}

int
edg_wlpr_StoreToken(char **buf, size_t *buf_len, char *command,
                    char *value, const char *separator)
{
   char line[2048];
   char *tmp;

   assert(buf != NULL);
   assert(separator != NULL);

   if (strlen(command) + 1 + strlen(value) + 2 > sizeof(line))
      return ERANGE; /* XXX */

   snprintf(line, sizeof(line), "%s%s%s", command, value, separator);

   while (strlen(*buf) + strlen(line) + 1 > *buf_len) {
      tmp = realloc(*buf, *buf_len + EDG_WLPR_BUF_SIZE);
      if (tmp == NULL)
         return ENOMEM;
      *buf = tmp;
      *buf_len += EDG_WLPR_BUF_SIZE;
   }
   strcat(*buf, line);

   return 0;
}

void
edg_wlpr_CleanRequest(edg_wlpr_Request *request)
{
   assert(request != NULL);
   if (request->version)
      free(request->version);
   if (request->proxy_filename)
      free(request->proxy_filename);
   if (request->myproxy_server)
      free(request->myproxy_server);
   if (request->jobid)
      free(request->jobid);
   if (request->entries) {
      char **p = request->entries;
      char **next;
      while (*p) {
	 next = p+1;
	 free(*p);
	 p = next;
      }
      free(request->entries);
   }

   memset(request, 0, sizeof(request));
}

void
edg_wlpr_CleanResponse(edg_wlpr_Response *response)
{
   assert(response != NULL);
   if (response->version)
      free(response->version);
   if (response->myproxy_server)
      free(response->myproxy_server);
   if (response->filenames) {
      char **p = response->filenames;
      char **next;

      while (*p) {
	 next = p+1;
	 free(*p);
	 p = next;
      }
      free(response->filenames);
   }
   memset(response, 0, sizeof(*response));
}

const char *
edg_wlpr_GetErrorString(int code)
{
   return (code == 0) ? "OK" : "Error";
}

char *
edg_wlpr_EncodeInt(int num) /* long? time */
{
   static char ret[64];

   snprintf(ret, sizeof(ret), "%d", num);
   return ret;
}

int
edg_wlpr_DecodeInt(char *str, int *num)
{
   *num = atol(str); /* XXX */
   return 0;
}

int
edg_wlpr_DecrementTimeout(struct timeval *timeout, struct timeval before, struct timeval after)
{
   (*timeout).tv_sec = (*timeout).tv_sec - (after.tv_sec - before.tv_sec);
   (*timeout).tv_usec = (*timeout).tv_usec - (after.tv_usec - before.tv_usec);
   while ( (*timeout).tv_usec < 0) {
      (*timeout).tv_sec--;
      (*timeout).tv_usec += 1000000;
   }

   if ( ((*timeout).tv_sec < 0) || (((*timeout).tv_sec == 0) && ((*timeout).tv_usec == 0)) ) return(1);
   else return(0);
}
