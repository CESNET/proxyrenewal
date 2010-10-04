#ifndef RENEWAL_LOCL_H
#define RENEWAL_LOCL_H

#ident "$Header$"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <linux/limits.h>
#include <signal.h>
#include <assert.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <poll.h>
#ifndef INFTIM
#define INFTIM (-1)
#endif

#include <openssl/md5.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "renewal.h"

#define JDL_MYPROXY "Myproxy_server="

typedef enum {
  EDG_WLPR_COMMAND_NONE = 0,
  EDG_WLPR_COMMAND_REG = 1,
  EDG_WLPR_COMMAND_UNREG,
  EDG_WLPR_COMMAND_GET,
  EDG_WLPR_COMMAND_LIST,
  EDG_WLPR_COMMAND_STATUS,
  EDG_WLPR_COMMAND_UPDATE_DB,
} edg_wlpr_Command;

/* prefix neni nutny */
#define EDG_WLPR_PROTO_VERSION          "Version="
#define EDG_WLPR_PROTO_COMMAND          "Command="
#define EDG_WLPR_PROTO_MYPROXY_SERVER   "Myproxy_server="
#define EDG_WLPR_PROTO_PROXY            "Proxy_name="
#define EDG_WLPR_PROTO_UNIQUE_PROXY     "Unique=" /* XXX */
#define EDG_WLPR_PROTO_JOBID            "Jobid="
#define EDG_WLPR_PROTO_ENTRY            "Entry="

#define EDG_WLPR_PROTO_RESPONSE         "Response=" /* XXX result ?? */
#define EDG_WLPR_PROTO_START_TIME       "Start_time="
#define EDG_WLPR_PROTO_END_TIME         "End_time="
#define EDG_WLPR_PROTO_RENEWAL_TIME     "Renewal_time=" /* XXX Next renewal ?? */

#define EDG_WLPR_MYPROXY_PORT 7512

#define EDG_WLPR_REPOSITORY_ROOT "/var/spool/edg-wl-renewd"

#define EDG_WLPR_BUF_SIZE 4096

#define EDG_WLPR_VERSION "EDG Proxy Renewal 1.0"

#define MAX_PROXIES 4 /* max. number of jobids sharing one proxy */

#define RENEWAL_CLOCK_SKEW (5 * 60)

#define DGPR_RETRIEVE_DEFAULT_HOURS 10

#define GLITE_PR_TIMEOUT_DEFAULT	120

typedef struct {
  char *version;
  edg_wlpr_Command command;
  char *myproxy_server;
  char *proxy_filename;
  int unique; 
  char *jobid;
  char **entries; /* for updates from the renewal part (renew.c) */
} edg_wlpr_Request;

typedef struct {
  char *version;
  int response_code;
  time_t start_time;
  time_t end_time;
  time_t next_renewal_time;
  int counter;
  char *myproxy_server;
  char **filenames;
} edg_wlpr_Response;

#define DGPR_REG_SOCKET_NAME_ROOT "/tmp/dgpr_renew_"

#if 0
/* Errors: */
/* XXX enum */
#define EDG_WLPR_ERROR_EOF 1
#define EDG_WLPR_ERROR_PARSE_NOT_FOUND 2
#define EDG_WLPR_ERROR_PARSE_ERROR 3
#define EDG_WLPR_ERROR_UNKNOWN_COMMAND 4
#define EDG_WLPR_ERROR_NOTFOUND 5
#endif

int
edg_wlpr_GetToken(const char *msg, const size_t msg_len,
                  const char *key, const char *separators,
                  int req_index, char **value);

int
edg_wlpr_StoreToken(char **buf, size_t *buf_len, char *command,
                    char *value, const char *separator);

int
edg_wlpr_Read(int sock, struct timeval *timeout, char **buf, size_t *buf_len);

int
edg_wlpr_Write(int sock, struct timeval *timeout, char *buf, size_t buf_len);

void
edg_wlpr_CleanRequest(edg_wlpr_Request *request);

void
edg_wlpr_CleanResponse(edg_wlpr_Response *response);

const char *
edg_wlpr_GetErrorString(int err);

char *
edg_wlpr_EncodeInt(int num); /* long? time */

int
edg_wlpr_DecodeInt(char *str, int *num);

int
edg_wlpr_RequestSend(edg_wlpr_Request *request, edg_wlpr_Response *response);

int
edg_wlpr_DecrementTimeout(struct timeval *timeout, struct timeval before, struct timeval after);

#endif /* RENEWAL_LOCL_H */
