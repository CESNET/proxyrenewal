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

#ifndef RENEWAL_CORE_H
#define RENEWAL_CORE_H

#ident "$Id$"

#include <sys/syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	GLITE_RENEWAL_LOG_NONE,
	GLITE_RENEWAL_LOG_STDOUT,
	GLITE_RENEWAL_LOG_SYSLOG,
} glite_renewal_log_dst;

typedef struct glite_renewal_core_context_data {
  int log_level;
  glite_renewal_log_dst log_dst;
  char *err_message;
  char *voms_conf;
  int order_attributes;
} glite_renewal_core_context_data;

typedef struct glite_renewal_core_context_data *glite_renewal_core_context;

/**
 * This cal initializes the context and sets default values
 */
int
glite_renewal_core_init_ctx(glite_renewal_core_context *context);

/**
 * This call frees the context and all memory used by the context
 */
int
glite_renewal_core_destroy_ctx(glite_renewal_core_context context);

/**
 * This call tries to renew the proxy certificate using the MyProxy
 * repository. If VOMS attributes are present in the proxy they are renewed
 * as well.
 * \param context IN: context with authentication information
 * \param myproxy_server IN: hostname of the myproxy repository
 * \param myproxy_port IN: TCP port of the myproxy repository, if 0 the
 * default value will be used
 * \param current_proxy IN: filename with the proxy to renew
 * \param new_proxy OUT: filename with the renewed proxy, the caller is
 * responsible for removing the file when it's not needed.
 */
int
glite_renewal_core_renew(glite_renewal_core_context context,
			 const char *myproxy_server,
			 unsigned int myproxy_port,
			 const char *current_proxy,
			 char **new_proxy);

void
glite_renewal_core_set_err(glite_renewal_core_context ctx, const char *format, ...);

void
glite_renewal_core_update_err(glite_renewal_core_context ctx, const char *format, ...);

char *
glite_renewal_core_get_err(glite_renewal_core_context ctx);

void
glite_renewal_core_reset_err(glite_renewal_core_context ctx);

#ifdef __cplusplus
}
#endif

#endif /* RENEWAL_CORE_H */
