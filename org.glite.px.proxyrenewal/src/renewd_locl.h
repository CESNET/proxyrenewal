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

#ifndef RENEWALD_LOCL_H
#define RENEWALD_LOCL_H

#ident "$Header$"

#include <globus_gsi_credential.h>
#include <globus_gsi_proxy.h>
#include <globus_gsi_cert_utils_constants.h>

#include <glite/security/voms/voms_apic.h>

#include "renewal.h"
#include "renewal_core.h"

#ifdef HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/* XXX */
#if 0
#define EDG_WLPR_ERROR_PARSE_NOT_FOUND EDG_WLPR_ERROR_PROTO_PARSE_ERROR
#define EDG_WLPR_ERROR_NOTFOUND        EDG_WLPR_PROXY_NOT_REGISTERED
#endif

typedef struct {
   unsigned int len;
   char **val;
} prd_list;

typedef struct {
   int suffix;
   prd_list jobids;
   int unique;
   int voms_exts;
   char *myproxy_server;
   time_t end_time;
   time_t next_renewal;
} proxy_record;

/* commands */
void
register_proxy(glite_renewal_core_context ctx, edg_wlpr_Request *request, edg_wlpr_Response *response);

void
unregister_proxy(glite_renewal_core_context ctx, edg_wlpr_Request *request, edg_wlpr_Response *response);

void
get_proxy(glite_renewal_core_context ctx, edg_wlpr_Request *request, edg_wlpr_Response *response);

void
update_db(glite_renewal_core_context ctx, edg_wlpr_Request *request, edg_wlpr_Response *response);

int
get_times(glite_renewal_core_context ctx, char *proxy_file, proxy_record *record);

void
watchdog_start(glite_renewal_core_context ctx);

void
edg_wlpr_Log(glite_renewal_core_context ctx, int dbg_level, const char *format, ...);

int
decode_record(glite_renewal_core_context ctx, char *line, proxy_record *record);

int
encode_record(glite_renewal_core_context ctx, proxy_record *record, char **line);

void
free_record(glite_renewal_core_context ctx, proxy_record *record);

int
load_proxy(glite_renewal_core_context ctx, const char *filename, X509 **cert, EVP_PKEY **privkey,
           STACK_OF(X509) **chain, globus_gsi_cred_handle_t *proxy);

int
get_proxy_base_name(glite_renewal_core_context ctx, const char *file, char **subject);

int
renew_voms_creds(glite_renewal_core_context ctx, const char *cur_file, const char *renewed_file, const char *new_file);

int
is_voms_cert(glite_renewal_core_context ctx, const char *proxy, int *present);

int
get_voms_cert(glite_renewal_core_context ctx,
              X509 *cert, STACK_OF(X509) *chain, struct vomsdata **vd);

#endif /* RENEWALD_LOCL_H */
