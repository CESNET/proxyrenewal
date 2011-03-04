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

#include <myproxy.h>
#include <myproxy_delegation.h>

#include "renewal_core.h"
#include "renewal_locl.h"
#include "renewd_locl.h"

static const char rcsid[] = "$Id$";

int
load_proxy(glite_renewal_core_context ctx, const char *cur_file, X509 **cert, EVP_PKEY **priv_key,
           STACK_OF(X509) **chain, globus_gsi_cred_handle_t *cur_proxy)
{
   globus_result_t result;
   globus_gsi_cred_handle_t proxy = NULL;
   int ret;

   result = globus_gsi_cred_handle_init(&proxy, NULL);
   if (result) {
      glite_renewal_core_set_err(ctx, "globus_gsi_cred_handle_init() failed");
      goto end;
   }

   result = globus_gsi_cred_read_proxy(proxy, (char *) cur_file);
   if (result) {
      glite_renewal_core_set_err(ctx, "globus_gsi_cred_read_proxy() failed");
      goto end;
   }

   if (cert) {
      result = globus_gsi_cred_get_cert(proxy, cert);
      if (result) {
	 glite_renewal_core_set_err(ctx, "globus_gsi_cred_get_cert() failed");
	 goto end;
      }
   }

   if (priv_key) {
      result = globus_gsi_cred_get_key(proxy, priv_key);
      if (result) {
	 glite_renewal_core_set_err(ctx, "globus_gsi_cred_get_key() failed");
	 goto end;
      }
   }

   if (chain) {
      result = globus_gsi_cred_get_cert_chain(proxy, chain);
      if (result) {
	 glite_renewal_core_set_err(ctx, "globus_gsi_cred_get_cert_chain() failed");
	 goto end;
      }
   }

   if (cur_proxy) {
      *cur_proxy = proxy;
      proxy = NULL;
   }

   ret = 0;
   
end:
   if (proxy)
      globus_gsi_cred_handle_destroy(proxy);
   if (result)
      ret = EDG_WLPR_ERROR_GENERIC;

   return ret;
}

int
get_proxy_base_name(glite_renewal_core_context ctx, const char *file, char **name)
{
   X509 *cert = NULL;
   EVP_PKEY *key = NULL;
   STACK_OF(X509) *chain = NULL;
   X509_NAME *subject = NULL;
   int ret;
   globus_result_t result;

   ret = load_proxy(ctx, file, &cert, &key, &chain, NULL);
   if (ret)
      return ret;

   subject = X509_NAME_dup(X509_get_subject_name(cert));

   sk_X509_insert(chain, cert, 0);
   cert = NULL;

   result = globus_gsi_cert_utils_get_base_name(subject, chain);
   if (result) {
      glite_renewal_core_set_err(ctx, "Cannot get subject name from proxy %s", file);
      ret = EDG_WLPR_ERROR_SSL; /* XXX ??? */
      goto end;
   }

   *name = X509_NAME_oneline(subject, NULL, 0);
   ret = 0;

end:
   if (cert)
      X509_free(cert);
   if (key)
      EVP_PKEY_free(key);
   if (chain)
      sk_X509_pop_free(chain, X509_free);
   if (subject)
      X509_NAME_free(subject);

   return ret;
}

int
glite_renewal_core_renew(glite_renewal_core_context ctx,
                         const char * myproxy_server,
			 unsigned int myproxy_port,
                         const char *current_proxy,
                         char **new_proxy)
{
   char tmp_proxy[FILENAME_MAX];
   int tmp_fd;
   int ret = -1;
   const char *server = NULL;
   myproxy_socket_attrs_t *socket_attrs;
   myproxy_request_t      *client_request;
   myproxy_response_t     *server_response;
   char *renewed_proxy;
   int voms_exts;

   socket_attrs = malloc(sizeof(*socket_attrs));
   memset(socket_attrs, 0, sizeof(*socket_attrs));

   client_request = malloc(sizeof(*client_request));
   memset(client_request, 0, sizeof(*client_request));

   server_response = malloc(sizeof(*server_response));
   memset(server_response, 0, sizeof(*server_response));

   myproxy_set_delegation_defaults(socket_attrs, client_request);

   edg_wlpr_Log(ctx, LOG_DEBUG, "Trying to renew proxy in %s", current_proxy);

   snprintf(tmp_proxy, sizeof(tmp_proxy), "%s.myproxy.XXXXXX", current_proxy);
   tmp_fd = mkstemp(tmp_proxy);
   if (tmp_fd == -1) {
      glite_renewal_core_set_err(ctx, "Cannot create temporary file (%s)",
                                 strerror(errno));
      return errno;
   }

   ret = get_proxy_base_name(ctx, current_proxy, &client_request->username);
   if (ret)
      goto end;

   is_voms_cert(ctx, current_proxy, &voms_exts);

   client_request->proxy_lifetime = 60 * 60 * DGPR_RETRIEVE_DEFAULT_HOURS;

   server = (myproxy_server) ? myproxy_server : socket_attrs->pshost;
   if (server == NULL) {
      glite_renewal_core_set_err(ctx, "No myproxy server specified");
      ret = EINVAL;
      goto end;
   }
   socket_attrs->pshost = strdup(server);

   socket_attrs->psport = (myproxy_port) ? myproxy_port : MYPROXY_SERVER_PORT;

   verror_clear();
   ret = myproxy_get_delegation(socket_attrs, client_request, (char *) current_proxy,
	                        server_response, tmp_proxy);
   if (ret == 1) {
      ret = EDG_WLPR_ERROR_MYPROXY;
      glite_renewal_core_set_err(ctx, "Error contacting MyProxy server for proxy %s: %s",
	                         current_proxy, verror_get_string());
      verror_clear();
      goto end;
   }

   renewed_proxy = tmp_proxy;

   if (voms_exts) {
      char tmp_voms_proxy[FILENAME_MAX];
      int tmp_voms_fd;
      
      snprintf(tmp_voms_proxy, sizeof(tmp_voms_proxy), "%s.voms.XXXXXX",
	       current_proxy);
      tmp_voms_fd = mkstemp(tmp_voms_proxy);
      if (tmp_voms_fd == -1) {
	 glite_renewal_core_set_err(ctx, "Cannot create temporary file (%s)",
	                            strerror(errno));
	 ret = errno;
	 goto end;
      }

      ret = renew_voms_creds(ctx, current_proxy, renewed_proxy, tmp_voms_proxy);
      close(tmp_voms_fd);
      if (ret) {
         glite_renewal_core_update_err(ctx,
             "Failed to renew VOMS attributes");
	 unlink(tmp_voms_proxy);
	 goto end;
      }

      renewed_proxy = tmp_voms_proxy;
      unlink(tmp_proxy);
   }

   if (new_proxy)
      *new_proxy = strdup(renewed_proxy);

   ret = 0;

end:
   if (socket_attrs->socket_fd)
      close(socket_attrs->socket_fd);
   close(tmp_fd);
   if (ret)
      unlink(tmp_proxy);
   myproxy_free(socket_attrs, client_request, server_response);

   return ret;
}

int
glite_renewal_core_init_ctx(glite_renewal_core_context *context)
{
   glite_renewal_core_context p = NULL;

   *context = NULL;

   p = calloc(1, sizeof(*p));
   if (p == NULL)
      return ENOMEM;

   p->log_level = LOG_ERR;
   p->log_dst = GLITE_RENEWAL_LOG_SYSLOG;

   *context = p;
   return 0;
}

int
glite_renewal_core_destroy_ctx(glite_renewal_core_context context)
{
   if (context == NULL)
      return 0;
   if (context->err_message);
      free(context->err_message);
   free(context);
   return 0;
}

void
glite_renewal_core_set_err(glite_renewal_core_context ctx, const char *format, ...)
{
    va_list ap;

    glite_renewal_core_reset_err(ctx);
    va_start(ap, format);
    vasprintf(&ctx->err_message, format, ap);
    va_end(ap);
}

void
glite_renewal_core_update_err(glite_renewal_core_context ctx, const char *format, ...)
{
    va_list ap;
    char *msg, *err;

    va_start(ap, format);
    vasprintf(&msg, format, ap);
    va_end(ap);

    if (ctx->err_message == NULL) {
       ctx->err_message = msg;
       return;
    }

    asprintf(&err, "%s; %s", ctx->err_message, msg);
    free(ctx->err_message);
    free(msg);
    ctx->err_message = err;
}

char *
glite_renewal_core_get_err(glite_renewal_core_context ctx)
{
    return (ctx->err_message) ? ctx->err_message : "No error";
}

void
glite_renewal_core_reset_err(glite_renewal_core_context ctx)
{
   if (ctx->err_message)
      free(ctx->err_message);
   ctx->err_message = NULL;
}

void
edg_wlpr_Log(glite_renewal_core_context context, int dbg_level, const char *format, ...)
{
   va_list ap;
   char *msg = NULL, *date, *p;
   time_t now = time(NULL);


   if (dbg_level > context->log_level)
      return;

   /* cannot handle the %m format argument specific for syslog() */
   va_start(ap, format);
   /* XXX can hardly log ENOMEM errors */
   vasprintf(&msg, format, ap);
   va_end(ap);

   switch (context->log_dst) {
      case GLITE_RENEWAL_LOG_STDOUT:
	 date = ctime(&now);
	 if ((p = strchr(date, '\n')))
	     *p = '\0';
	 printf("%s [renewd %u]: %s\n", date, getpid(), msg);
	 break;
      case GLITE_RENEWAL_LOG_SYSLOG:
	 syslog(dbg_level, "%s", msg);
	 break;
      case GLITE_RENEWAL_LOG_NONE:
      default:
	 break;
   }

   free(msg);

   return;
}
