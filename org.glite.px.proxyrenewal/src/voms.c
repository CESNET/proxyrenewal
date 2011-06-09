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

static const char rcsid[] = "$Id$";

#include "renewal_locl.h"
#include "renewd_locl.h"

#include <string.h>
#include <openssl/x509.h>

#include "voms/voms_apic.h"

#include "voms/newformat.h"

char **listadd(char **, char *, int);
void listfree(char **, void (*f)(void *));

static int
generate_proxy(glite_renewal_core_context ctx, globus_gsi_cred_handle_t cur_proxy,
               X509_EXTENSION *voms_extension, const char *new_file)
{
   globus_result_t result;
   globus_gsi_proxy_handle_t proxy_handle = NULL;
   globus_gsi_cred_handle_t proxy = NULL;
   EVP_PKEY *cur_proxy_priv_key = NULL;
   X509 *new_cert = NULL;
   X509 *voms_cert = NULL;
   globus_gsi_cert_utils_cert_type_t proxy_type;

   result = globus_gsi_proxy_handle_init(&proxy_handle, NULL);
   if (result) {
      glite_renewal_core_set_err(ctx, "globus_gsi_proxy_handle_init() failed");
      goto end;
   }

   result = globus_gsi_cred_get_key(cur_proxy, &cur_proxy_priv_key);
   if (result) {
      glite_renewal_core_set_err(ctx, "globus_gsi_cred_get_key() failed");
      goto end;
   }

   /* Create and sign a new proxy */
   result = globus_gsi_cred_get_cert_type(cur_proxy, &proxy_type);
   if (result) {
      glite_renewal_core_set_err(ctx, "globus_gsi_cred_get_cert_type() failed");
      goto end;
   }

   result = globus_gsi_proxy_handle_set_type(proxy_handle, proxy_type);
   if (result) {
      glite_renewal_core_set_err(ctx, "globus_gsi_proxy_handle_set_type() failed");
      goto end;
   }

   result = globus_gsi_proxy_create_signed(proxy_handle, cur_proxy, &proxy);
   if (result) {
      glite_renewal_core_set_err(ctx, "globus_gsi_proxy_handle_init() failed");
      goto end;
   }

   /* Get the new proxy */
   result = globus_gsi_cred_get_cert(proxy, &new_cert);
   if (result) {
      glite_renewal_core_set_err(ctx, "globus_gsi_cred_get_cert() failed");
      goto end;
   }

   /* The Globus API doesn't allow to store custom X.509 extensions */
   voms_cert = X509_dup(new_cert);
   if (voms_cert->cert_info->extensions == NULL)
      voms_cert->cert_info->extensions = sk_X509_EXTENSION_new_null();
   sk_X509_EXTENSION_push(voms_cert->cert_info->extensions, voms_extension);

   /* Openssl ensures that memory containing old signature structures is unallocated */
#if 0
   X509_sign(voms_cert, cur_proxy_priv_key, proxy_handle->attrs->signing_algorithm);
#else
   X509_sign(voms_cert, cur_proxy_priv_key, EVP_md5());
#endif

   /* And put the cert back, older one is unallocated by the function */
   result = globus_gsi_cred_set_cert(proxy, voms_cert);
   if (result) {
      glite_renewal_core_set_err(ctx, "globus_gsi_cred_set_cert() failed");
      goto end;
   }

   result = globus_gsi_cred_write_proxy(proxy, (char *)new_file);

end:

   return 0;
}

static int
create_voms_command(glite_renewal_core_context ctx, struct vomsdata *vd, struct voms **voms_cert, char **command)
{
   int voms_err, i;
   struct data **attribs;
   char *str = NULL;
   char *role, *cmd = NULL, *tmp  = NULL;

   if (voms_cert == NULL || *voms_cert == NULL || (*voms_cert)->std == NULL) {
      glite_renewal_core_set_err(ctx, "Invalid VOMS certificate");
      return 1;
   }

   VOMS_ResetOrder(vd, &voms_err);
   attribs = (*voms_cert)->std;
   i = 0;
   while (attribs && attribs[i]) {
      role = NULL;
      if ((attribs[i])->role && strcmp ((attribs[i])->role, "NULL") != 0 &&
          strcmp((attribs[i])->role, "") != 0)
         role = (attribs[i])->role;

      asprintf(&str, "%s%s%s",
               (attribs[i])->group,
               (role) ? ":" : "",
               (role) ? role : "");

      if (ctx->order_attributes) 
         VOMS_Ordering(str, vd, &voms_err);

      asprintf(&tmp, "%s%s%s%s",
               (cmd) ? cmd : "",
               (cmd) ? "," : "",
               (role) ? "B" : "G",
               str);
      cmd = tmp;
      
      free(str);
      str = NULL;
      i++;
   }

   *command = cmd;
   return 0;
}

static int
get_voms_ac(glite_renewal_core_context ctx, char *server, int port,
	    char *server_subj, char *cmd, struct vomsdata *vd, AC **ac)
{
    int ret, voms_error = 0, voms_version;
    unsigned char *p;
    void *buf = NULL;
    int buf_len;
    char *err_msg;

    ret = VOMS_ContactRaw(server, port, server_subj, cmd, &buf, &buf_len,
			  &voms_version, vd, &voms_error);
    if (ret == 0) {
	err_msg = VOMS_ErrorMessage(vd, voms_error, NULL, 0);
	glite_renewal_core_set_err(ctx, "Error contacting VOMS server: %s",
				   err_msg);
	free(err_msg);
	return -1;
    }

    p = buf;
    *ac = d2i_AC(NULL, &p, buf_len);
    if (*ac == NULL) {
	glite_renewal_core_set_err(ctx, "d2i_AC() failed");
	ret = -1;
	goto end;
    }
    ret = 0;

end:
    if (buf)
	free(buf);

    return 0;
}

static int
renew_voms_cert(glite_renewal_core_context ctx, struct vomsdata *vd,
		struct voms **voms_cert, AC **ac)
{
   int voms_error = 0, ret, port = -1;
   struct contactdata **voms_contacts = NULL;
   struct contactdata **c;
   char *command = NULL;
   char *err_msg, *voms_server = NULL, *p;

   ret = create_voms_command(ctx, vd, voms_cert, &command);
   if (ret)
      return ret;

   VOMS_SetLifetime(60*60*12, vd, &voms_error);

   /* first try to contact the VOMS server that issued the original AC */
   if ((*voms_cert)->uri != NULL) {
      voms_server = strdup((*voms_cert)->uri);
      if (voms_server == NULL) {
         glite_renewal_core_set_err(ctx, "Not enough memory");
         ret = 1;
         goto end;
      }

      p = strchr(voms_server, ':');
      if (p) {
         *p++ = '\0';
         port = atoi(p);
      }
   }

   if (voms_server && port != -1 && (*voms_cert)->server != NULL) {
       ret = get_voms_ac(ctx, voms_server, port, (*voms_cert)->server,
	                 command, vd, ac);
       if (ret == 0)
	   /* success, let's finish */
	   goto end;

       edg_wlpr_Log(ctx, LOG_WARNING,
                   "Failed to get attributes from the origin VOMS server %s for '%s' (%s). "
		   "Retrying with local VOMS configuration.",
		   voms_server, (*voms_cert)->voname,
		   glite_renewal_core_get_err(ctx));
       glite_renewal_core_reset_err(ctx);
   }

   /* if the original URI doesn't work, try VOMS servers given in local
      configuration */
   voms_contacts = VOMS_FindByVO(vd, (*voms_cert)->voname, ctx->voms_conf, NULL, &voms_error);
   if (voms_contacts == NULL) {
      err_msg = VOMS_ErrorMessage(vd, voms_error, NULL, 0);
      glite_renewal_core_set_err(ctx, "Can't find configuration for VO %s: %s",
		   (*voms_cert)->voname, err_msg);
      free(err_msg);
      ret = 1;
      goto end;
   }

   ret = -1;
   for (c = voms_contacts; c && *c; c++) {
       ret = get_voms_ac(ctx, (*c)->host, (*c)->port, (*c)->contact,
			 command, vd, ac);
       if (ret == 0)
	   break;

       edg_wlpr_Log(ctx, LOG_WARNING,
		    "Failed to get attributes from VOMS server %s of VO '%s': %s",
		    (*c)->host, (*voms_cert)->voname,
		    glite_renewal_core_get_err(ctx));
       glite_renewal_core_reset_err(ctx);
   }

   if (ret)
       glite_renewal_core_set_err(ctx,
	       "Failed to contact all known VOMS servers for VO '%s'",
		(*voms_cert)->voname);

end:
   if (voms_contacts)
       VOMS_DeleteContacts(voms_contacts);
   if (command)
      free(command);
   if (voms_server)
       free(voms_server);

   return ret;
}

static int
renew_voms_certs(glite_renewal_core_context ctx, const char *cur_file, const char *renewed_file, const char *new_file)
{
   globus_gsi_cred_handle_t cur_proxy = NULL;
   globus_gsi_cred_handle_t new_proxy = NULL;
   struct vomsdata *vd = NULL;
   struct voms **voms_cert = NULL;
   int ret;
   X509 *cert = NULL;
   STACK_OF(X509) *chain = NULL;
   X509_EXTENSION *extension = NULL;
   char *old_env_proxy = getenv("X509_USER_PROXY");
   char *old_env_cert = getenv("X509_USER_CERT");
   char *old_env_key = getenv("X509_USER_KEY");
   AC *ac = NULL;
   AC **aclist = NULL, **l;

   setenv("X509_USER_PROXY", cur_file, 1);
   setenv("X509_USER_CERT", renewed_file, 1);
   setenv("X509_USER_KEY", renewed_file, 1);

   ret = load_proxy(ctx, cur_file, &cert, NULL, &chain, &cur_proxy);
   if (ret)
      goto end;

   ret = get_voms_cert(ctx, cert, chain, &vd);
   if (ret || vd == NULL)
      goto end;

   for (voms_cert = vd->data; voms_cert && *voms_cert; voms_cert++) {
      ret = renew_voms_cert(ctx, vd, voms_cert, &ac);
      if (ret)
	 goto end;

      l = (AC **)listadd((char **)aclist, (char *)ac, sizeof(AC *));
      if (l == NULL) {
	  glite_renewal_core_set_err(ctx, "Not enough memory when obtaining VOMS ACs");
	  ret = ENOMEM;
	  goto end;
      }
      aclist = l;
   }

   if (aclist == NULL) {
       ret = -1;
       glite_renewal_core_set_err(ctx, "No VOMS attributes found in proxy");
       goto end;
   }

   extension = X509V3_EXT_conf_nid(NULL, NULL, OBJ_txt2nid("acseq"), (char*)aclist);
   if (extension == NULL) {
       ret = -1;
       glite_renewal_core_set_err(ctx, "Failed to construct X.509 extension");
       goto end;
   }
   aclist = NULL;

   ret = load_proxy(ctx, renewed_file, NULL, NULL, NULL, &new_proxy);
   if (ret)
      goto end;

   ret = generate_proxy(ctx, new_proxy, extension, new_file);

end:
   (old_env_proxy) ? setenv("X509_USER_PROXY", old_env_proxy, 1) :
      		     unsetenv("X509_USER_PROXY");
   (old_env_cert) ? setenv("X509_USER_CERT", old_env_cert, 1) :
                    unsetenv("X509_USER_CERT");
   (old_env_key) ? setenv("X509_USER_KEY", old_env_key, 1) :
                   unsetenv("X509_USER_KEY");

   if (cert)
      X509_free(cert);
   if (chain)
      sk_X509_pop_free(chain, X509_free);
   if (vd)
      VOMS_Destroy(vd);
   if (cur_proxy)
      globus_gsi_cred_handle_destroy(cur_proxy);
   if (new_proxy)
      globus_gsi_cred_handle_destroy(new_proxy);
   if (extension)
       X509_EXTENSION_free(extension);
   if (aclist)
       listfree((char **)aclist, (void(*)(void *))AC_free);

   return ret;
}

int
renew_voms_creds(glite_renewal_core_context ctx, const char *cur_file, const char *renewed_file, const char *new_file)
{
   return renew_voms_certs(ctx, cur_file, renewed_file, new_file);
}

char *
get_voms_fqans(glite_renewal_core_context ctx, const char *file)
{
   struct vomsdata *voms_info = NULL;
   struct voms **voms_cert;
   STACK_OF(X509) *chain = NULL;
   X509 *cert = NULL;
   int ret;
   char *fqans = NULL, **f, *tmp;
   size_t len, flen;
   
   ret = load_proxy(ctx, file, &cert, NULL, &chain, NULL);
   if (ret)
      return NULL;

   ret = get_voms_cert(ctx, cert, chain, &voms_info);
   if (ret || voms_info == NULL) 
      goto end;

   len = 0;
   for (voms_cert = voms_info->data; voms_cert && *voms_cert; voms_cert++) {
       for (f = (*voms_cert)->fqan; f && *f; f++) {
	   flen = strlen(*f);
	   tmp = realloc(fqans, len + flen + 1);
	   if (tmp == NULL) {
	       free(fqans);
	       fqans = NULL;
	       goto end;
	   }
	   fqans = tmp;
	   if (len == 0)
	       fqans[0] = '\0';
	   else
	       strcat(fqans, ":");
	   strcat(fqans, *f);
	   len += flen + 1;
       }
   }

end:
   if (voms_info)
      VOMS_Destroy(voms_info);
   sk_X509_pop_free(chain, X509_free);
   X509_free(cert);

   return fqans;
}

int
is_voms_cert(glite_renewal_core_context ctx,
	      const char *file,
              int *present)
{
    char *fqans = get_voms_fqans(ctx, file);
    *present = (fqans != NULL);
    free(fqans);
    return 0;
}

int
get_voms_cert(glite_renewal_core_context ctx,
              X509 *cert, STACK_OF(X509) *chain, struct vomsdata **vd)
{
   struct vomsdata *voms_info = NULL;
   int voms_err, ret, voms_ret;

   /* XXX pass the vomsdir and cadir parameters */
   voms_info = VOMS_Init(NULL, NULL);
   if (voms_info == NULL) {
      glite_renewal_core_set_err(ctx, "VOMS_Init() failed, probably voms dir was not specified");
      return EDG_WLPR_ERROR_VOMS;
   }

   VOMS_SetVerificationType(VERIFY_NONE, voms_info, &voms_err);

   ret = 0;
   voms_ret = VOMS_Retrieve(cert, chain, RECURSE_CHAIN, voms_info, &voms_err);
   if (voms_ret == 0) {
      if (voms_err == VERR_NOEXT) {
         voms_info = NULL;
         ret = 0;
      } else {
         char *err_msg = VOMS_ErrorMessage(voms_info, voms_err, NULL, 0);
         glite_renewal_core_set_err(ctx, "Failed to retrieve VOMS attributes: %s",
                      err_msg);
         free(err_msg);
         ret = -1; /* XXX */
      }
   }

   if (ret == 0 && vd != NULL)
      *vd = voms_info;
   else
      VOMS_Destroy(voms_info);

   return ret;
}

#if 0
int
main(int argc, char *argv[])
{
   int ret;
   const char *current_proxy = "/tmp/x509up_u11930";
   const char *renewed_proxy = "/tmp/proxy";

   if (argc > 1)
      current_proxy = argv[1];
   if (argc > 2)
      renewed_proxy = argv[2];

   if (globus_module_activate(GLOBUS_GSI_PROXY_MODULE) != GLOBUS_SUCCESS ||
       globus_module_activate(GLOBUS_GSI_CERT_UTILS_MODULE) != GLOBUS_SUCCESS) {
       glite_renewal_core_set_err(ctx, "Unable to initialize Globus modules");
       return 1;
   }

   ret = renew_voms_certs(current_proxy, renewed_proxy);

   return 0;
}
#endif
