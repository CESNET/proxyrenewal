#include "renewal_locl.h"
#include "renewd_locl.h"

#include <string.h>
#include <openssl/x509.h>

#include "glite/security/voms/voms_apic.h"

#include "glite/security/voms/newformat.h"

char * Decode(const char *, int, int *);
char **listadd(char **, char *, int);

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
      glite_renewal_log(ctx, LOG_ERR, "globus_gsi_proxy_handle_init() failed\n");
      goto end;
   }

   result = globus_gsi_cred_get_key(cur_proxy, &cur_proxy_priv_key);
   if (result) {
      glite_renewal_log(ctx, LOG_ERR, "globus_gsi_cred_get_key() failed\n");
      goto end;
   }

   /* Create and sign a new proxy */
   result = globus_gsi_cred_get_cert_type(cur_proxy, &proxy_type);
   if (result) {
      glite_renewal_log(ctx, LOG_ERR, "globus_gsi_cred_get_cert_type() failed\n");
      goto end;
   }

   result = globus_gsi_proxy_handle_set_type(proxy_handle, proxy_type);
   if (result) {
      glite_renewal_log(ctx, LOG_ERR, "globus_gsi_proxy_handle_set_type() failed\n");
      goto end;
   }

   result = globus_gsi_proxy_create_signed(proxy_handle, cur_proxy, &proxy);
   if (result) {
      glite_renewal_log(ctx, LOG_ERR, "globus_gsi_proxy_handle_init() failed\n");
      goto end;
   }

   /* Get the new proxy */
   result = globus_gsi_cred_get_cert(proxy, &new_cert);
   if (result) {
      glite_renewal_log(ctx, LOG_ERR, "globus_gsi_cred_get_cert() failed\n");
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
      glite_renewal_log(ctx, LOG_ERR, "globus_gsi_cred_set_cert() failed\n");
      goto end;
   }

   result = globus_gsi_cred_write_proxy(proxy, (char *)new_file);

end:

   return 0;
}

static int
my_VOMS_Export(glite_renewal_core_context ctx, void *buf, int buf_len, X509_EXTENSION **extension)
{
   AC *ac = NULL;
   unsigned char *p, *pp;
   AC **voms_attrs = NULL;

   p = pp = buf;
   ac = d2i_AC(NULL, &p, buf_len+1);
   if (ac == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "d2i_AC() failed\n");
      return 1;
   }

   voms_attrs = (AC **)listadd((char **)voms_attrs, (char *)ac, sizeof(AC *));

   *extension = X509V3_EXT_conf_nid(NULL, NULL, OBJ_txt2nid("acseq"),
				   (char*)voms_attrs);
   return 0;
}

static int
create_voms_command(glite_renewal_core_context ctx, struct vomsdata *vd, struct voms **voms_cert, char **command)
{
   int voms_error, ret;
   struct data **attribs;

#if 0
   VOMS_ResetOrder(vd, &voms_error);
   for (i = 2; i < argc; i++) {
      ret = VOMS_Ordering(argv[i], vd, &voms_error);
      if (ret == 0) {
	 glite_renewal_log(ctx, LOG_ERR, "VOMS_Ordering() failed\n"); 
	 return 1;
      }
   }
#endif

   if (voms_cert == NULL || *voms_cert == NULL || (*voms_cert)->std == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Invalid VOMS certificate\n");
      return 1;
   }

   attribs = (*voms_cert)->std;

   if (strcmp (attribs[0]->role, "NULL") == 0 )
      ret = asprintf(command, "G%s", attribs[0]->group);
   else
      ret = asprintf(command, "B%s:%s", attribs[0]->group, attribs[0]->role);

end:

   return 0;
}

static int
renew_voms_cert(glite_renewal_core_context ctx, struct vomsdata *vd, struct voms **voms_cert, 
                char **buf, size_t *buf_len)
{
   int voms_error = 0, i, ret, voms_version;
   struct contactdata **voms_contacts = NULL;
   char *command = NULL;

   voms_contacts = VOMS_FindByVO(vd, (*voms_cert)->voname, ctx->voms_conf, NULL, &voms_error);

   if (voms_contacts == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "VOMS_FindByVO() failed\n");
      return 1;
   }

   ret = create_voms_command(ctx, vd, voms_cert, &command);

   /* XXX the lifetime should be taken from the older proxy */
   ret = VOMS_SetLifetime(60*60*12, vd, &voms_error);

   /* XXX iterate over all servers on the list on errors */
   ret = VOMS_ContactRaw(voms_contacts[0]->host, voms_contacts[0]->port,
	                 voms_contacts[0]->contact, command, 
			 (void**) buf, buf_len, &voms_version,
			 vd, &voms_error);
   if (ret == 0) {
      glite_renewal_log(ctx, LOG_ERR, "VOMS_Contact() failed\n");
      return 1;
   }

   VOMS_DeleteContacts(voms_contacts);

   if (command)
      free(command);

   return 0;
}

static int
renew_voms_certs(glite_renewal_core_context ctx, const char *cur_file, const char *renewed_file, const char *new_file)
{
   globus_gsi_cred_handle_t cur_proxy = NULL;
   globus_gsi_cred_handle_t new_proxy = NULL;
   struct vomsdata *vd = NULL;
   struct voms **voms_cert = NULL;
   int voms_err, ret;
   X509 *cert = NULL;
   STACK_OF(X509) *chain = NULL;
   char *buf = NULL;
   size_t buf_len = 0;
   X509_EXTENSION *extension = NULL;
   char *old_env_proxy = getenv("X509_USER_PROXY");
   char *old_env_cert = getenv("X509_USER_CERT");
   char *old_env_key = getenv("X509_USER_KEY");

   setenv("X509_USER_PROXY", cur_file, 1);
   setenv("X509_USER_CERT", renewed_file, 1);
   setenv("X509_USER_KEY", renewed_file, 1);

   ret = glite_renewal_load_proxy(ctx, cur_file, &cert, NULL, &chain, &cur_proxy);
   if (ret)
      goto end;

   vd = VOMS_Init(NULL, NULL);
   if (vd == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "VOMS_Init() failed\n");
      return 1;
   }

   ret = VOMS_Retrieve(cert, chain, RECURSE_CHAIN, vd, &voms_err);
   if (ret == 0) {
      if (voms_err == VERR_NOEXT) {
	 /* no VOMS cred, no problem; continue */
	 /* XXX this part shouldn't be reachable, this call is only called
	  * if the proxy does contain VOMS attributes */
	 glite_renewal_log(ctx, LOG_ERR, "No VOMS attributes found in proxy %s\n", cur_file);
	 ret = 0;
	 goto end;
      } else {
	 glite_renewal_log(ctx, LOG_ERR, "Cannot get VOMS certificate(s) from proxy");
	 ret = 1;
	 goto end;
      }
   }

   /* XXX make sure this loop can really work for multiple voms certificates
    * embedded in the proxy */
   for (voms_cert = vd->data; voms_cert && *voms_cert; voms_cert++) {
      char *tmp, *ptr;
      size_t tmp_len;

      ret = renew_voms_cert(ctx, vd, voms_cert, &tmp, &tmp_len);
      if (ret)
	 goto end;
      ptr = realloc(buf, buf_len + tmp_len);
      if (ptr == NULL) {
         ret = ENOMEM;
         goto end;
      }
      buf = ptr;
      memcpy(buf + buf_len, tmp, tmp_len);
      buf_len += tmp_len;
   }

   if (buf == NULL) {
      /* no extension renewed, return */
      ret = 0;
      goto end;
   }

   ret = my_VOMS_Export(ctx, buf, buf_len, &extension);
   if (ret)
      goto end;

   ret = glite_renewal_load_proxy(ctx, renewed_file, NULL, NULL, NULL, &new_proxy);
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
   if (buf)
      free(buf);

   return ret;
}

int
glite_renewal_renew_voms_creds(glite_renewal_core_context ctx, const char *cur_file, const char *renewed_file, const char *new_file)
{
   return renew_voms_certs(ctx, cur_file, renewed_file, new_file);
}

int
glite_renewal_check_voms_attrs(glite_renewal_core_context ctx, const char *proxy)
{
   int ret, voms_err, present;
   X509 *cert = NULL;
   STACK_OF(X509) *chain = NULL;
   struct vomsdata *vd = NULL;

   ret = glite_renewal_load_proxy(ctx, proxy, &cert, NULL, &chain, NULL);
   if (ret)
      return 0;

   vd = VOMS_Init(NULL, NULL);
   if (vd == NULL) {
      present = 0;
      goto end;
   }

   ret = VOMS_Retrieve(cert, chain, RECURSE_CHAIN, vd, &voms_err);
   if (ret == 0) {
      present = 0;
      goto end;
   }

   present = 1;

end:
   if (cert)
      X509_free(cert);
   if (chain)
      sk_X509_pop_free(chain, X509_free);
   if (vd)
      VOMS_Destroy(vd);

   return present;
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
       glite_renewal_log(ctx, LOG_ERR, "[%d]: Unable to initialize Globus modules\n", getpid());
       return 1;
   }

   ret = renew_voms_certs(current_proxy, renewed_proxy);

   return 0;
}
#endif
