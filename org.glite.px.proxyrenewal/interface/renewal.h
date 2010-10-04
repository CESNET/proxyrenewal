/**
 * \file proxyrenewal/renewal.h
 * \author Daniel Kouril
 * \author Miroslav Ruda
 * \brief  API for proxy renewal.
 * \version 2.0
 *
 * General rules:
 * - functions return 0 on success, nonzero on error, errror details can
 *   be found via edg_wlpr_GetErrorText()
 */

#ifndef RENEWAL_H
#define RENEWAL_H

#ident "$Header$"

#ifdef RENEWAL_HAVE_JOBID
#include "glite/wmsutils/jobid/cjobid.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define EDG_WLPR_FLAG_UNIQUE   1
#define EDG_WLPR_FLAG_UPDATE   2

typedef enum _edg_wlpr_ErrorCode {
/**
 * Base for proxy renewal specific code.
 * Start sufficently high not to collide with standard errno. */
 /* XXX see common/exception_codes.h */
    EDG_WLPR_ERROR_BASE = 1900,
    EDG_WLPR_ERROR_UNEXPECTED_EOF,
    EDG_WLPR_ERROR_GENERIC,
    EDG_WLPR_ERROR_PROTO_PARSE_ERROR,
    EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND,
    EDG_WLPR_ERROR_UNKNOWN_COMMAND,
    EDG_WLPR_ERROR_SSL,
    EDG_WLPR_ERROR_MYPROXY,
    EDG_WLPR_PROXY_NOT_REGISTERED,
    EDG_WLPR_PROXY_EXPIRED,
    EDG_WLPR_ERROR_VOMS,
    EDG_WLPR_ERROR_TIMEOUT,
    EDG_WLPR_ERROR_ERRNO,
} edg_wlpr_ErrorCode;

/**
 * Return a human readable string containg description of the errorcode
 * \retval char* pointer to a error description
 */
const char *
edg_wlpr_GetErrorText(int err_code);

/**
 * This function contacts the renewal daemon and registers the specified proxy
 * for periodic renewal.
 * \param filename IN: specification of the proxy to register.
 * \param jdl IN: JDL of the job owing the proxy. The JDL is looked for a 
 * myproxy server contact.
 * \param flags IN: one of EDG_WLPR_FLAG_UNIQUE or EDG_WLPR_FLAG_UPDATE, or
 * their bitwise OR.
 * \param repository_filename OUT: filename of registered proxy in repository.
 * \retval 0 success
 * \retval nonzero on error. Human readable form of the error can be get via
 * edg_wlpr_GetErrorText().
 */
int
edg_wlpr_RegisterProxy(
      const char * filename,
      const char *jdl,
      int flags,
      char ** repository_filename
);

/**
 * The same function as edg_wlpr_RegisterProxy() but information about the
 * myproxy server and jobid are passed as parameters instead of in JDL.
 */
#ifdef RENEWAL_HAVE_JOBID
int
edg_wlpr_RegisterProxyExt(
      const char * filename,
      const char * server,
      unsigned int port,
      edg_wlc_JobId jobid,
      int flags,
      char ** repository_filename
);
#endif

int
glite_renewal_RegisterProxy(
	const char * filename,
	const char * server,
	unsigned int port,
	const char *jobid,
	int flags,
	char ** repository_filename
);

/**
 * Unregister proxy from the renewal daemon.
 * \param jobid IN: specification of job whose proxy shall be unregistered
 * \param filename IN: (optional) specification of the proxy to unregister.
 * \retval 0 success
 * \retval nonzero on error. Human readable form of the error can be get via
 * edg_wlpr_GetErrorText().
 */
#ifdef RENEWAL_HAVE_JOBID
int
edg_wlpr_UnregisterProxy(
      edg_wlc_JobId jobid,
      const char * repository_filename
);
#endif

int
glite_renewal_UnregisterProxy(
	const char * jobid,
	const char * repository_filename
);

/**
 * Get a list of registered proxies maintained by the renewal daemon.
 * \param count OUT: number of proxies
 * \param list OUT: a list of filenames separated by '\n'
 * specifying the registered proxies. 
 * \warning The caller is responsible for freeing the data.
 * \retval 0 success
 * \retval nonzero on error. Human readable form of the error can be get via
 * edg_wlpr_GetErrorText().
 */
int
edg_wlpr_GetList(int *count, char **list);

/**
 * Get a status message about a proxy.
 * The function contacts the renewal daemon and retrieve information it 
 * maintains about the proxy.
 * \param filename IN: specification of the proxy to query
 * \param info OUT: status message.
 * \warning The caller is responsible for freeing the data.
 * \retval 0 success
 * \retval nonzero on error. Human readable form of the error can be get via
 * edg_wlpr_GetErrorText().
 */
int
edg_wlpr_GetStatus(const char *repository_filename, char **info);

/**
 * For given jobid return registered proxy filename from repository
 * \param jobid IN: specification of jobid
 * \param repository_filename OUT: proxy regitered for given jobid
 * \warning The caller is responsible for freeing the data.
 * \retval 0 success
 * \retval nonzero on error. Human readable form of the error can be get via
 * edg_wlpr_GetErrorText().
 */
#ifdef RENEWAL_HAVE_JOBID
int
edg_wlpr_GetProxy(edg_wlc_JobId jobid, char **repository_filename);
#endif

int
glite_renewal_GetProxy(
	const char * jobid,
	char **repository_filename);

#ifdef __cplusplus
}
#endif

#endif /* RENEWAL_H */
