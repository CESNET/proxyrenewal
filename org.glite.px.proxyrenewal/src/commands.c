#include "renewal_locl.h"
#include "renewd_locl.h"

#include "glite/security/voms/voms_apic.h"

#ident "$Header$"

#define SEPARATORS ",\n"
#define RENEWAL_START_FRACTION 0.75 /* XXX */
#define RENEWAL_MIN_LIFETIME (15 * 60)

extern char *repository;
extern time_t condor_limit;
extern char *cadir;
extern char *vomsdir;
extern int voms_enabled;

static char *
strmd5(glite_renewal_core_context ctx, const char *s, unsigned char *digest);

static int
get_record_ext(glite_renewal_core_context ctx, FILE *fd, proxy_record *record, int *last_used_suffix);

static int
get_record(glite_renewal_core_context ctx, FILE *fd, proxy_record *record);

static int
store_record(glite_renewal_core_context ctx, char *basename, proxy_record *record);

static int
copy_file_content(glite_renewal_core_context ctx, FILE *in, FILE *out);

static int
copy_file(glite_renewal_core_context ctx, char *src, char *dst);

static int
get_base_filename(glite_renewal_core_context ctx, char *proxy_file, char **basefilename);

int
decode_record(glite_renewal_core_context ctx, char *line, proxy_record *record);

int
encode_record(glite_renewal_core_context ctx, proxy_record *record, char **line);

static int
open_metafile(glite_renewal_core_context ctx, char *proxy_file, FILE **fd);

void
free_record(glite_renewal_core_context ctx, proxy_record *record);

static int
realloc_prd_list(glite_renewal_core_context ctx, prd_list *list);

/* make public: */
static int
edg_wlpr_GetTokenInt(glite_renewal_core_context ctx, const char *msg, const size_t msg_len,
                     const char *key, const char *separators,
                     int req_index, int *value);

static void
record_to_response(glite_renewal_core_context ctx, int status_code, proxy_record *record,
                   edg_wlpr_Response *response);

static int
filename_to_response(glite_renewal_core_context ctx, char *filename, edg_wlpr_Response *response);




static char *
strmd5(glite_renewal_core_context ctx, const char *s, unsigned char *digest)
{
    MD5_CTX md5;
    unsigned char   d[16];
    int     i;
    static char mbuf[33];

    MD5_Init(&md5);
    MD5_Update(&md5,s,strlen(s));
    MD5_Final(d,&md5);

    if (digest)
       memcpy(digest,d,sizeof(d));
    for (i=0; i<16; i++) {
       int     dd = d[i] & 0x0f;
       mbuf[2*i+1] = dd<10 ? dd+'0' : dd-10+'a';
       dd = d[i] >> 4;
       mbuf[2*i] = dd<10 ? dd+'0' : dd-10+'a';
    }
    mbuf[32] = 0;
    return mbuf;
}

static int
get_base_filename(glite_renewal_core_context ctx, char *proxy_file, char **basefilename)
{
   char *subject = NULL;
   char file[FILENAME_MAX];
   int ret;

   assert(basefilename != NULL);

   ret = glite_renewal_get_proxy_base_name(ctx, proxy_file, &subject);
   if (ret)
      goto end;

   snprintf(file, sizeof(file), "%s/%s", repository, strmd5(ctx, subject, NULL));
   *basefilename = strdup(file); /* XXX test ENOMEM */
   ret = 0;
   
end:
   if (subject)
      free(subject);
   return ret;
}

static int
copy_file_content(glite_renewal_core_context ctx, FILE *in, FILE *out)
{
   char buf[1024];
   size_t num;
   int ret;

   while (1) {
      num = fread(buf, sizeof(*buf), sizeof(buf), in);
      if ((ret = ferror(in))) {
	 glite_renewal_log(ctx, LOG_ERR, "Reading failed: %s", strerror(errno));
	 return ret;
      }
      num = fwrite(buf, sizeof(*buf), num, out);
      if ((ret = ferror(in))) {
	 glite_renewal_log(ctx, LOG_ERR, "Writing failed: %s", strerror(errno));
	 return ret;
      }
      if (feof(in))
	 return 0;
   }
}

/* return the time interval, after which the renewal should be started */
static time_t
get_delta(glite_renewal_core_context ctx, time_t current_time, time_t start_time, time_t end_time)
{
   time_t remaining_life;
   time_t life_to_lose;
   time_t limit;
   time_t delta;

   if (RENEWAL_MIN_LIFETIME > condor_limit) {
     limit = RENEWAL_MIN_LIFETIME;
   } else {
     limit = condor_limit;
   }

   limit += RENEWAL_CLOCK_SKEW;

   if (current_time + limit >= end_time) {
     /* if the proxy is too short, renew it as soon as possible */

     if (current_time + condor_limit > end_time ) {
       glite_renewal_log(ctx, LOG_ERR, "Remaining proxy lifetime fell below the value of the Condor limit!");
     }

     return 0;
   }

   remaining_life = end_time - current_time;

   /* renewal should gain the jobs an extra lifetime of
      RENEWAL_START_FRACTION (default 3/4) of the new proxy's
      lifetime. If the time remaining on the current proxy is already
      small then the jobs may gain an extra lifetime of more than that.

      In any case, a renewal will be scheduled to happen before the
      lifetime limit.

      'life_to_lose' is the lifetime that will be lost, ie the time that
      will still remain on the current proxy when it is renewed
   */

   life_to_lose = (1.0-RENEWAL_START_FRACTION)*60*60*DGPR_RETRIEVE_DEFAULT_HOURS;

   if (life_to_lose < limit) {
     life_to_lose = limit;
   }

   delta = life_to_lose - limit;

   while( remaining_life < (limit + delta) ) {
     delta *= (1.0-RENEWAL_START_FRACTION);
   }

   life_to_lose = limit + delta;

   return (remaining_life - life_to_lose);
}

int
get_times(glite_renewal_core_context ctx, char *proxy_file, proxy_record *record)
{
   FILE *fd;
   X509 *cert = NULL;
   ASN1_UTCTIME *asn1_time = NULL;
   int ret;
   time_t current_time, start_time, end_time;

   assert(record != NULL);
   assert(proxy_file != NULL);

   fd = fopen(proxy_file, "r");
   if (fd == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Opening proxy file %s failed: %s",
	           proxy_file, strerror(errno));
      return errno;
   }

   cert = PEM_read_X509(fd, NULL, NULL, NULL);
   if (cert == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Cannot read X.509 certificate from %s",
	           proxy_file);
      ret = -1; /* XXX SSL_ERROR */
      goto end;
   }

   asn1_time = ASN1_UTCTIME_new();
   X509_gmtime_adj(asn1_time,0);
   globus_gsi_cert_utils_make_time(X509_get_notAfter(cert), &end_time);
   globus_gsi_cert_utils_make_time(X509_get_notBefore(cert), &start_time);
   current_time = time(NULL);
   ASN1_UTCTIME_free(asn1_time);
   /* if (end_time - RENEWAL_CLOCK_SKEW < current_time) { Too short proxy } */
   if (end_time + RENEWAL_CLOCK_SKEW < current_time) {
      glite_renewal_log(ctx, LOG_ERR, "Expired proxy in %s", proxy_file);
      ret = EDG_WLPR_PROXY_EXPIRED;
      goto end;
   }

   /* Myproxy seems not to do check on expiration and return expired proxies
      if credentials in repository are expired */
   X509_free(cert);
   cert = NULL;
   while (1) {
      time_t tmp_end;
      /* see http://www.openssl.org/docs/crypto/pem.html section BUGS */
      cert = PEM_read_X509(fd, NULL, NULL, NULL);
      if (cert == NULL) {
	 if (ERR_GET_REASON(ERR_peek_error()) == PEM_R_NO_START_LINE) {
	    /* End of file reached. no error */
	    ERR_clear_error();
	    break;
	 }
	 glite_renewal_log(ctx, LOG_ERR, "Cannot read additional certificates from %s",
		      proxy_file);
	 ret = -1; /* XXX SSL_ERROR */
	 goto end;
      }
      globus_gsi_cert_utils_make_time(X509_get_notAfter(cert), &tmp_end);
      if (tmp_end + RENEWAL_CLOCK_SKEW < current_time) {
	 glite_renewal_log(ctx, LOG_ERR, "Expired proxy in %s", proxy_file);
	 ret = EDG_WLPR_PROXY_EXPIRED;
	 goto end;
      }
      X509_free(cert);
      cert = NULL;
   }

   record->next_renewal = current_time + get_delta(ctx, current_time, start_time,
	 					   end_time);
   record->end_time = end_time;
   ret = 0;

end:
   fclose(fd);
   if (cert)
      X509_free(cert);

   return ret;
}

static int
copy_file(glite_renewal_core_context ctx, char *src, char *dst)
{
   FILE *from = NULL;
   FILE *tmp_to = NULL;
   int tmp_fd;
   char tmpfile[FILENAME_MAX];
   int ret;

   if (strcmp(src, dst) == 0)
      return 0; 

   from = fopen(src, "r");
   if (from == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Cannot open file %s for reading (%s)",
	           src, strerror(errno));
      return errno;
   }

   snprintf(tmpfile, sizeof(tmpfile), "%s.XXXXXX", dst);
   tmp_fd = mkstemp(tmpfile);
   if (tmp_fd == -1) {
      glite_renewal_log(ctx, LOG_ERR, "Cannot create temporary file (%s)",
	           strerror(errno));
      ret = errno;
      goto end;
   }


   tmp_to = fdopen(tmp_fd, "w");
   if (tmp_to == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Cannot associate stream with temporary file (%s)",
	           strerror(errno));
      unlink(tmpfile);
      ret = errno;
      goto end;
   }

   ret = copy_file_content(ctx, from, tmp_to);
   fclose(tmp_to);
   if (ret) {
      goto end;
   }

   ret = rename(tmpfile, dst);
   if (ret) {
      glite_renewal_log(ctx, LOG_ERR, "Cannot replace repository file %s with temporary file (%s)",
	           strerror(errno));
      unlink(tmpfile);
      ret = errno;
      goto end;
   }
   tmp_to = NULL;
      
end:
   fclose(from);
   close(tmp_fd);
   unlink(tmpfile);

   return ret;
}

void
free_record(glite_renewal_core_context ctx, proxy_record *record)
{
   int i;

   if (record == NULL)
      return;
   if (record->myproxy_server)
      free(record->myproxy_server);
   if (record->jobids.val) {
      for (i = 0; i < record->jobids.len; i++)
	 free(record->jobids.val[i]);
      free(record->jobids.val);
   }
   memset(record, 0, sizeof(*record));
}

static int
realloc_prd_list(glite_renewal_core_context ctx, prd_list *list)
{
   char **tmp;

   tmp = realloc(list->val, (list->len + 1) * sizeof(*list->val));
   if (tmp == NULL)
      return ENOMEM;
   list->val = tmp;
   list->len++;
   return 0;
}

static int
get_jobids(glite_renewal_core_context ctx, const char *msg, const size_t msg_len, proxy_record *record)
{
   int index = 0;
   int ret;
   char *value;
   char **tmp;

   memset(&record->jobids, 0, sizeof(record->jobids));
   while ((ret = edg_wlpr_GetToken(msg, msg_len, "jobid=", SEPARATORS,
	                           index, &value)) == 0) {
      tmp = realloc(record->jobids.val, (record->jobids.len + 1) * sizeof(*tmp));
      if (tmp == NULL) {
	 ret = ENOMEM;
	 break;
      }
      record->jobids.val = tmp;
      record->jobids.val[index] = value;
      record->jobids.len++;
      index++;
   }
   if (ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND) {
      if (record->jobids.len)
	 free(record->jobids.val);
      record->jobids.len = 0;
      record->jobids.val = NULL;
      return ret;
   }

   return 0;
}

static int
edg_wlpr_GetTokenInt(glite_renewal_core_context ctx, const char *msg, const size_t msg_len,
                     const char *key, const char *separators,
		     int req_index, int *value)
{
   int ret;
   char *str_value = NULL;

   ret = edg_wlpr_GetToken(msg, msg_len, key, separators, req_index, &str_value);
   if (ret)
      return ret;

   ret = edg_wlpr_DecodeInt(str_value, value);
   free(str_value);
   return ret;
}

int
decode_record(glite_renewal_core_context ctx, char *line, proxy_record *record)
{
   /* line must be ended with '\0' */
   int ret;
   size_t len;

   assert(line != NULL);
   assert(record != NULL);

   memset(record, 0, sizeof(*record));

   len = strlen(line) + 1;

   ret = edg_wlpr_GetTokenInt(ctx, line, len, "suffix=", SEPARATORS, 0,
			      &record->suffix);
   if (ret)
      return ret;

#if 0
   ret = edg_wlpr_GetTokenInt(ctx, line, len, "counter=", SEPARATORS, 0, 
	                      &record->counter);
   if (ret)
      goto end;
#endif

   ret = edg_wlpr_GetTokenInt(ctx, line, len, "unique=", SEPARATORS, 0,
			      &record->unique);
   if (ret)
      goto end;

   ret = edg_wlpr_GetTokenInt(ctx, line, len, "voms_exts=", SEPARATORS, 0,
	 		      &record->voms_exts);

   ret = edg_wlpr_GetToken(line, len, "server=", SEPARATORS, 0,
	 		   &record->myproxy_server);
   if (ret)
      goto end;

   ret = edg_wlpr_GetTokenInt(ctx, line, len, "next_renewal=", SEPARATORS, 0,
	 		      (int *)&record->next_renewal);
   if (ret)
      goto end;

   ret = edg_wlpr_GetTokenInt(ctx, line, len, "end_time=", SEPARATORS, 0,
	 		      (int *)&record->end_time);
   if (ret)
      goto end;

   ret = get_jobids(ctx, line, len, record);
   if (ret)
      goto end;

end:
   if (ret)
      free_record(ctx, record);

   return ret;
}

int
encode_record(glite_renewal_core_context ctx, proxy_record *record, char **line)
{
   char tmp_line[1024];
   size_t jobids_len = 0;
   int i;
   
   snprintf(tmp_line, sizeof(tmp_line), "suffix=%d, unique=%d, voms_exts=%d, server=%s, next_renewal=%ld, end_time=%ld",
	   record->suffix, record->unique, record->voms_exts,
	   (record->myproxy_server) ? record->myproxy_server : "",
	   record->next_renewal, record->end_time);
   for (i = 0; i < record->jobids.len; i++)
      /* alloc space for string ", jobid=<jobid>" */
      jobids_len += 2 + strlen("jobid=") + strlen(record->jobids.val[i]);

   *line = calloc(1, strlen(tmp_line) + jobids_len + 1);
   if (*line == NULL)
      return ENOMEM;

   strcat(*line, tmp_line);
   memset(tmp_line, 0, sizeof(tmp_line));

   for (i = 0; i < record->jobids.len; i++) {
      snprintf(tmp_line, sizeof(tmp_line), ", jobid=%s", record->jobids.val[i]);
      strcat(*line, tmp_line);
   }

   return 0;
}

/* Get proxy record from the index file. If no suffix is defined return a free 
   record with the smallest index */
static int
get_record_ext(glite_renewal_core_context ctx, FILE *fd, proxy_record *record, int *last_used_suffix)
{
   char line[1024];
   int last_suffix = -1;
   int ret;
   char *p;
   proxy_record tmp_record;
   time_t current_time;
   int line_num = 0;

   assert(record != NULL);
   memset(&tmp_record, 0, sizeof(tmp_record));

   current_time = time(NULL);
   while (fgets(line, sizeof(line), fd) != NULL) {
      line_num++;
      free_record(ctx, &tmp_record);
      p = strchr(line, '\n');
      if (p)
	 *p = '\0';
      ret = decode_record(ctx, line, &tmp_record);
      if (ret) {
	 glite_renewal_log(ctx, LOG_ERR, "Skipping invalid entry at line %d", line_num);
	 continue;
      }
      if (record->suffix >= 0) {
	 if (record->suffix == tmp_record.suffix) {
	    record->suffix = tmp_record.suffix;
	    record->jobids.len = tmp_record.jobids.len;
	    record->jobids.val = tmp_record.jobids.val;
	    record->unique = tmp_record.unique;
	    record->voms_exts = tmp_record.voms_exts;
	    if (record->myproxy_server)
	       free(record->myproxy_server);
	    record->myproxy_server = tmp_record.myproxy_server;
	    record->end_time = tmp_record.end_time;
	    record->next_renewal = tmp_record.next_renewal;
	    return 0;
	 } else
	    continue;
      }
      if (tmp_record.suffix > last_suffix)
	 last_suffix = tmp_record.suffix;

      /* if no particular suffix was specified get the first free record 
	 available */
      if (tmp_record.jobids.len >= MAX_PROXIES || tmp_record.unique || 
	  tmp_record.voms_exts)
	 continue;

      if (tmp_record.jobids.len == 0) {
	 /* no jobs registered for this record, so use it initialized with the
	  * parameters (currently myproxy location) provided by user */
	 record->suffix = tmp_record.suffix;
	 record->next_renewal = record->end_time = 0;
	 free_record(ctx, &tmp_record);
	 return 0;
      }

      /* Proxies with VOMS attributes require a separate record, which is not
       * shared with another proxies. The same applies it the unique flag was
       * set by the caller */
      if (record->voms_exts || record->unique)
	 continue;

      if (tmp_record.jobids.len > 0 && record->myproxy_server &&
	  strcmp(record->myproxy_server, tmp_record.myproxy_server) != 0)
	 continue;

      if (tmp_record.jobids.len > 0 &&
          current_time + condor_limit + RENEWAL_CLOCK_SKEW > tmp_record.end_time) {

	 /* skip expired proxy (or ones that are going to expire soon),
	    leaving it untouched (it will be removed after next run of the 
	    renewal process) */

	 continue;
      }

      record->suffix = tmp_record.suffix;
      record->jobids.len = tmp_record.jobids.len;
      record->jobids.val = tmp_record.jobids.val;
      record->unique = tmp_record.unique;
      record->voms_exts = tmp_record.voms_exts;
      if (record->myproxy_server)
	 free(record->myproxy_server);
      record->myproxy_server = tmp_record.myproxy_server;
      record->end_time = tmp_record.end_time;
      record->next_renewal = tmp_record.next_renewal;
      return 0;
   }

   if (last_used_suffix)
      *last_used_suffix = last_suffix;

   if (record->suffix >= 0) {
      glite_renewal_log(ctx, LOG_DEBUG, "Requested suffix %d not found in meta file",
	           record->suffix);
   }

   free_record(ctx, &tmp_record);

   return EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND;
}

static int
get_record(glite_renewal_core_context ctx, FILE *fd, proxy_record *record)
{
   return get_record_ext(ctx, fd, record, NULL);
}

static int
store_record(glite_renewal_core_context ctx, char *basename, proxy_record *record)
{
   int stored = 0;
   FILE *fd = NULL;
   int temp;
   char line[1024];
   char *new_line = NULL;
   int ret, i;
   char *p;
   proxy_record tmp_record;
   char tmp_file[FILENAME_MAX];
   char meta_file[FILENAME_MAX];
   int line_num = 0;

   assert (record != NULL);

   memset(&tmp_record, 0, sizeof(tmp_record));

   snprintf(meta_file, sizeof(meta_file), "%s.data", basename);
   snprintf(tmp_file, sizeof(tmp_file), "%s.XXXXXX", meta_file);

   temp = mkstemp(tmp_file);
   if (temp < 0)
      return errno;

   fd = fopen(meta_file, "r");
   if (fd == NULL) {
      ret = errno;
      goto end;
   }
   while (fgets(line, sizeof(line), fd) != NULL) {
      line_num++;
      free_record(ctx, &tmp_record);
      p = strchr(line, '\n');
      if (p)
	 *p = '\0';
      ret = decode_record(ctx, line, &tmp_record);
      if (ret) {
	 glite_renewal_log(ctx, LOG_ERR, "Removing invalid entry at line %d in %s", line_num, basename);
	 continue;
      }
      if (record->suffix == tmp_record.suffix &&
	  record->unique == tmp_record.unique) {
	 tmp_record.next_renewal = record->next_renewal;
	 tmp_record.end_time = record->end_time;
	 tmp_record.voms_exts = record->voms_exts;
	 if (tmp_record.myproxy_server != NULL)
	    free(tmp_record.myproxy_server);
	 tmp_record.myproxy_server = strdup(record->myproxy_server);
	 if (tmp_record.jobids.val) {
	    for (i = 0; i < tmp_record.jobids.len; i++)
	        free(tmp_record.jobids.val[i]);
	    free(tmp_record.jobids.val);
	 }
	 tmp_record.jobids.len = 0;
	 tmp_record.jobids.val = NULL;
	 for (i = 0; i < record->jobids.len; i++) {
	    realloc_prd_list(ctx, &tmp_record.jobids);
	    tmp_record.jobids.val[tmp_record.jobids.len - 1] = 
	       strdup(record->jobids.val[i]);
	 }
	 stored = 1;
      }
      ret = encode_record(ctx, &tmp_record, &new_line);
      if (ret)
	 goto end;
      dprintf(temp, "%s\n", new_line);
      free(new_line);
      new_line = NULL;
   }
   if (! stored) {
      ret = encode_record(ctx, record, &new_line);
      if (ret)
	 goto end;
      ret = dprintf(temp, "%s\n", new_line);
      free(new_line);
      new_line = NULL;
   }
   fclose(fd); fd = NULL;
   close(temp);

   ret = rename(tmp_file, meta_file);
   if (ret)
      ret = errno;

end:
   free_record(ctx, &tmp_record);
   if (fd)
      fclose(fd);
   close(temp);
   return ret;
}

static int
open_metafile(glite_renewal_core_context ctx, char *basename, FILE **fd)
{
   FILE *meta_fd;
   char meta_filename[FILENAME_MAX];

   snprintf(meta_filename, sizeof(meta_filename), "%s.data", basename);
   meta_fd = fopen(meta_filename, "a+");
   if (meta_fd == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Opening meta file %s failed (%s)",
	           meta_filename, strerror(errno));
      return errno;
   }
   rewind(meta_fd);
   *fd = meta_fd;
   glite_renewal_log(ctx, LOG_DEBUG, "Using meta file %s", meta_filename);
   return 0;
}

static int
filename_to_response(glite_renewal_core_context ctx, char *filename, edg_wlpr_Response *response)
{
   response->filenames = malloc(2 * sizeof(*response->filenames));
   if (response->filenames == NULL) {
      glite_renewal_log(ctx, LOG_DEBUG, "Not enough memory");
      return errno;
   }
   response->filenames[0] = strdup(filename);
   if (response->filenames[0] == NULL) {
      glite_renewal_log(ctx, LOG_DEBUG, "Not enough memory");
      free(response->filenames);
      return errno;
   }
   response->filenames[1] = NULL;
   return 0;
}

static void
record_to_response(glite_renewal_core_context ctx, int status_code, proxy_record *record,
        	   edg_wlpr_Response *response)
{
   /* XXX Neni struktrura proxy_record zbytecna? Mohla by se pouzivat primo
      edg_wlpr_Response? */
   response->response_code = status_code; /* XXX chyba parsovatelna pres API */
   if (status_code)
      return;

   if (response->myproxy_server) {
      response->myproxy_server = strdup(record->myproxy_server);
      if (response->myproxy_server == NULL) {
	 response->response_code = ENOMEM; /* XXX */
	 return;
      }
   }
   response->end_time = record->end_time;
   response->next_renewal_time = record->next_renewal;
   /* XXX use jobid response->counter = record->counter; */
}

int
check_proxyname(glite_renewal_core_context ctx, char *datafile, char *jobid, char **filename)
{
   proxy_record record;
   FILE *meta_fd = NULL;
   char line[1024];
   char proxy[FILENAME_MAX];
   char *p;
   int ret, i;

   memset(&record, 0, sizeof(record));

   meta_fd = fopen(datafile, "r");
   if (meta_fd == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Cannot open meta file %s (%s)",
	           datafile, strerror(errno));
      return errno;
   }

   while (fgets(line, sizeof(line), meta_fd) != NULL) {
      free_record(ctx, &record);
      p = strchr(line, '\n');
      if (p)
	 *p = '\0';
      ret = decode_record(ctx, line, &record);
      if (ret)
	 continue; /* XXX exit? */
      for (i = 0; i < record.jobids.len; i++) {
	 if (strcmp(jobid, record.jobids.val[i]) == 0) {
	    snprintf(proxy, sizeof(proxy), "%s/%s", repository, datafile);
	    p = strrchr(proxy, '.');
	    sprintf(p, ".%d", record.suffix);
	    *filename = strdup(proxy);
            free_record(ctx, &record);
	    fclose(meta_fd);
	    return 0;
	 }
      }
   }
   free_record(ctx, &record);
   fclose(meta_fd);
   return EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND;
}
      
int
find_proxyname(glite_renewal_core_context ctx, char *jobid, char **filename)
{
   DIR *dir = NULL;
   struct dirent *file;
   int ret;
   
   chdir(repository);

   dir = opendir(repository);
   if (dir == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Cannot open repository directory %s (%s)",
	           repository, strerror(errno));
      return errno;
   }

   while ((file = readdir(dir))) {
      /* read files of format `md5sum`.data, where md5sum() is of fixed length
	 32 chars */
      if (file->d_name == NULL || strlen(file->d_name) != 37 ||
	  strcmp(file->d_name + 32, ".data") != 0)
	 continue;
      ret = check_proxyname(ctx, file->d_name, jobid, filename);
      if (ret == 0) {
	 closedir(dir);
	 return 0;
      }
   }
   closedir(dir);
   glite_renewal_log(ctx, LOG_ERR, "Requested proxy is not registered");
   return EDG_WLPR_PROXY_NOT_REGISTERED;
}

#ifdef NOVOMS
int
find_voms_cert(glite_renewal_core_context ctx, char *file, int *present)
{
	*present = 0;
	return 0;
}

#else
int
find_voms_cert(glite_renewal_core_context ctx, char *file, int *present)
{
   struct vomsdata *voms_info = NULL;
   STACK_OF(X509) *chain = NULL;
   EVP_PKEY *privkey = NULL;
   X509 *cert = NULL;
   int ret, err;
   
   *present = 0;

   voms_info = VOMS_Init(vomsdir, cadir);
   if (voms_info == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "check_voms_cert(): Cannot initialize VOMS context (VOMS_Init() failed, probably voms dir was not specified)");
      return EDG_WLPR_ERROR_VOMS;
   }

   ret = glite_renewal_load_proxy(ctx, file, &cert, &privkey, &chain, NULL);
   if (ret) {
      VOMS_Destroy(voms_info);
      return ret;
   }

   ret = VOMS_Retrieve(cert, chain, RECURSE_CHAIN, voms_info, &err);
   if (ret == 1) {
      *present = 1;
   }

   VOMS_Destroy(voms_info);
   X509_free(cert);
   EVP_PKEY_free(privkey);
   sk_X509_pop_free(chain, X509_free);
   return 0;
}
#endif

void
register_proxy(glite_renewal_core_context ctx, edg_wlpr_Request *request, edg_wlpr_Response *response)
{
   proxy_record record;
   int ret;
   FILE *meta_fd = NULL;
   int last_suffix;
   char *basename = NULL;
   char filename[FILENAME_MAX];

   assert(request != NULL);
   assert(response != NULL);

   memset(&record, 0, sizeof(record));
   memset(response, 0, sizeof(*response));
   glite_renewal_log(ctx, LOG_DEBUG, "Registration request for %s", request->proxy_filename);

   if (request->proxy_filename == NULL || request->jobid == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Registration request doesn't contain registration information");
      return; /*  EINVAL; */
   }
   umask(0177);

   ret = get_base_filename(ctx, request->proxy_filename, &basename);
   if (ret)
      goto end;

   ret = open_metafile(ctx, basename, &meta_fd);
   if (ret)
      goto end;

   if (voms_enabled)
     ret = find_voms_cert(ctx, request->proxy_filename, &record.voms_exts);
     /* ignore VOMS related error */

   /* Find first free record */
   record.suffix = -1;
   record.myproxy_server = strdup(request->myproxy_server);
   ret = get_record_ext(ctx, meta_fd, &record, &last_suffix);
   fclose(meta_fd); meta_fd = NULL;
   if (ret && ret != EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND)
      goto end;

   if (ret == EDG_WLPR_ERROR_PROTO_PARSE_NOT_FOUND || record.jobids.len == 0 || request->unique || record.voms_exts) {
      /* create a new proxy file in the repository */
      int suffix;

      suffix = (record.jobids.len == 0 && record.suffix >= 0) ? 
	         record.suffix : last_suffix + 1;
      snprintf(filename, sizeof(filename), "%s.%d", basename, suffix);
      ret = copy_file(ctx, request->proxy_filename, filename);
      if (ret)
	 goto end;
      ret = get_times(ctx, filename, &record);
      if (ret)
	 goto end;
      record.suffix = suffix;
      ret = realloc_prd_list(ctx, &record.jobids);
      if (ret)
	 goto end;
      record.jobids.val[record.jobids.len - 1] = strdup(request->jobid);
      record.unique = request->unique;
      glite_renewal_log(ctx, LOG_DEBUG, "Created a new proxy file in repository (%s)",
	           filename);
   } else {
      ret = realloc_prd_list(ctx, &record.jobids);
      if (ret)
	 goto end;
      record.jobids.val[record.jobids.len - 1] = strdup(request->jobid);
      snprintf(filename, sizeof(filename), "%s.%d", basename, record.suffix);
      glite_renewal_log(ctx, LOG_DEBUG, "Inremented counter on %s", filename);
   }

   ret = store_record(ctx, basename, &record);

end:
   if (meta_fd) {
      fclose(meta_fd);
   }

   if (basename)
      free(basename);

   if (ret == 0)
      ret = filename_to_response(ctx, filename, response);
   record_to_response(ctx, ret, &record, response);
   free_record(ctx, &record);
}

void
unregister_proxy(glite_renewal_core_context ctx, edg_wlpr_Request *request, edg_wlpr_Response *response)
{
   proxy_record record;
   int ret, i, index;
   FILE *meta_fd = NULL;
   char *basename = NULL;
   char *p;
   struct stat stat_buf;

   memset(&record, 0, sizeof(record));
   glite_renewal_log(ctx, LOG_DEBUG, "Unregistration request for %s", request->jobid);

   if (request->jobid == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Unregistration request doesn't contain needed information");
      ret = EINVAL;
      goto end;
   }

   if (request->proxy_filename == NULL) {
      ret = find_proxyname(ctx, request->jobid, &request->proxy_filename);
      if (ret)
	 goto end;
   }

   ret = get_base_filename(ctx, request->proxy_filename, &basename);
   if (ret) {
      goto end;
   }

   if (strncmp(request->proxy_filename, basename, strlen(basename) != 0)) {
      glite_renewal_log(ctx, LOG_DEBUG, "Requested proxy %s is not from repository",
	           request->proxy_filename);
      ret = EDG_WLPR_PROXY_NOT_REGISTERED;
      goto end;
   }

   p = strrchr(request->proxy_filename, '.');
   if (p == NULL) {
      glite_renewal_log(ctx, LOG_DEBUG, "Requested proxy %s is not from repository",
	           request->proxy_filename);
      ret = EDG_WLPR_PROXY_NOT_REGISTERED;
      goto end;
   }

   ret = edg_wlpr_DecodeInt(p+1, &record.suffix);
   if (ret) {
      glite_renewal_log(ctx, LOG_DEBUG, "Requested proxy %s is not from repository",
	          request->proxy_filename);
      ret = EDG_WLPR_PROXY_NOT_REGISTERED;
      goto end;
   }

   ret = open_metafile(ctx, basename, &meta_fd);
   if (ret) {
      /* fill in error response */
      return;
   }

   ret = get_record(ctx, meta_fd, &record);
   if (ret)
      goto end;

   ret = EDG_WLPR_PROXY_NOT_REGISTERED;
   for (i = 0; i < record.jobids.len; i++)
      if (strcmp(request->jobid, record.jobids.val[i]) == 0) {
	 ret = 0;
	 break;
      }
   if (ret) {
      glite_renewal_log(ctx, LOG_DEBUG, "Requested proxy %s is not registered",
	           request->proxy_filename);
      goto end;
   }

   /* remove jobid from the list */
   index = i;
   free(record.jobids.val[i]);
   record.jobids.len--;
   for (i = index; i < record.jobids.len; i++)
      record.jobids.val[i] = record.jobids.val[i+1];

   if (record.jobids.len == 0) {
      record.unique = 0;
      record.voms_exts = 0;
      record.end_time = 0;
      record.next_renewal = 0;
   }

   ret = stat(request->proxy_filename, &stat_buf);
   if (ret) {
      glite_renewal_log(ctx, LOG_DEBUG, "Cannot stat file %s: (%s)",
	           request->proxy_filename, strerror(errno));
      ret = errno;
      goto end;
   }

   ret = store_record(ctx, basename, &record);
   if (ret)
      goto end;

   if (record.jobids.len == 0)
      unlink(request->proxy_filename);

end:
   if (meta_fd) {
      fclose(meta_fd);
   }
   if (basename)
      free(basename);

   if (ret == 0)
      ret = filename_to_response(ctx, request->proxy_filename, response);
   record_to_response(ctx, ret, &record, response);
   free_record(ctx, &record);
}

void
get_proxy(glite_renewal_core_context ctx, edg_wlpr_Request *request, edg_wlpr_Response *response)
{
   char *filename = NULL;
   int ret;

   memset(response, 0, sizeof(*response));

   glite_renewal_log(ctx, LOG_DEBUG, "GET request for %s", request->jobid);
   
   if (request->jobid == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "GET request doesn't contain jobid specification");
      ret = EINVAL;
      goto end;
   }

   ret = find_proxyname(ctx, request->jobid, &filename);

end:
   if (ret == 0)
      ret = filename_to_response(ctx, filename, response);
   if (filename)
      free(filename);
   response->response_code = ret;
}

void
update_db(glite_renewal_core_context ctx, edg_wlpr_Request *request, edg_wlpr_Response *response)
{
   FILE *fd = NULL;
   int tmp_fd = -1;
   int suffix = -1;
   char tmp_file[FILENAME_MAX];
   char cur_proxy[FILENAME_MAX];
   char datafile[FILENAME_MAX];
   char line[1024];
   char *new_line = NULL;
   char *basename, *proxy = NULL;
   char **entry;
   proxy_record record;
   int ret;
   char *p;
   time_t current_time;

   memset(&record, 0, sizeof(record));

   glite_renewal_log(ctx, LOG_DEBUG, "UPDATE_DB request for %s", request->proxy_filename);

   chdir(repository);
   basename = request->proxy_filename;

   snprintf(datafile, sizeof(datafile), "%s.data", basename);
   fd = fopen(datafile, "r");
   if (fd == NULL) {
      glite_renewal_log(ctx, LOG_ERR, "Cannot open meta file %s (%s)",
	           datafile, strerror(errno));
      ret = errno;
      return;
   }

   snprintf(tmp_file, sizeof(tmp_file), "%s.XXXXXX", datafile);
   tmp_fd = mkstemp(tmp_file);
   if (tmp_fd < 0) {
      glite_renewal_log(ctx, LOG_ERR, "Cannot create temporary file (%s)",
	           strerror(errno));
      ret = errno;
      goto end;
   }

   entry = request->entries;
   if (entry) {
      p = strchr(*entry, ':');
      *p = '\0';
      suffix = atoi(*entry);
      proxy = p+1;
   }

   current_time = time(NULL);

   while (fgets(line, sizeof(line), fd) != NULL) { 
      free_record(ctx, &record);
      p = strchr(line, '\n');
      if (p)
	 *p = '\0';
      ret = decode_record(ctx, line, &record);
      if (ret)
	 goto end;
      
      if (record.suffix > suffix && entry && *entry) {
	 do {
	    entry++;
	    if (entry == NULL || *entry == NULL) {
	       suffix = -1;
	       break;
	    }
	    
	    p = strchr(*entry, ':');
	    suffix = atoi(*entry);
	    proxy = p+1;
	 } while (record.suffix > suffix);
      }

      if (record.suffix == suffix) {
	 snprintf(cur_proxy, sizeof(cur_proxy), "%s.%d", basename, suffix);
	 if (proxy == NULL || *proxy == '\0') {
	    /* if proxy isn't specified use file registered currently and
	     * reschedule renewal */
	    if (record.end_time < current_time) {
	       char *server;
	       /* remove file with expired proxy and clean the record in db */
	       unlink(cur_proxy);
	       server = strdup(record.myproxy_server);
	       free_record(ctx, &record);
	       record.suffix = suffix;
	       record.myproxy_server = server;
	       glite_renewal_log(ctx, LOG_WARNING, "Removed expired proxy %s", cur_proxy);
	    } else
	       get_times(ctx, cur_proxy, &record);
	 } else {
	    ret = get_times(ctx, proxy, &record);
	    (ret == 0) ? rename(proxy, cur_proxy) : unlink(proxy);
	 }
      }
      
      ret = encode_record(ctx, &record, &new_line);
      if (ret)
	 goto end;

      dprintf(tmp_fd, "%s\n", new_line);
      free(new_line);
      new_line = NULL;
   }
   free_record(ctx, &record);

   close(tmp_fd);
   fclose(fd);

   rename(tmp_file, datafile);

   return;

end:
   if (fd)
      fclose(fd);
   unlink(tmp_file);
   if (tmp_fd > 0)
      close(tmp_fd);
   free_record(ctx, &record);

   return;
}
