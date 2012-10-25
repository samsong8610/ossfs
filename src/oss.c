#include <glib.h>
#include <glib/gstdio.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <libxml/xmlreader.h>
#include <locale.h>

#include "oss.h"

static gchar *sign(const OssService *service, const gchar *method, const gchar *content_md5, const gchar *content_type, const gchar *date, GHashTable *header, const gchar *path);
static void authorize(const OssService *service, const gchar *method, const gchar *content_md5, const gchar *content_type, GHashTable *header, const gchar *path);
static gchar *get_current_date_time_gmt();
static const gchar* calculate_md5(const gchar *content, gsize len);
static GSList* process_list_all_my_buckets_result(FILE *f);
static OssError* process_error(FILE *f);
static OssListBucketResult* process_list_bucket_result(FILE *f);
static HttpClient* get_or_create_client(OssService *service);
static OssBucket* process_access_control_policy(FILE *f);
static const gchar* get_canonical_resource(OssObject *object);
static void process_copy_object_result(FILE *f, OssObject *object);

OssService *oss_service_new(const gchar *bucket, GHashTable *conf)
{
  OssService *result;
  gpointer value;

  result = g_new0(OssService, 1);
  result->bucket = bucket;

  if (conf) {
    if (value = g_hash_table_lookup(conf, OSS_CONFIG_SCHEME)) {
      result->scheme = (const gchar*)value;
    }
    if (value = g_hash_table_lookup(conf, OSS_CONFIG_HOST)) {
      result->host = (const gchar*)value;
    }
    if (value = g_hash_table_lookup(conf, OSS_CONFIG_PORT)) {
      result->port = (gint)g_ascii_strtoull((gchar*)value, NULL, 10);
    }
    if (value = g_hash_table_lookup(conf, OSS_CONFIG_PUBLIC)) {
      if (g_strcmp0((gchar*)value, "1") == 0 ||
	  g_strcmp0((gchar*)value, "TRUE") == 0 ||
	  g_strcmp0((gchar*)value, "True") == 0 ||
	  g_strcmp0((gchar*)value, "true") == 0) {
	result->is_public = TRUE;
      }
    }
    if (value = g_hash_table_lookup(conf, OSS_CONFIG_ACCESSID)) {
      result->access_id = (const gchar*)value;
    }
    if (value = g_hash_table_lookup(conf, OSS_CONFIG_ACCESSKEY)) {
      result->access_key = (const gchar*)value;
    }
  }

  if (result->scheme == NULL) {
    result->scheme = "http";
  }
  if (result->host == NULL) {
    result->host = "oss.aliyuncs.com";
  }
  if (result->port == 0) {
    result->port = 80;
  }
  if (result->access_id == NULL) {
    result->access_id = "3z4om38nk29w60axe69khvqg";
  }
  if (result->access_key == NULL) {
    result->access_key = "OJWbkW+U5ohhQ/rxYoDKojkqkZE=";
  }
  result->sha1 = EVP_sha1();

  result->client = NULL;

  return result;
}

void oss_service_destroy(OssService *service)
{
  g_return_if_fail(service != NULL);

  if (service->client) {
    http_client_destroy((HttpClient*)service->client);
    service->client = NULL;
  }
  g_free(service);
}

OssBucket* oss_bucket_new(const gchar *name, const gchar *acl)
{
  OssBucket *result = NULL;
  g_return_val_if_fail(name != NULL, NULL);

  result = g_new(OssBucket, 1);
  if (result) {
    result->name = g_strdup(name);
    if (acl) {
      result->acl = g_strdup(acl);
    } else {
      result->acl = NULL;
    }
    result->creation_date = NULL;
    result->owner = NULL;
  }
  return result;
}

void oss_bucket_destroy(OssBucket *bucket)
{
  g_return_if_fail(bucket != NULL);
  if (bucket->name) {
    g_free(bucket->name);
    bucket->name = NULL;
  }
  if (bucket->creation_date) {
    g_free(bucket->creation_date);
    bucket->creation_date = NULL;
  }
  if (bucket->acl) {
    g_free(bucket->acl);
    bucket->acl = NULL;
  }
  if (bucket->owner) {
    if (bucket->owner->id) {
      g_free(bucket->owner->id);
    }
    if (bucket->owner->display_name) {
      g_free(bucket->owner->display_name);
    }
    g_free(bucket->owner);
    bucket->owner = NULL;
  }
  g_free(bucket);
}

OssObject* oss_object_new(const gchar *key)
{
  OssObject *result;

  result = g_new0(OssObject, 1);
  result->key = g_strdup(key);
  result->meta = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);

  return result;
}

OssObject* oss_object_new_file(const gchar *key, const gchar *path, const gchar *mode)
{
  gchar *pos;
  OssObject *result;
  GStatBuf stbuf;

  if (key == NULL) {
    pos = g_strrstr(path, G_DIR_SEPARATOR_S);
    if (pos) key = pos+1;
  }
  result = oss_object_new(key);
  result->content = g_fopen(path, mode);
  if (g_lstat(path, &stbuf) == 0) {
    result->size = stbuf.st_size;
  }
  return result;
}

void oss_object_destroy(OssObject *object)
{
  g_return_if_fail(object != NULL);

  if (object->key) {
    g_free(object->key);
    object->key = NULL;
  }
  if (object->last_modified) {
    g_free(object->last_modified);
    object->last_modified = NULL;
  }
  if (object->etag) {
    g_free(object->etag);
    object->etag = NULL;
  }
  if (object->type) {
    g_free(object->type);
    object->type = NULL;
  }
  if (object->storage_class) {
    g_free(object->storage_class);
    object->storage_class = NULL;
  }
  if (object->owner) {
    if (object->owner->id) {
      g_free(object->owner->id);
      object->owner->id = NULL;
    }
    if (object->owner->display_name) {
      g_free(object->owner->display_name);
      object->owner->display_name = NULL;
    }
    g_free(object->owner);
    object->owner = NULL;
  }
  if (object->content) {
    fclose(object->content);
    object->content = NULL;
  }
  if (object->meta) {
    g_hash_table_destroy(object->meta);
    object->meta = NULL;
  }
}

GSList *oss_service_get(OssService *service, GError **error)
{
  GSList *result = NULL;
  const gchar *res = "/";
  HttpClient *client;

  g_return_val_if_fail(error == NULL || *error == NULL, NULL);
  g_return_val_if_fail(service != NULL && service->host != NULL, NULL);
  client = get_or_create_client(service);

  GHashTable *header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  GHashTable *resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);

  authorize(service, HTTP_METHOD_GET, NULL, NULL, header, res);

  FILE *f = tmpfile();
  if (f == NULL) {
    g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
    return result;
  }
  *error = NULL;
  gint r = http_client_get(client, res, header, resp_header, NULL, f, error);
  if (!r) {
    rewind(f);
    result = process_list_all_my_buckets_result(f);
  } else {
    /* TODO process error message */
  }

  fflush(f);
  fclose(f);

  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return result;
}

void oss_service_get_destroy(GSList *buckets)
{
  GSList *p;
  OssBucket *bucket;
  OssOwner *owner;
  gboolean freed = FALSE;

  if (buckets) {
    p = buckets;
    while (p) {
      bucket = (OssBucket*)p->data;
      if (p) {
	g_free(bucket->name);
	bucket->name = NULL;
	g_free(bucket->creation_date);
	bucket->creation_date = NULL;
	g_free(bucket->acl);
	bucket->acl = NULL;
	owner = bucket->owner;
	if (owner && !freed) {
	  g_free(owner->id);
	  owner->id = NULL;
	  g_free(owner->display_name);
	  owner->display_name = NULL;
	  g_free(owner);
	  freed = TRUE;
	}
	bucket->owner = NULL;
	g_free(bucket);
	p->data = NULL;
      }
      p = p->next;
    }
    g_slist_free(buckets);
  }
}

gint oss_bucket_put(OssService *service, OssBucket *bucket, GError **error)
{
  int len;
  GRegex *regex;
  GMatchInfo *match_info;
  HttpClient *client;
  GString *res;
  gint r;
  OssError *err;

  g_return_val_if_fail(bucket != NULL && bucket->name != NULL, -1);
  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  len = strlen(bucket->name);
  if (len < 3 || len > 63) {
    g_set_error_literal(error, OSS_ERROR, OSS_ERROR_INVALID_BUCKET_NAME, "Bucket name length must be between 3 and 63 characters.");
    return -1;
  }
   
  regex = g_regex_new("^[a-z0-9][a-z0-9\\-]*$", 0, 0, NULL);
  g_regex_match(regex, (const gchar*)bucket->name, 0, &match_info);
  if (!g_match_info_matches(match_info)) {
    g_match_info_free(match_info);
    g_regex_unref(regex);
    g_set_error_literal(error, OSS_ERROR, OSS_ERROR_INVALID_BUCKET_NAME, "Bucket name does not match naming rule.");
    return -1;
  }
  g_match_info_free(match_info);
  g_regex_unref(regex);

  service->bucket = bucket->name;
  client = get_or_create_client(service);

  res = g_string_new("/");

  GHashTable *header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  GHashTable *resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);
  g_hash_table_insert(header, g_strdup("Expect"), g_strdup(""));/*disable Expect header. */
  if (bucket->acl) {
    g_hash_table_insert(header, g_strdup("x-oss-acl"), g_strdup(bucket->acl));
  }

  authorize(service, HTTP_METHOD_PUT, NULL, NULL, header, res->str);

  FILE *f = tmpfile();
  if (f == NULL) {
    g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
    g_string_free(res, TRUE);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  }
  r = http_client_put(client, res->str, header, resp_header, NULL, NULL, NULL, f, NULL);
  if (r) {
    *error = NULL;
    if (r >= 400 && r < 500) {
      err = process_error(f);
      if (g_strcmp0(err->code, "BucketAlreadyExists") == 0) {
	g_set_error(error, OSS_ERROR, OSS_ERROR_BUCKET_ALREADY_EXISTS, "%s", err->message);
      } else if (g_strcmp0(err->code, "InvalidBucketName") == 0) {
	g_set_error_literal(error, OSS_ERROR, OSS_ERROR_INVALID_BUCKET_NAME, err->message);
      } else if (g_strcmp0(err->code, "AccessDenied") == 0) {
	g_set_error_literal(error, OSS_ERROR, OSS_ERROR_ACCESS_DENIED, err->message);
      } else if (g_strcmp0(err->code, "TooManyBuckets") == 0) {
	g_set_error_literal(error, OSS_ERROR, OSS_ERROR_TOO_MANY_BUCKETS, err->message);
      } else if (g_strcmp0(err->code, "InvalidArgument") == 0) {
	g_set_error_literal(error, OSS_ERROR, OSS_ERROR_INVALID_ARGUMENT, err->message);
      } else {
	g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, err->message);
      }

      g_free(err);
      err = NULL;
    } else if (r == -1) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, client->error_message);
    } else {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, client->status_message);
    }

    fclose(f);
    g_string_free(res, TRUE);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  }

  fclose(f);
  g_string_free(res, TRUE);
  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return 0;
}

gint oss_bucket_put_acl(OssService *service, OssBucket *bucket, GError **error)
{
  return oss_bucket_put(service, bucket, error);
}

OssListBucketResult* oss_bucket_get(OssService *service, const gchar *resource, GError **error)
{
  HttpClient *client;
  GString *res;
  gint r;
  OssListBucketResult *result = NULL;
  OssError *err = NULL;
  GError *ce;

  g_return_val_if_fail(error == NULL || *error == NULL, NULL);

  client = get_or_create_client(service);

  if (g_str_has_prefix(resource, "/")) {
    res = g_string_new(resource);
  } else {
    res = g_string_new("/");
    g_string_append(res, resource);
  }

  GHashTable *header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  GHashTable *resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);
  g_hash_table_insert(header, g_strdup("Expect"), g_strdup(""));/*disable Expect header. */

  authorize(service, HTTP_METHOD_GET, NULL, NULL, header, res->str);

  FILE *f = tmpfile();
  if (f == NULL) {
    g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
    g_string_free(res, TRUE);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return NULL;
  }

  r = http_client_get(client, res->str, header, resp_header, NULL, f, error);
  if (r) {
    ce = g_error_copy(*error);
    *error = NULL;
    err = process_error(f);
    if (g_strcmp0(err->code, "NoSuchBucket") == 0) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_NO_SUCH_BUCKET, err->message);
    } else if (g_strcmp0(err->code, "AccessDenied") == 0) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_ACCESS_DENIED, err->message);
    } else if (g_strcmp0(err->code, "InvalidArgument") == 0) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_INVALID_ARGUMENT, err->message);
    } else {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, ce->message);
    }
    g_error_free(ce);
  } else {
    result = process_list_bucket_result(f);
  }

  fflush(f);
  fclose(f);
  g_string_free(res, TRUE);
  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return result;
}

void oss_bucket_get_destroy(OssListBucketResult *list)
{
  GSList *cur;
  OssObject *obj;
  g_return_if_fail(list != NULL);

  if (list->name) {
    g_free(list->name);
    list->name = NULL;
  }
  if (list->prefix) {
    g_free(list->prefix);
    list->prefix = NULL;
  }
  if (list->marker) {
    g_free(list->marker);
    list->marker = NULL;
  }
  if (list->delimiter) {
    g_free(list->delimiter);
    list->delimiter = NULL;
  }
  cur = list->contents;
  while (cur) {
    obj = (OssObject*)cur->data;
    cur->data = NULL;
    oss_object_destroy(obj);
    cur = cur->next;
  }
  g_free(list);
}

OssBucket* oss_bucket_get_acl(OssService *service, const gchar *bucket, GError **error)
{
  OssBucket *result = NULL;
  GHashTable *header, *resp_header;
  gint r;
  GString *res;
  HttpClient *client = NULL;

  g_return_val_if_fail(error == NULL || *error == NULL, NULL);

  service->bucket = bucket;
  client = get_or_create_client(service);
  res = g_string_new("/?acl");

  header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);
  g_hash_table_insert(header, g_strdup("Expect"), g_strdup(""));/*disable Expect header. */

  authorize(service, HTTP_METHOD_GET, NULL, NULL, header, res->str);

  FILE *f = tmpfile();
  if (f == NULL) {
    g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
    g_string_free(res, TRUE);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return NULL;
  }

  r = http_client_get(client, res->str, header, resp_header, NULL, f, error);
  if (r) {
    /* TODO process error */

  } else {
    result = process_access_control_policy(f);
    result->name = g_strdup(bucket);
    result->creation_date = NULL;
  }

  fflush(f);
  fclose(f);
  g_string_free(res, TRUE);
  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return result;
}

gint oss_bucket_delete(OssService *service, const gchar *bucket, GError **error)
{
  GHashTable *header, *resp_header;
  gint r;
  GString *res;
  HttpClient *client = NULL;
  OssError *err;

  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  service->bucket = bucket;
  client = get_or_create_client(service);
  res = g_string_new("/");
  
  header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);
  g_hash_table_insert(header, g_strdup("Expect"), g_strdup(""));/*disable Expect header. */

  authorize(service, HTTP_METHOD_DELETE, NULL, NULL, header, res->str);

  FILE *f = tmpfile();
  if (f == NULL) {
    g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
    g_string_free(res, TRUE);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  }

  r = http_client_delete(client, res->str, header, resp_header, NULL, f, NULL);
  if (r) {
    err = process_error(f);
    *error = NULL;
    if (r >= 400 && r < 500) {
      if (g_strcmp0(err->code, "NoSuchBucket") == 0) {
	g_set_error_literal(error, OSS_ERROR, OSS_ERROR_NO_SUCH_BUCKET, err->message);
      } else if (g_strcmp0(err->code, "BucketNotEmpty") == 0) {
	g_set_error_literal(error, OSS_ERROR, OSS_ERROR_BUCKET_NOT_EMPTY, err->message);
      } else if (g_strcmp0(err->code, "AccessDenied") == 0) {
	g_set_error_literal(error, OSS_ERROR, OSS_ERROR_ACCESS_DENIED, err->message);
      } else {
	g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, client->error_message);
      }
    } else if (r == -1) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, client->error_message);
    } else {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, client->status_message);
    }

    fflush(f);
    fclose(f);
    g_string_free(res, TRUE);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  }

  fflush(f);
  fclose(f);
  g_string_free(res, TRUE);
  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return 0;
}

gint oss_object_put(OssService *service, OssObject *object, GError **error)
{
  int len;
  HttpClient *client;
  const gchar *res;
  gint r;
  OssError *err;
  GHashTableIter iter;
  gpointer key, value;

  g_return_val_if_fail(object != NULL && object->key != NULL, -1);
  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  len = strlen(object->key);
  if (len < OSS_OBJECT_KEY_MIN || len > OSS_OBJECT_KEY_MAX) {
    *error = g_error_new_literal(OSS_ERROR, OSS_ERROR_INVALID_ARGUMENT, "InvalidKey");
    return -1;
  }
   
  client = get_or_create_client(service);

  res = get_canonical_resource(object);

  GHashTable *header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  GHashTable *resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);
  g_hash_table_insert(header, g_strdup("Expect"), g_strdup(""));/*disable Expect header. */
  if (object->meta) {
    g_hash_table_iter_init(&iter, object->meta);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      if (g_strcmp0((gchar*)key, "Cache-Control") == 0 ||
	  g_strcmp0((gchar*)key, "Expires") == 0 ||
	  g_strcmp0((gchar*)key, "Content-Encoding") == 0 ||
	  g_strcmp0((gchar*)key, "Content-Disposition") == 0 ||
	  g_str_has_prefix((gchar*)key, "x-oss-")) {
	g_hash_table_insert(header, g_strdup((gchar*)key), g_strdup((gchar*)value));
      }
    }
  }

  /*TODO content md5 */
  authorize(service, HTTP_METHOD_PUT, NULL, NULL, header, res);

  FILE *f = tmpfile();
  if (f == NULL) {
    g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
    g_free((gpointer)res);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  }
  r = http_client_put(client, res, header, resp_header, NULL, object->content, NULL, f, NULL);
  if (r) {
    if (r == 404) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_NO_SUCH_BUCKET, "NoSuchBucket");
    } else if (r == 403) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_ACCESS_DENIED, "AccessDenied");
    } else {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, client->error_message);
    }

    g_free((gpointer)res);
    fclose(f);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  }

  fclose(f);
  g_free((gpointer)res);
  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return 0;
}

gint oss_object_get(OssService *service, OssObject *object, GError **error)
{
  HttpClient *client;
  const gchar *res;
  gint r, len;
  FILE *f = NULL;
  GHashTableIter iter;
  gpointer key, value;
  OssError *err;

  g_return_val_if_fail(object != NULL && object->key != NULL, -1);
  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  len = strlen(object->key);
  if (len < OSS_OBJECT_KEY_MIN || len > OSS_OBJECT_KEY_MAX) {
    *error = g_error_new_literal(OSS_ERROR, OSS_ERROR_INVALID_OBJECT_NAME, "Object name is too long");
    return -1;
  }

  client = get_or_create_client(service);

  res = get_canonical_resource(object);

  GHashTable *header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  GHashTable *resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);
  g_hash_table_insert(header, g_strdup("Expect"), g_strdup(""));/*disable Expect header. */
  if (object->meta) {
    g_hash_table_iter_init(&iter, object->meta);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      if (g_strcmp0((gchar*)key, "Range") == 0 ||
	  g_strcmp0((gchar*)key, "If-Modified-Since") == 0 ||
	  g_strcmp0((gchar*)key, "If-Unmodified-Since") == 0 ||
	  g_strcmp0((gchar*)key, "If-Match") == 0 ||
	  g_strcmp0((gchar*)key, "If-None-Match") == 0 ||
	  g_str_has_prefix((gchar*)key, "x-oss-")) {
	g_hash_table_insert(header, g_strdup((gchar*)key), g_strdup((gchar*)value));
      }
    }
  }

  authorize(service, HTTP_METHOD_GET, NULL, NULL, header, res);

  if (object->content == NULL) {
    f = tmpfile();
    if (f == NULL) {
      g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
      g_free((gpointer)res);
      g_hash_table_destroy(header);
      g_hash_table_destroy(resp_header);
      return -1;
    }
    object->content = f;
  } else {
    f = object->content;
  }

  r = http_client_get(client, res, header, resp_header, NULL, f, NULL);
  if (r) {
    /* TODO process error */
    err = process_error(f);
    error = NULL;
    if (r == 404) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_NO_SUCH_KEY, err->message);
    } else {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, client->error_message);
    }

    fflush(f);
    g_free((gpointer)res);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  } else {
    rewind(f);
    g_hash_table_iter_init(&iter, resp_header);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      if (g_strcmp0((gchar*)key, "Last-Modified") == 0) {
	object->last_modified = g_strdup(value);
      } else if (g_strcmp0((gchar*)key, "ETag") == 0) {
	object->etag = g_strdup(value);
      } else if (g_strcmp0((gchar*)key, "Content-Length") == 0) {
	object->size = g_ascii_strtoull((gchar*)value, NULL, 10);
      } else if (g_str_has_prefix((gchar*)key, "x-oss-")) {
	if (object->meta == NULL) {
	  object->meta = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
	}
	g_hash_table_insert(object->meta, g_strdup(key), g_strdup(value));
      }
    }
  }

  fflush(f);
  rewind(f);
  g_free((gpointer)res);
  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return 0;
}

gint oss_object_copy(OssService *service, OssObject *object, const gchar *src_bucket, OssObject *src, GError **error)
{
  int len;
  HttpClient *client;
  const gchar *res;
  gint r;
  OssError *err;
  GHashTableIter iter;
  gpointer key, value;
  GString *copy_src;

  g_return_val_if_fail(object != NULL && object->key != NULL, -1);
  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  len = strlen(object->key);
  if (len < OSS_OBJECT_KEY_MIN || len > OSS_OBJECT_KEY_MAX) {
    *error = g_error_new_literal(OSS_ERROR, OSS_ERROR_INVALID_ARGUMENT, "InvalidKey");
    return -1;
  }
   
  client = get_or_create_client(service);

  res = get_canonical_resource(object);

  GHashTable *header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  GHashTable *resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);
  g_hash_table_insert(header, g_strdup("Expect"), g_strdup(""));/*disable Expect header. */
  g_hash_table_iter_init(&iter, object->meta);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    if (g_strcmp0((gchar*)key, "Cache-Control") == 0 ||
	g_strcmp0((gchar*)key, "Expires") == 0 ||
	g_strcmp0((gchar*)key, "Content-Encoding") == 0 ||
	g_strcmp0((gchar*)key, "Content-Disposition") == 0 ||
	g_str_has_prefix((gchar*)key, "x-oss-")) {
      g_hash_table_insert(header, g_strdup((gchar*)key), g_strdup((gchar*)value));
    }
  }
  if (src == NULL) {
    g_hash_table_insert(header, g_strdup("x-oss-copy-source"), g_strdup(res));
  } else {
    if (g_str_has_prefix(src_bucket, "/")) {
      copy_src = g_string_new(src_bucket);
    } else {
      copy_src = g_string_new("/");
      g_string_append(copy_src, src_bucket);
    }
    g_string_append(copy_src, get_canonical_resource(src));
    g_hash_table_insert(header, g_strdup("x-oss-copy-source"), (gpointer)copy_src->str);
    g_string_free(copy_src, FALSE);
    if (src->meta != NULL && g_hash_table_size(src->meta)) {
      g_hash_table_iter_init(&iter, src->meta);
      while (g_hash_table_iter_next(&iter, &key, &value)) {
	if (g_str_has_prefix((gchar*)key, "x-oss-")) {
	  g_hash_table_insert(header, g_strdup((gchar*)key), g_strdup((gchar*)value));
	}
      }
    }
  }

  /*TODO content md5 */
  authorize(service, HTTP_METHOD_PUT, NULL, NULL, header, res);

  FILE *f = tmpfile();
  if (f == NULL) {
    g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
    g_free((gpointer)res);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  }
  r = http_client_put(client, res, header, resp_header, NULL, NULL, NULL, f, NULL);
  if (r) {
    if (r == 404) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_NO_SUCH_BUCKET, "NoSuchBucket");
    } else if (r == 403) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_ACCESS_DENIED, "AccessDenied");
    } else {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, client->error_message);
    }

    fclose(f);
    g_free((gpointer)res);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  } else {
    process_copy_object_result(f, object);
  }

  fclose(f);
  g_free((gpointer)res);
  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return 0;
}

gint oss_object_head(OssService *service, OssObject *object, GError **error)
{
  HttpClient *client;
  const gchar *res;
  gint r, len;
  FILE *f = NULL;
  GHashTableIter iter;
  gpointer key, value;
  GError *err;

  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  if (object == NULL || object->key == NULL) {
    *error = g_error_new_literal(OSS_ERROR, OSS_ERROR_INVALID_ARGUMENT, "Object or name is NULL");
    return -1;
  }
  len = strlen(object->key);
  if (len < OSS_OBJECT_KEY_MIN || len > OSS_OBJECT_KEY_MAX) {
    *error = g_error_new_literal(OSS_ERROR, OSS_ERROR_INVALID_OBJECT_NAME, "InvalidObjectName");
    return -1;
  }

  client = get_or_create_client(service);

  res = get_canonical_resource(object);

  GHashTable *header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  GHashTable *resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);
  g_hash_table_insert(header, g_strdup("Expect"), g_strdup(""));/*disable Expect header. */
  if (object->meta) {
    g_hash_table_iter_init(&iter, object->meta);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      if (g_strcmp0((gchar*)key, "Range") == 0 ||
	  g_strcmp0((gchar*)key, "If-Modified-Since") == 0 ||
	  g_strcmp0((gchar*)key, "If-Unmodified-Since") == 0 ||
	  g_strcmp0((gchar*)key, "If-Match") == 0 ||
	  g_strcmp0((gchar*)key, "If-None-Match") == 0 ||
	  g_str_has_prefix((gchar*)key, "x-oss-")) {
	g_hash_table_insert(header, g_strdup((gchar*)key), g_strdup((gchar*)value));
      }
    }
  }

  authorize(service, HTTP_METHOD_HEAD, NULL, NULL, header, res);

  r = http_client_head(client, res, header, resp_header, error);
  if (r) {
    err = g_error_copy(*error);
    *error = NULL;
    if (r == 403) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_ACCESS_DENIED, (err)->message);
    }else if (r == 404) {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_NO_SUCH_KEY, (err)->message);
    } else {
      g_set_error_literal(error, OSS_ERROR, OSS_ERROR_FAILED, client->error_message);
    }
    
    g_free((gpointer)res);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    g_error_free(err);
    return -1;
  } else {
    g_hash_table_iter_init(&iter, resp_header);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      if (g_strcmp0((gchar*)key, "Last-Modified") == 0) {
	object->last_modified = g_strdup(value);
      } else if (g_strcmp0((gchar*)key, "ETag") == 0) {
	object->etag = g_strdup(value);
      } else if (g_strcmp0((gchar*)key, "Content-Length") == 0) {
	object->size = g_ascii_strtoull((gchar*)value, NULL, 10);
      } else if (g_str_has_prefix((gchar*)key, "x-oss-")) {
	if (object->meta == NULL) {
	  object->meta = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
	}
	g_hash_table_insert(object->meta, g_strdup(key), g_strdup(value));
      }
    }
  }

  g_free((gpointer)res);
  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return 0;
}

gint oss_object_delete(OssService *service, const gchar *object,  GError **error)
{
  HttpClient *client;
  const gchar *res;
  gint r, len;
  FILE *f = NULL;
  OssObject *tmp;
  OssError *err;

  g_return_val_if_fail(object != NULL, -1);
  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  len = strlen(object);
  if (len < OSS_OBJECT_KEY_MIN || len > OSS_OBJECT_KEY_MAX) {
    *error = g_error_new_literal(OSS_ERROR, OSS_ERROR_INVALID_ARGUMENT, "InvalidKey");
    return -1;
  }

  client = get_or_create_client(service);

  tmp = g_new(OssObject, 1);
  tmp->key = (gchar*)object;
  res = get_canonical_resource(tmp);
  g_free(tmp);
  tmp = NULL;

  GHashTable *header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  GHashTable *resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);
  g_hash_table_insert(header, g_strdup("Expect"), g_strdup(""));/*disable Expect header. */

  authorize(service, HTTP_METHOD_DELETE, NULL, NULL, header, res);

  f = tmpfile();
  if (f == NULL) {
    g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
    g_free((gpointer)res);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  }
  r = http_client_delete(client, res, header, resp_header, NULL, f, NULL);
  if (r) {
    /* TODO process error */

    fclose(f);
    f = NULL;
    g_free((gpointer)res);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  }

  fflush(f);
  fclose(f);
  g_free((gpointer)res);
  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return 0;
}

gint oss_object_delete_multiple(OssService *service, gboolean quiet, GError **error, ...)
{
  va_list ap;
  const gchar *object;
  HttpClient *client;
  const gchar *res;
  gint r, len;
  FILE *f = NULL, *fpost = NULL;
  GString *buf;
  gchar *encoded;
  gchar *md5;
  OssError *err;

  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  res = "/?delete";

  fpost = tmpfile();
  if (fpost == NULL) {
    g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
    return -1;
  }
  va_start(ap, error);
  buf = g_string_sized_new(1024);
  g_string_append(buf, "<Delete><Quiet>");
  if (quiet) {
    g_string_append(buf, "true");
  } else {
    g_string_append(buf, "false");
  }
  g_string_append(buf, "</Quiet>");
  while (object = va_arg(ap, gchar *)) {
    len = strlen(object);
    if (len < OSS_OBJECT_KEY_MIN || len > OSS_OBJECT_KEY_MAX) {
      *error = g_error_new_literal(OSS_ERROR, OSS_ERROR_INVALID_ARGUMENT, "InvalidKey");
      return -1;
    } else {
      g_string_append(buf, "<Object><Key>");
      g_string_append(buf, object);
      g_string_append(buf, "</Key></Object>");
    }
  }
  g_string_append(buf, "</Delete>");
  va_end(ap);
  /*
    encoded = g_uri_escape_string(buf->str, NULL, FALSE);
  */
  encoded = "<Delete>"
"<Quiet>false</Quiet>"
"<Object>"
"<Key>multipart.data</Key>"
"</Object>"
"<Object>"
"<Key>test.jpg</Key>"
"</Object>"
"<Object>"
"<Key>demo.jpg</Key>"
"</Object>"
    "</Delete>";

  fwrite(encoded, strlen(encoded), sizeof(gchar), fpost);
  fflush(fpost);
  rewind(fpost);

  client = get_or_create_client(service);

  GHashTable *header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  GHashTable *resp_header = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  gchar *date = get_current_date_time_gmt();
  g_hash_table_insert(header, g_strdup("Date"), date);
  g_hash_table_insert(header, g_strdup("Expect"), g_strdup(""));/*disable Expect header. */
  /* TODO calculate content md5 */
  md5 = calculate_md5(encoded, strlen(encoded));
  g_hash_table_insert(header, g_strdup("Content-MD5"), g_strdup(md5));
  authorize(service, HTTP_METHOD_POST, md5, "application/xml", header, res);
  g_string_free(buf, TRUE);
  g_free(md5);
  md5 = NULL;

  if (!quiet) {
    f = tmpfile();
    if (f == NULL) {
      g_debug("make temp file failed: %s\n", g_strerror(errno));
    g_set_error(error, OSS_ERROR, OSS_ERROR_FAILED, "make temp file failed: %s\n", g_strerror(errno));
      g_free((gpointer)res);
      g_hash_table_destroy(header);
      g_hash_table_destroy(resp_header);
      return -1;
    }
  }
  r = http_client_post(client, res, header, resp_header, NULL, encoded, NULL, f, error);
  if (r) {
    /* TODO process error */
    if (f) {
      rewind(f);
      err = process_error(f);

      fclose(f);
      f = NULL;
    }
    g_free(encoded);
    g_free((gpointer)res);
    g_hash_table_destroy(header);
    g_hash_table_destroy(resp_header);
    return -1;
  }

  if (f) {
    fflush(f);
    fclose(f);
  }
  fflush(fpost);
  fclose(fpost);
  g_free(encoded);
  g_free((gpointer)res);
  g_hash_table_destroy(header);
  g_hash_table_destroy(resp_header);
  return 0;
}

static gchar *get_current_date_time_gmt()
{
  gchar buf[50];
  gchar *old;
  time_t t = time(NULL);
  old = setlocale(LC_ALL, NULL);
  setlocale(LC_TIME, "en_US.UTF-8");
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
  setlocale(LC_ALL, old);
  return g_strdup(buf);
  /*
  GDateTime *now = g_date_time_new_now_utc();
  gchar *result = g_date_time_format(now, "%a, %d %b %Y %H:%M:%S GMT");
  g_date_time_unref(now);

  return result;
  */
}

static gchar *sign(const OssService *service, const gchar *method, const gchar *content_md5, const gchar *content_type, const gchar *date, GHashTable *header, const gchar *resource)
{
  const gchar lf = '\n';
  GString *buf = NULL;
  GSList *canon_headers = NULL;
  GHashTableIter iter;
  gpointer key;
  gpointer value;
  GString *head = NULL;
  gint i;
  gint len;
  gchar *pos;
  GSList *canon_res = NULL;
  gchar *result;

  /*if (date == NULL || resource == NULL) {
    return NULL;
  }
  */

  buf = g_string_sized_new(255);
  if (method) g_string_append(buf, method);
  g_string_append_c(buf, lf);
  if (content_md5) g_string_append(buf, content_md5);
  g_string_append_c(buf, lf);
  if (content_type) g_string_append(buf, content_type);
  g_string_append_c(buf, lf);
  g_string_append(buf, date);
  g_string_append_c(buf, lf);

  if (header != NULL && g_hash_table_size(header)) {
    head = g_string_sized_new(100);
    g_hash_table_iter_init(&iter, header);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      g_string_assign(head, (char*)key);
      g_string_ascii_down(head);
      if (g_str_has_prefix((char*)head->str, "x-oss-")) {
	g_string_append_c(head, ':');
	g_string_append(head, value);
	canon_headers = g_slist_append(canon_headers, g_strdup(head->str));
      }
    }
    g_string_free(head, TRUE);

    len = g_slist_length(canon_headers);
    if (len) {
      canon_headers = g_slist_sort(canon_headers, (GCompareFunc)g_strcmp0);
      GSList *p = canon_headers;
      while (p) {
	g_string_append(buf, (char*)p->data);
	g_string_append_c(buf, lf);
	p = p->next;
      }
      /*for (i = 0; i < g_slist_length(canon_headers); ++i) {
	g_string_append(buf, (char*)g_slist_nth_data(canon_headers, i));
	g_string_append_c(buf, lf);
	}*/
    }

    g_slist_free(canon_headers);
  }

  if (service->bucket) {
    g_string_append_c(buf, '/');
    g_string_append(buf, service->bucket);
  }
  if (!g_str_has_prefix(resource, "/")) {
    g_string_append_c(buf, '/');
  }

  pos = strchr(resource, (int)'?');
  if (pos) {
    g_string_append_len(buf, resource, pos-resource);
    if (*(pos+1)) {/* '?' is not the last char of resource */
      gchar **parts = g_strsplit(pos+1, "&", 0);
      gchar **p = parts;
      while (*p) {
	if (g_ascii_strcasecmp(*p, "acl") == 0 ||
	    g_ascii_strcasecmp(*p, "group") == 0 ||
	    g_ascii_strcasecmp(*p, "uploadId") == 0 ||
	    g_ascii_strcasecmp(*p, "partNumber") == 0 ||
	    g_ascii_strcasecmp(*p, "uploads") == 0) {
	  canon_res = g_slist_append(canon_res, *p);
	}
	p++;
      }

      len = g_slist_length(canon_res);
      if (len) {
	g_string_append_c(buf, '?');
	canon_res = g_slist_sort(canon_res, (GCompareFunc)g_strcmp0);
	for (i = 0; i < len; ) {
	  g_string_append(buf, (char*)g_slist_nth_data(canon_res, i));
	  ++i;
	  if (i != len) g_string_append_c(buf, '&');
	}
      }

      g_slist_free(canon_res);
      g_strfreev(parts);
    }
  } else {
    g_string_append(buf, resource);
  }

  /*
  GHmac *hmac;
  guint8 digest[150];
  gssize digest_len;
  hmac = g_hmac_new(G_CHECKSUM_SHA1, service->access_key, strlen(service->access_key));
  g_hmac_update(hmac, buf->str, buf->len);
  g_hmac_get_digest(hmac, digest, &digest_len);
  result = g_base64_encode((guchar*)digest, digest_len);
  */

  guint8 digest[EVP_MAX_MD_SIZE];
  gssize digest_len;
  HMAC(service->sha1, service->access_key, strlen(service->access_key), buf->str, buf->len, digest, &digest_len);
  result = g_base64_encode((guchar*)digest, digest_len);

  g_string_free(buf, TRUE);
  return result;
}

static const gchar* calculate_md5(const gchar *content, gsize len)
{
  guchar buf[MD5_DIGEST_LENGTH];
  gchar *result = NULL;
  gsize i;

  MD5((guchar*)content, len, buf);
  /*  result = g_base64_encode(buf, MD5_DIGEST_LENGTH); */
  result = g_new(gchar, MD5_DIGEST_LENGTH * 2 + 1);
  for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
    g_snprintf((gchar*)(result+2*i), 3, "%02x", (guint)(*(buf+i)));
  }

  return result;
}

static GSList* process_list_all_my_buckets_result(FILE *f)
{
  const gchar *LIST_ALL_MY_BUCKETS_RESULT = "ListAllMyBucketsResult";
  const gchar *OWNER = "Owner";
  const gchar *ID = "ID";
  const gchar *DISPLAY_NAME = "DisplayName";
  const gchar *BUCKETS = "Buckets";
  const gchar *BUCKET = "Bucket";
  const gchar *NAME = "Name";
  const gchar *CREATION_DATE = "CreationDate";

  xmlTextReaderPtr reader;
  int ret, type;
  const xmlChar *name, *value;
  GSList *buckets = NULL;
  OssOwner *owner;
  OssBucket *bucket;

  rewind(f);
  reader = xmlReaderForFd(fileno(f), NULL, "UTF-8", 0);
  if (reader != NULL) {
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
      name = xmlTextReaderConstName(reader);
      type = xmlTextReaderNodeType(reader);
      if (type == 1) { /* Element */
	if (g_strcmp0(name, OWNER) == 0) {
	  owner = g_new0(OssOwner, 1);
	} else if (g_strcmp0(name, ID) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    owner->id = g_strdup(value);
	  }
	} else if (g_strcmp0(name, DISPLAY_NAME) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    owner->display_name = g_strdup(value);
	  }
	} else if (g_strcmp0(name, BUCKET) == 0) {
	  bucket = g_new0(OssBucket, 1);
	  bucket->owner = owner;
	} else if (g_strcmp0(name, NAME) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    bucket->name = g_strdup(value);
	  }
	} else if (g_strcmp0(name, CREATION_DATE) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    bucket->creation_date = g_strdup(value);
	  }
	}
      } else if (type == 15) { /* EndElement */
	if (g_strcmp0(name, BUCKET) == 0) {
	  buckets = g_slist_append(buckets, bucket);
	}
      }
      ret = xmlTextReaderRead(reader);
    }
  }

  return buckets;
}

static OssError* process_error(FILE *f)
{
  const gchar *ERROR = "Error";
  const gchar *CODE = "Code";
  const gchar *MESSAGE = "Message";
  const gchar *ARGUMENT_NAME = "ArgumentName";
  const gchar *ARGUMENT_VALUE = "ArgumentValue";
  const gchar *REQUEST_ID = "RequestId";
  const gchar *HOST_ID = "HostId";

  xmlTextReaderPtr reader;
  int ret, type;
  const xmlChar *name, *value;
  OssError *error = NULL;

  rewind(f);
  reader = xmlReaderForFd(fileno(f), NULL, "UTF-8", 0);
  if (reader != NULL) {
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
      name = xmlTextReaderConstName(reader);
      type = xmlTextReaderNodeType(reader);
      if (type == 1) { /* Element */
	if (g_strcmp0(name, ERROR) == 0) {
	  error = g_new0(OssError, 1);
	} else if (g_strcmp0(name, CODE) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    error->code = g_strdup(value);
	  }
	} else if (g_strcmp0(name, MESSAGE) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    error->message = g_strdup(value);
	  }
	} else if (g_strcmp0(name, ARGUMENT_NAME) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    error->argument_name = g_strdup(value);
	  }
	} else if (g_strcmp0(name, ARGUMENT_VALUE) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    error->argument_value = g_strdup(value);
	  }
	} else if (g_strcmp0(name, REQUEST_ID) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    error->request_id = g_strdup(value);
	  }
	} else if (g_strcmp0(name, HOST_ID) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    error->host_id = g_strdup(value);
	  }
	}
      }
      ret = xmlTextReaderRead(reader);
    }
  }

  return error;
}

static OssListBucketResult* process_list_bucket_result(FILE *f)
{
  const gchar *LIST_BUCKET_RESULT = "ListBucketResult";
  const gchar *NAME = "Name";
  const gchar *PREFIX = "Prefix";
  const gchar *MARKER = "Marker";
  const gchar *MAX_KEYS = "MaxKeys";
  const gchar *DELIMITER = "Delimiter";
  const gchar *IS_TRUNCATED = "IsTruncated";
  const gchar *CONTENTS = "Contents";
  const gchar *KEY = "Key";
  const gchar *LAST_MODIFIED = "LastModified";
  const gchar *ETAG = "ETag";
  const gchar *TYPE = "Type";
  const gchar *SIZE = "Size";
  const gchar *STORAGE_CLASS = "StorageClass";
  const gchar *OWNER = "Owner";
  const gchar *ID = "ID";
  const gchar *DISPLAY_NAME = "DisplayName";
  const gchar *COMMON_PREFIXES = "CommonPrefixes";

  OssListBucketResult *result = NULL;
  xmlTextReaderPtr reader;
  int ret, type;
  const xmlChar *name, *value;
  OssObject *object;
  OssOwner *owner;
  gboolean common = FALSE;

  rewind(f);
  reader = xmlReaderForFd(fileno(f), NULL, "UTF-8", 0);
  if (reader != NULL) {
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
      name = xmlTextReaderConstName(reader);
      type = xmlTextReaderNodeType(reader);
      if (type == 1) { /* Element */
	if (g_strcmp0(name, LIST_BUCKET_RESULT) == 0) {
	  result = g_new0(OssListBucketResult, 1);
	  result->contents = NULL;
	  result->common_prefixes = NULL;
	} else if (g_strcmp0(name, NAME) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    result->name = g_strdup(value);
	  }
	} else if (g_strcmp0(name, PREFIX) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    if (common) {
	      result->common_prefixes = g_slist_append(result->common_prefixes, g_strdup(value));
	    } else {
	      result->prefix = g_strdup(value);
	    }
	  }
	} else if (g_strcmp0(name, MARKER) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    result->marker = g_strdup(value);
	  }
	} else if (g_strcmp0(name, MAX_KEYS) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    result->max_keys = (guint)g_ascii_strtoull(value, NULL, 10);
	  }
	} else if (g_strcmp0(name, DELIMITER) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    result->delimiter = g_strdup(value);
	  }
	} else if (g_strcmp0(name, IS_TRUNCATED) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    result->is_truncated = g_ascii_strcasecmp(value, "false") == 0?FALSE:TRUE;
	  }
	} else if (g_strcmp0(name, CONTENTS) == 0) {
	  object = g_new0(OssObject, 1);
	} else if (g_strcmp0(name, KEY) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    object->key = g_strdup(value);
	  }
	} else if (g_strcmp0(name, LAST_MODIFIED) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    object->last_modified = g_strdup(value);
	  }
	} else if (g_strcmp0(name, ETAG) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    object->etag = g_strdup(value);
	  }
	} else if (g_strcmp0(name, TYPE) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    object->type = g_strdup(value);
	  }
	} else if (g_strcmp0(name, SIZE) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    object->size = g_ascii_strtoull(value, NULL, 10);
	  }
	} else if (g_strcmp0(name, STORAGE_CLASS) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    object->storage_class = g_strdup(value);
	  }
	} else if (g_strcmp0(name, OWNER) == 0) {
	  owner = g_new0(OssOwner, 1);
	} else if (g_strcmp0(name, ID) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    owner->id = g_strdup(value);
	  }
	} else if (g_strcmp0(name, DISPLAY_NAME) == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    owner->display_name = g_strdup(value);
	  }
	} else if (g_strcmp0(name, COMMON_PREFIXES) == 0) {
	  common = TRUE;
	}
      } else if (type == 15) { /* End of element */
	if (g_strcmp0(name, OWNER) == 0) {
	  object->owner = owner;
	  owner = NULL;
	} else if (g_strcmp0(name, CONTENTS) == 0) {
	  result->contents = g_slist_append(result->contents, object);
	  object = NULL;
	} else if (g_strcmp0(name, COMMON_PREFIXES) == 0) {
	  common = FALSE;
	}
      }
      ret = xmlTextReaderRead(reader);
    }
  }
  return result;
}

 static GQuark oss_error_quark()
 {
   return g_quark_from_static_string("oss-error-quark");
 }

static HttpClient* get_or_create_client(OssService *service)
{
  HttpClient *client = NULL;
  GString *address;

  address = g_string_sized_new(128);
  g_string_append(address, service->scheme);
  g_string_append(address, "://");
  if (service->bucket != NULL) {
    g_string_append(address, service->bucket);
    g_string_append_c(address, '.');
  }
  g_string_append(address, service->host);

  if (service->client == NULL) {
    client = http_client_new(address->str, service->port);
    if (client == NULL) {
      g_print("Initialize http client failed: %s\n", g_strerror(errno));
      exit(-1);
    }
    service->client = client;
  } else if (g_strcmp0(service->client->host, address->str) != 0) {
    http_client_destroy(service->client);
    client = http_client_new(address->str, service->port);
    if (client == NULL) {
      g_print("Initialize http client failed: %s\n", g_strerror(errno));
      exit(-1);
    }
    service->client = client;
  } else {
    client = service->client;
  }
  g_string_free(address, FALSE);
  return client;
}

static void authorize(const OssService *service, const gchar *method, const gchar *content_md5, const gchar *content_type, GHashTable *header, const gchar *path)
{
  gchar *date;
  gchar *signature;
  GString *auth;

  date = (gchar*)g_hash_table_lookup(header, "Date");
  signature = sign(service, method, content_md5, content_type, date, header, path);

  auth = g_string_sized_new(255);
  g_string_append(auth, "OSS ");
  g_string_append(auth, service->access_id);
  g_string_append_c(auth, ':');
  g_string_append(auth, signature);
  g_hash_table_insert(header, g_strdup("Authorization"), auth->str);
  g_free(signature);
  g_string_free(auth, FALSE);
}

static OssBucket* process_access_control_policy(FILE *f)
{
  xmlTextReaderPtr reader;
  OssBucket *result = NULL;
  OssOwner *owner;
  const xmlChar *name, *value;
  gint ret, type;

  result = g_new0(OssBucket, 1);

  rewind(f);
  reader = xmlReaderForFd(fileno(f), NULL, "UTF-8", 0);
  if (reader != NULL) {
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
      name = xmlTextReaderConstName(reader);
      type = xmlTextReaderNodeType(reader);
      if (type == 1) { /* Element */
	if (g_strcmp0(name, "Owner") == 0) {
	  owner = g_new0(OssOwner, 1);
	} else if (g_strcmp0(name, "ID") == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    owner->id = g_strdup(value);
	  }
	} else if (g_strcmp0(name, "DisplayName") == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    owner->display_name = g_strdup(value);
	  }
	} else if (g_strcmp0(name, "Grant") == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    result->acl = g_strdup(value);
	  }
	}
      } else if (type == 15) {/*EndElement */
	if (g_strcmp0(name, "Owner") == 0) {
	  result->owner = owner;
	  owner = NULL;
	}
      }
      ret = xmlTextReaderRead(reader);
    }
  }
  return result;
}

static const gchar* get_canonical_resource(OssObject *object)
{
  GString *res;
  const gchar *result;
  GHashTableIter iter;
  gpointer key, value;
  gboolean first = TRUE;

  if (g_str_has_prefix(object->key, "/")) {
    res = g_string_new("");
  } else {
    res = g_string_new("/");
  }
  g_string_append(res, object->key);

  first = (strchr(res->str, '?') == NULL);
  /* add response headers */
  if (object->meta && g_hash_table_size(object->meta)) {
    g_hash_table_iter_init(&iter, object->meta);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      if (g_str_has_prefix((gchar*)key, "Response-")) {
	if (first) {
	  g_string_append_c(res, '?');
	  first = FALSE;
	} else {
	  g_string_append_c(res, '&');
	}
	g_string_append(res, (gchar*)key);
	g_string_append_c(res, ':');
	g_string_append(res, (gchar*)value);
      }
    }
  }

  /*result = g_uri_escape_string(res->str, "/?&#", FALSE);
    g_string_free(res, TRUE);
  */
  result = res->str;
  g_string_free(res, FALSE);
  return result;
}

static void process_copy_object_result(FILE *f, OssObject *object)
{
  xmlTextReaderPtr reader;
  const xmlChar *name, *value;
  gint ret, type;

  rewind(f);
  reader = xmlReaderForFd(fileno(f), NULL, "UTF-8", 0);
  if (reader != NULL) {
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
      name = xmlTextReaderConstName(reader);
      type = xmlTextReaderNodeType(reader);
      if (type == 1) { /* Element */
	if (g_strcmp0(name, "LastModified") == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    object->last_modified = g_strdup(value);
	  }
	} else if (g_strcmp0(name, "ETag") == 0) {
	  if (xmlTextReaderRead(reader) == 1) {
	    value = xmlTextReaderConstValue(reader);
	    object->etag = g_strdup(value);
	  }
	}
      }
      ret = xmlTextReaderRead(reader);
    }
  }
}
