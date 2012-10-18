#ifndef OSS_H
#define OSS_H

#include <glib.h>
#include <openssl/evp.h>

#include "http.h"

#define OSS_SERVICE_NAME        "OSS"
#define OSS_ACL_PUBLIC_RW       "public-read-write"
#define OSS_ACL_PUBLIC_RO       "public-read"
#define OSS_ACL_PRIVATE         "private"

#define OSS_OBJECT_KEY_MIN      1
#define OSS_OBJECT_KEY_MAX      1023

#define OSS_CONFIG_SCHEME       "scheme"
#define OSS_CONFIG_HOST         "host"
#define OSS_CONFIG_PORT         "port"
#define OSS_CONFIG_ACCESSID     "accessid"
#define OSS_CONFIG_ACCESSKEY    "accesskey"
#define OSS_CONFIG_PUBLIC       "public"

#define OSS_ERROR oss_error_quark()

static GQuark oss_error_quark();

typedef enum {
  OSS_ERROR_FAILED,
  OSS_ERROR_ACCESS_DENIED,
  OSS_ERROR_BUCKET_ALREADY_EXISTS,
  OSS_ERROR_BUCKET_NOT_EMPTY,
  OSS_ERROR_ENTITY_TOO_LARGE,
  OSS_ERROR_ENTITY_TOO_SMALL,
  OSS_ERROR_FILE_GROUP_TOO_LARGE,
  OSS_ERROR_FILE_PART_NOT_EXIST,
  OSS_ERROR_FILE_PART_STALE,
  OSS_ERROR_INVALID_ARGUMENT,
  OSS_ERROR_INVALID_ACCESS_KEY_ID,
  OSS_ERROR_INVALID_BUCKET_NAME,
  OSS_ERROR_INVALID_DIGEST,
  OSS_ERROR_INVALID_OBJECT_NAME,
  OSS_ERROR_INVALID_PART,
  OSS_ERROR_INVALID_PART_ORDER,
  OSS_ERROR_INTERNAL_ERROR,
  OSS_ERROR_MALFORMED_XML,
  OSS_ERROR_METHOD_NOT_ALLOWED,
  OSS_ERROR_MISSING_ARGUMENT,
  OSS_ERROR_MISSING_CONTENT_LENGTH,
  OSS_ERROR_NO_SUCH_BUCKET,
  OSS_ERROR_NO_SUCH_KEY,
  OSS_ERROR_UPLOAD,
  OSS_ERROR_NOT_IMPLEMENTED,
  OSS_ERROR_PRECONDITION_FAILED,
  OSS_ERROR_REQUEST_TIME_TOO_SKEWED,
  OSS_ERROR_REQUEST_TIMEOUT,
  OSS_ERROR_SIGNATURE_DOES_NOT_MATCH,
  OSS_ERROR_TOO_MANY_BUCKETS
} OssErrors;

typedef struct {
  const gchar *scheme;
  const gchar *host;
  gint port;
  const gchar *bucket;
  gboolean is_public;
  const gchar *access_id;
  const gchar *access_key;
  HttpClient *client;
  const EVP_MD *sha1;
} OssService;

typedef struct {
  gchar *id;
  gchar *display_name;
} OssOwner;

typedef struct {
  gchar *name;
  gchar *creation_date;
  OssOwner *owner;
  gchar *acl;
} OssBucket;

typedef struct {
  gchar *code;
  gchar *message;
  gchar *argument_name;
  gchar *argument_value;
  gchar *request_id;
  gchar *host_id;
} OssError;

typedef struct {
  gchar *key;
  gchar *last_modified;
  gchar *etag;
  gchar *type;
  gulong size;
  gchar *storage_class;
  OssOwner *owner;
  FILE *content;
  GHashTable *meta;
} OssObject;

typedef struct {
  gchar *name;
  gchar *prefix;
  gchar *marker;
  guint max_keys;
  gchar *delimiter;
  gboolean is_truncated;
  GSList *contents;
  GSList *common_prefixes;
} OssListBucketResult;

OssService* oss_service_new(const gchar *bucket, GHashTable *conf);
void oss_service_destroy(OssService *service);
OssBucket* oss_bucket_new(const gchar *name, const gchar *acl);
void oss_bucket_destroy(OssBucket *bucket);
OssObject* oss_object_new(const gchar *key);
OssObject* oss_object_new_file(const gchar *key, const gchar *path, const gchar *mode);
void oss_object_destroy(OssObject *object);

GSList* oss_service_get(OssService *service, GError **error);
void oss_service_get_destroy(GSList *buckets);

gint oss_bucket_put(OssService *service, OssBucket *bucket, GError **error);
gint oss_bucket_put_acl(OssService *service, OssBucket *bucket, GError **error);
OssListBucketResult* oss_bucket_get(OssService *service, const gchar *resource, GError **error);
OssBucket* oss_bucket_get_acl(OssService *service, const gchar *bucket, GError **error);
gint oss_bucket_delete(OssService *service, const gchar *bucket, GError **error);
void oss_bucket_get_destroy(OssListBucketResult *list);

gint oss_object_put(OssService *service, OssObject *object, GError **error);
gint oss_object_get(OssService *service, OssObject *object, GError **error);
gint oss_object_copy(OssService *service, OssObject *object, const gchar *src_bucket, OssObject *src, GError **error);
gint oss_object_head(OssService *service, OssObject *object, GError **error);
gint oss_object_delete(OssService *service, const gchar *object, GError **error);
gint oss_object_delete_multiple(OssService *service, gboolean quiet, GError **error, ...);
#endif /* OSS_H */
