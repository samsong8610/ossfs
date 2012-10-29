#ifndef HTTP_H
#define HTTP_H

#include <glib.h>
#include <curl/curl.h>

#define HTTP_METHOD_HEAD    "HEAD"
#define HTTP_METHOD_GET     "GET"
#define HTTP_METHOD_PUT     "PUT"
#define HTTP_METHOD_POST    "POST"
#define HTTP_METHOD_DELETE  "DELETE"

#define HTTP_STATUS_CODE_OK 200

#define HTTP_CLIENT_ERROR http_client_error_quark ()
#define HTTP_SERVER_ERROR http_server_error_quark ()

typedef enum {
  HTTP_CLIENT_ERROR_FAILED=400,
  HTTP_CLIENT_ERROR_BAD_REQUEST,
  HTTP_CLIENT_ERROR_UNAUTHORIZED,
  HTTP_CLIENT_ERROR_PAYMENT_REQUIRED,
  HTTP_CLIENT_ERROR_FORBIDDEN,
  HTTP_CLIENT_ERROR_NOT_FOUND,
  HTTP_CLIENT_ERROR_METHOD_NOT_ALLOWED,
  HTTP_CLIENT_ERROR_NOT_ACCEPTABLE,
  HTTP_CLIENT_ERROR_PROXY_AUTHENTICATION_REQUIRED,
  HTTP_CLIENT_ERROR_REQUEST_TIMEOUT,
  HTTP_CLIENT_ERROR_CONFLICT,
  HTTP_CLIENT_ERROR_GONE,
  HTTP_CLIENT_ERROR_LENGTH_REQUIRED,
  HTTP_CLIENT_ERROR_PRECONDITION_FAILED,
  HTTP_CLIENT_ERROR_REQUEST_ENTITY_TOO_LARGE,
  HTTP_CLIENT_ERROR_REQUEST_URL_TOO_LONG,
  HTTP_CLIENT_ERROR_UNSUPPORTED_MEDIA_TYPE,
  HTTP_CLIENT_ERROR_REQUESTED_RANGE_NOT_SATISFIABLE,
  HTTP_CLIENT_ERROR_EXPECTATION_FAILED
} HttpClientError;

typedef struct {
  const gchar *host;       /* Target host name or ip address, default localhost. */
  glong port;         /* Server port, default 80. */
  /*CURL *handle;       Using CURL to communicate. DELETE 20121028 create a new handle every time. */
  long status_code;  /* Status code of last response. */
  gchar status_message[CURL_ERROR_SIZE]; /* Status message of last response, nul-terminated. */
  gchar error_message[CURL_ERROR_SIZE]; /* Receive curl error message */
} HttpClient;

typedef gssize (*HttpWriteFunc)(gpointer ptr, gsize size, gsize nmemb, gpointer user_data);
typedef gssize (*HttpReadFunc)(gpointer ptr, gsize size, gsize nmemb, gpointer user_data);
/*
 * Initialize a http client using host name and port.
 * @host gchar* target host name or ip address. If NULL, use localhost.
 * @port gint server port. if less than or equal to 0, use 80.
 *
 * @return a pointer to struct HttpClient, used in others functions. If any error occures, return NULL.
 */
HttpClient* http_client_new(const gchar *host, glong port);
void http_client_destroy(HttpClient *client);

gint http_client_head(HttpClient *client, const gchar *path, GHashTable *header, GHashTable *resp_header, GError **error);

gint http_client_get(HttpClient *client, const gchar *path, GHashTable *header, GHashTable *resp_header, HttpWriteFunc writer, gpointer user_data, GError **error);

gint http_client_put(HttpClient *client, const gchar *path, GHashTable *header, GHashTable *resp_header, HttpReadFunc reader, gpointer read_data, HttpWriteFunc writer, gpointer write_data, GError **error);

gint http_client_delete(HttpClient *client, const gchar *path, GHashTable *header, GHashTable *resp_header, HttpWriteFunc writer, gpointer write_data, GError **error);

gint http_client_post(HttpClient *client, const gchar *path, GHashTable *header, GHashTable *resp_header, HttpReadFunc reader, gpointer read_data, HttpWriteFunc writer, gpointer write_data, GError **error);
#endif /* HTTP_H */
