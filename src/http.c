#include <glib.h>
#include <curl/curl.h>
#include <errno.h>
#include <sys/stat.h>

#include "http.h"

static gchar* str_normalize(gchar *src)
{
  /*remove suffix \r\n*/
  gchar *pos;
  if (pos = g_strrstr(src, "\r")) {
    *pos = '\0';
  }
  return g_strstrip(src);
}

typedef struct {
  HttpClient *client;
  GHashTable *header;
} HeadFuncContext;

static size_t header_func(void *ptr, size_t size, size_t nmemb, void *data)
{
  HeadFuncContext *context;
  context = (HeadFuncContext*)data;
  if (context == NULL) {
    return 0;
  }

  gchar **parts = g_strsplit((const gchar*)ptr, ":", 2);
  if (g_strv_length(parts) == 2) {
    /*contains ":"*/
    g_hash_table_insert(context->header, parts[0], str_normalize(parts[1]));
  } else {
    GRegex *regex;
    GMatchInfo *match_info;
   
    regex = g_regex_new("^HTTP\\/\\S*\\s*(\\d+)\\s*(.*?)\\s*$", 0, 0, NULL);
    g_regex_match(regex, (const gchar*)ptr, 0, &match_info);
    gchar *endptr;
    if (g_match_info_matches(match_info)) {
      gchar *word = g_match_info_fetch(match_info, 1);
      context->client->status_code = g_ascii_strtoll(word, &endptr, 10);
      g_free(word);
      word = g_match_info_fetch(match_info, 2);
      g_stpcpy(context->client->status_message, word);
      g_free(word);
    }
    
    g_match_info_free(match_info);
    g_regex_unref(regex);
    g_strfreev(parts);
  }

  /*  g_strfreev(parts);*/
  return size * nmemb;
}

/*
 * Convert a GHashTable to a curl_slist by concating key and value using ':'.
 * CURLOPT_HTTPHEADER option needs this type to store headers of request.
 * @Return a newly allocated pointer to curl_slist struct. Use curl_slist_free_all(3) to free it.
 */
static struct curl_slist *to_curl_slist(GHashTable *header)
{
  struct curl_slist *result = NULL;
  GHashTableIter iter;
  gpointer key, value;

  g_hash_table_iter_init(&iter, header);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    g_debug("header[%s]='%s'", (gchar*)key, (gchar*)value);
    result = curl_slist_append(result, g_strjoin(":", key, value, NULL));
  }

  return result;
}

static gint do_request(CURL *handle, gchar *message);
static void set_error(const HttpClient *client, GError **error);
static CURL* handle_new(HttpClient *client)
{
  CURL *url;
  url = curl_easy_init();
  if (url == NULL) {
    g_debug("Initialize curl handle failed: %s", g_strerror(errno));
    curl_global_cleanup();
    return NULL;
  }
  curl_easy_setopt(url, CURLOPT_FRESH_CONNECT, 1);/* create new connection every time */
  curl_easy_reset(url);
  return url;
}
static void handle_destroy(CURL *handle)
{
  if (handle) {
    curl_easy_cleanup(handle);
  }
}

HttpClient *http_client_new(const gchar *host, glong port)
{
  HttpClient *client = NULL;

  CURL *url = NULL;
  CURLcode r;
  r = curl_global_init(CURL_GLOBAL_ALL);
  if (r) {
    g_warning("Initialize curl failed");
    return NULL;
  }
  url = curl_easy_init();
  if (url == NULL) {
    g_warning("Initialize curl handle failed: %s", g_strerror(errno));
    curl_global_cleanup();
    return NULL;
  }
  curl_easy_setopt(url, CURLOPT_FRESH_CONNECT, 1);/* create new connection every time */
  client = g_new(HttpClient, 1);
  if (client == NULL) {
    g_warning("New http client failed: %s", g_strerror(errno));
    curl_easy_cleanup(url);
    curl_global_cleanup();
    return NULL;
  }
  client->host = host;
  client->port = port;
  client->status_code = 0;
  return client;
}

void http_client_destroy(HttpClient *client)
{
  if (client) {
    curl_global_cleanup();
  }
}

gint http_client_head(HttpClient *client, const gchar *path, GHashTable *header, GHashTable *resp_header, GError **error)
{
  gchar *url = NULL;
  CURLcode r;
  HeadFuncContext *context;
  CURL *handle;

  g_return_val_if_fail(client != NULL, -1);
  g_return_val_if_fail(path != NULL && strlen(path) > 0, -1);
  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  g_debug("http_client_head(path=%s)", path);
  handle = handle_new(client);
  if (handle == NULL) return -1;

  url = g_strconcat(client->host, path, NULL);
  r = curl_easy_setopt(handle, CURLOPT_URL, url);
  g_message("HEAD %s", url);
  curl_easy_setopt(handle, CURLOPT_PORT, client->port);
  curl_easy_setopt(handle, CURLOPT_NOBODY, TRUE);
  if (header && g_hash_table_size(header)) {
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, to_curl_slist(header));
  }
  curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
  context = g_new(HeadFuncContext, 1);
  context->client = client;
  context->header = resp_header;
  curl_easy_setopt(handle, CURLOPT_HEADERDATA, context);
  
  r = do_request(handle, client->error_message);
  if (r != 200) {
    g_debug("Perform curl HEAD operation failed: %s", client->error_message);
    set_error(client, error);

    g_free(context);
    g_free(url);
    handle_destroy(handle);
    return r;
  }

  g_free(context);
  g_free(url);
  handle_destroy(handle);
  return r;
}

gint http_client_get(HttpClient *client, const gchar *path, GHashTable *header, GHashTable *resp_header, HttpWriteFunc writer, gpointer user_data, GError **error)
{
  gchar *url = NULL;
  CURLcode r;
  HeadFuncContext *context;
  CURL *handle;

  g_return_val_if_fail(client != NULL, -1);
  g_return_val_if_fail(path != NULL && strlen(path) > 0, -1);
  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  handle = handle_new(client);
  if (handle == NULL) return -1;

  url = g_strconcat(client->host, path, NULL);
  r = curl_easy_setopt(handle, CURLOPT_URL, url);
  g_message("GET %s", url);
  curl_easy_setopt(handle, CURLOPT_PORT, client->port);
  curl_easy_setopt(handle, CURLOPT_HTTPGET, TRUE);
  if (header && g_hash_table_size(header)) {
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, to_curl_slist(header));
  }
  curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
  context = g_new(HeadFuncContext, 1);
  context->client = client;
  context->header = resp_header;
  curl_easy_setopt(handle, CURLOPT_HEADERDATA, context);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writer);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, user_data);

  r = do_request(handle, client->error_message);
  g_free(context);

  if (r != 200) {
    g_debug("Perform curl GET operation failed: %s", client->error_message);
    set_error(client, error);

  } else {
    long code;
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &code);
    if (code != HTTP_STATUS_CODE_OK) {
      g_free(url);
      handle_destroy(handle);
      return -1;
    }
  }

  g_free(url);
  handle_destroy(handle);
  return r;
}

gint http_client_put(HttpClient *client, const gchar *path, GHashTable *header, GHashTable *resp_header, HttpReadFunc reader, gpointer read_data, HttpWriteFunc writer, gpointer write_data, GError **error)
{
  gchar *url = NULL;
  CURLcode r;
  HeadFuncContext *context;
  struct stat st;
  CURL *handle;

  g_return_val_if_fail(client != NULL, -1);
  g_return_val_if_fail(path != NULL && strlen(path) > 0, -1);
  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  handle = handle_new(client);
  if (handle == NULL) return -1;

  url = g_strconcat(client->host, path, NULL);
  r = curl_easy_setopt(handle, CURLOPT_URL, url);
  g_message("PUT %s", url);
  curl_easy_setopt(handle, CURLOPT_PORT, client->port);
  curl_easy_setopt(handle, CURLOPT_UPLOAD, 1);
  /*TODO how to get content length */
  if (read_data == NULL) {
    curl_easy_setopt(handle, CURLOPT_INFILESIZE, 0L);
    g_message("header[Content-Length]='0'");
  } else {
    if (fstat(fileno(read_data), &st) == 0) {
      curl_easy_setopt(handle, CURLOPT_INFILESIZE, st.st_size);
      g_message("header[Content-length]='%ld'", (long)st.st_size);
    }
    curl_easy_setopt(handle, CURLOPT_READFUNCTION, reader);
    curl_easy_setopt(handle, CURLOPT_READDATA, read_data);
  }

  if (header && g_hash_table_size(header)) {
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, to_curl_slist(header));
  }
  curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
  context = g_new(HeadFuncContext, 1);
  context->client = client;
  context->header = resp_header;
  curl_easy_setopt(handle, CURLOPT_HEADERDATA, context);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writer);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, write_data);

  r = do_request(handle, client->error_message);
  if (r != 200) {
    g_debug("Perform curl PUT operation failed: %s", client->error_message);
    set_error(client, error);

    g_free(context);
    g_free(url);
    handle_destroy(handle);
    return r;
  }

  g_free(context);
  g_free(url);
  handle_destroy(handle);
  return r;
}

gint http_client_delete(HttpClient *client, const gchar *path, GHashTable *header, GHashTable *resp_header, HttpWriteFunc writer, gpointer write_data, GError **error)
{
  gchar *url = NULL;
  CURLcode r;
  HeadFuncContext *context;
  CURL *handle;

  g_return_val_if_fail(client != NULL, -1);
  g_return_val_if_fail(path != NULL && strlen(path) > 0, -1);
  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  handle = handle_new(client);
  if (handle == NULL) return -1;

  url = g_strconcat(client->host, path, NULL);
  r = curl_easy_setopt(handle, CURLOPT_URL, url);
  g_message("DELETE %s", url);
  curl_easy_setopt(handle, CURLOPT_PORT, client->port);
  curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "DELETE");
  if (header && g_hash_table_size(header)) {
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, to_curl_slist(header));
  }
  curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
  context = g_new(HeadFuncContext, 1);
  context->client = client;
  context->header = resp_header;
  curl_easy_setopt(handle, CURLOPT_HEADERDATA, context);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writer);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, write_data);

  r = do_request(handle, client->error_message);
  g_free(context);

  if (r != 200) {
    g_debug("Perform curl DELETE operation failed: %s", client->error_message);
    set_error(client, error);

    g_free(url);
    handle_destroy(handle);
    return r;
  }

  g_free(url);
  handle_destroy(handle);
  return r;
}

gint http_client_post(HttpClient *client, const gchar *path, GHashTable *header, GHashTable *resp_header, HttpReadFunc reader, gpointer read_data, HttpWriteFunc writer, gpointer write_data, GError **error)
{
  gchar *url = NULL;
  CURLcode r;
  HeadFuncContext *context;
  CURL *handle;

  g_return_val_if_fail(client != NULL, -1);
  g_return_val_if_fail(path != NULL && strlen(path) > 0, -1);
  g_return_val_if_fail(error == NULL || *error == NULL, -1);

  handle = handle_new(client);
  if (handle == NULL) return -1;

  url = g_strconcat(client->host, path, NULL);
  r = curl_easy_setopt(handle, CURLOPT_URL, url);
  g_message("POST %s", url);
  curl_easy_setopt(handle, CURLOPT_PORT, client->port);
  curl_easy_setopt(handle, CURLOPT_PUT, 0);
  curl_easy_setopt(handle, CURLOPT_POST, 1);
  /*TODO how to get content length */
  if (read_data == NULL) {
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, NULL);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, 0L);
    g_message("header[Content-Length]='0'");
  } else {
    if (reader == NULL) {
      curl_easy_setopt(handle, CURLOPT_POSTFIELDS, read_data);
      curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, strlen(read_data));
      g_message("header[Content-Length]='%d'", strlen(read_data));
    } else {
      curl_easy_setopt(handle, CURLOPT_READFUNCTION, reader);
      curl_easy_setopt(handle, CURLOPT_READDATA, read_data);
    }
  }

  if (header && g_hash_table_size(header)) {
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, to_curl_slist(header));
  }
  curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
  context = g_new(HeadFuncContext, 1);
  context->client = client;
  context->header = resp_header;
  curl_easy_setopt(handle, CURLOPT_HEADERDATA, context);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writer);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, write_data);

  r = do_request(handle, client->error_message);
  if (r != 200) {
    g_debug("Perform curl POST operation failed: %s", client->error_message);
    set_error(client, error);

    g_free(context);
    g_free(url);
    handle_destroy(handle);
    return r;
  }

  g_free(context);
  g_free(url);
  handle_destroy(handle);
  return r;
}

static gint do_request(CURL *handle, gchar *message)
{
  CURLcode r;
  long code;

  curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(handle, CURLOPT_TIMEOUT, 5*60);
  curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, message);
  r = curl_easy_perform(handle);
  switch (r) {
  case CURLE_OK:
    if (r = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &code)) {
      g_warning("curl_easy_getinfo retrieve HTTP response status code failed: %s", curl_easy_strerror(r));
      return -1;
    }

    g_debug("HTTP response code %ld\n", code);
    return code;
  case CURLE_WRITE_ERROR:
    g_warning("curl_easy_perform write failed: %s", curl_easy_strerror(r));
    break;
  case CURLE_OPERATION_TIMEDOUT:
    g_warning("curl_easy_perform operation timeout: %s", curl_easy_strerror(r));
    break;
  case CURLE_COULDNT_RESOLVE_HOST:
    g_warning("curl_easy_perform could not resolve host: %s", curl_easy_strerror(r));
    break;
  case CURLE_COULDNT_CONNECT:
    g_warning("curl_easy_perform could not connect: %s", curl_easy_strerror(r));
    break;
  case CURLE_GOT_NOTHING:
    g_warning("curl_easy_perform got nothing: %s", curl_easy_strerror(r));
    break;
  case CURLE_ABORTED_BY_CALLBACK:
    g_warning("curl_easy_perform aborted by callback: %s", curl_easy_strerror(r));
    break;
  case CURLE_PARTIAL_FILE:
    g_warning("curl_easy_perform partial file: %s", curl_easy_strerror(r));
    break;
  case CURLE_SEND_ERROR:
    g_warning("curl_easy_perform send error: %s", curl_easy_strerror(r));
    break;
  case CURLE_RECV_ERROR:
    g_warning("curl_easy_perform receive error: %s", curl_easy_strerror(r));
    break;
  case CURLE_SSL_CACERT:
    g_warning("curl_easy_perform ssl cacert: %s", curl_easy_strerror(r));
    break;
  case CURLE_HTTP_RETURNED_ERROR:
    g_warning("curl_easy_perform http returned error: %s", curl_easy_strerror(r));
    break;
  default:
    g_error("curl_easy_perform returned unknown value '%ld': %s", code, curl_easy_strerror(code));
    exit(-1);
    break;
  }
  return -1;
}

static GQuark http_client_error_quark(void)
{
  return g_quark_from_static_string("http-client-error-quark");
}
static GQuark http_server_error_quark(void)
{
  return g_quark_from_static_string("http-server-error-quark");
}

void set_error(const HttpClient *client, GError **error)
{
  if (error) {
    if (client->status_code >= 400 && client->status_code < 500) { /*client error */
      *error = g_error_new(HTTP_CLIENT_ERROR, client->status_code, "%s", client->status_message);
    } else if (client->status_code >= 500) {
      *error = g_error_new(HTTP_SERVER_ERROR, client->status_code, "%s", "Server Error");
    } else { /* not http response error */
      *error = g_error_new(HTTP_CLIENT_ERROR, -1, "Other error: %s", client->error_message);
    }
  }
}
