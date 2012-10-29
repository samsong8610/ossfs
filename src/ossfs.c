#define FUSE_USE_VERSION 26

#include <glib.h>
#include <glib/gprintf.h>
#include <errno.h>
#include <fuse.h>
#include <dirent.h>
#include <locale.h>
#include <getopt.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "http.h"
#include "oss.h"

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#define GMT_FORMAT      "%a, %d %b %Y %H:%M:%S GMT"

#define OSS_META_MODE   "x-oss-meta-mode"

#define PROGRAME_NAME    "ossfs"
#define CONFIG_PATH     ".config/ossfs"
#define CONFIG_FILENAME "conf"

static void print_header(gpointer key, gpointer value, gpointer user_data);
static void destroyer(gpointer data);
static gchar *get_current_date_time_gmt();
static time_t parse_date_time_gmt(const gchar *gmt);
static gchar* ltos(glong l);
static int rename_object(const char *from, const char *to);
static int rename_directory(const char *from, const char *to);

static OssService *service;
static mode_t root_mode = 0;
static mode_t default_mode = 0755;
static gchar *bucket = "sam-pub";

static GHashTable *cache = NULL;
static GMutex *cache_lock;
static void cache_init(void);
static void cache_add(gpointer key, gpointer value);
static void cache_remove(gpointer key);
static gboolean cache_contains(gpointer key);
static gpointer cache_lookup(gpointer key);

static GLogLevelFlags level;
static void log_to_file(const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data);

static int ossfs_getattr(const char *path, struct stat *stbuf)
{
  gint res;
  OssObject *object;
  GError *error;
  gpointer value;
  gpointer st;
  GString *dir;

  g_debug("ossfs_getattr(path=%s)", path);
  memset(stbuf, 0, sizeof(struct stat));  
  if (cache_contains((gpointer)path)) {
    st = cache_lookup((gpointer)path);
    memcpy(stbuf, st, sizeof(struct stat));
    return 0;
  }

  if (g_strcmp0(path, "/") == 0) {
    stbuf->st_nlink = 1;
    stbuf->st_mode = root_mode | S_IFDIR;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    return 0;
  }

  object = oss_object_new(path);
  if (!object) return -ENOMEM;

  error = NULL;
  res = oss_object_head(service, object, &error);
  if (res) {
    oss_object_destroy(object);
    switch (error->code) {
    case OSS_ERROR_NO_SUCH_KEY:
      if (g_str_has_suffix(path, "/")) return -ENOENT;
      /* try to get path as directory */
      dir = g_string_new(path);
      if (dir == NULL) return -ENOMEM;
      g_string_append_c(dir, '/');
      g_message("try to get %s attribute", dir->str);
      if (g_hash_table_contains(cache, dir->str)) {
	st = g_hash_table_lookup(cache, dir->str);
	memcpy(stbuf, st, sizeof(struct stat));
	g_string_free(dir, TRUE);
	return 0;
      }
      object = oss_object_new(dir->str);
      g_string_free(dir, TRUE);
      if (!object) return -ENOMEM;

      error = NULL;
      res = oss_object_head(service, object, &error);
      if (res) {
	oss_object_destroy(object);
	switch (error->code) {
	case OSS_ERROR_NO_SUCH_KEY:
	  return -ENOENT;
        default:
          return -EIO;
	}
      }
      break; /* case OSS_ERROR_NO_SUCH_KEY */
    default:
      return -EIO;
    }
  }

  /* st_mode */
  value = g_hash_table_lookup(object->meta, OSS_META_MODE);
  if (value) {
    g_debug("%s: %s", OSS_META_MODE, (gchar*)value);
    stbuf->st_mode = g_ascii_strtoull((gchar*)value, NULL, 10);
  } else {
    stbuf->st_mode = default_mode;
    /* TODO: make sure how to test an object is a dir */
    if (g_str_has_suffix(object->key, "/")) {
      stbuf->st_mode |= S_IFDIR;
    } else {
      stbuf->st_mode |= S_IFREG;
    }
    g_debug("using default mode: %d", stbuf->st_mode);
  }

  stbuf->st_nlink = 1;
  stbuf->st_size = object->size;
  g_debug("size: %ld", (long)stbuf->st_size);
  if (S_ISREG(stbuf->st_mode)) {
    stbuf->st_blocks = stbuf->st_size / 512 + 1;
  }
  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();

  stbuf->st_mtime = parse_date_time_gmt(object->last_modified);

  st = g_memdup((gpointer)stbuf, sizeof(struct stat));
  cache_add(g_strdup(object->key), st);
  oss_object_destroy(object);
  return 0;
}

static int ossfs_access(const char *path, int mask)
{
  struct stat stbuf;
  int res;
  uid_t uid;
  gid_t gid;

  g_debug("ossfs_access(path=%s)", path);
  /* TODO how to check F_OK */
  /*  memset(&stbuf, 0, sizeof(struct stat));
  res = ossfs_getattr(path, &stbuf);
  if (res) return res;
  uid = getuid();
  gid = getgid();
  if (uid == stbuf.st_uid) {
    if (mask & R_OK) { 
      if (!(stbuf.st_mode & S_IRUSR)) return -EACCES;
    }
    if (mask & W_OK) {
      if (!(stbuf.st_mode & S_IWUSR)) return -EACCES;
    }
    if (mask & X_OK) {
      if (!(stbuf.st_mode & S_IXUSR)) return -EACCES;
    }
    return 0;
  } else if (gid == stbuf.st_gid) {
    if (mask & R_OK) { 
      if (!(stbuf.st_mode & S_IRGRP)) return -EACCES;
    }
    if (mask & W_OK) {
      if (!(stbuf.st_mode & S_IWGRP)) return -EACCES;
    }
    if (mask & X_OK) {
      if (!(stbuf.st_mode & S_IXGRP)) return -EACCES;
    }
    return 0;
  } else {
    if (mask & R_OK) { 
      if (!(stbuf.st_mode & S_IROTH)) return -EACCES;
    }
    if (mask & W_OK) {
      if (!(stbuf.st_mode & S_IWOTH)) return -EACCES;
    }
    if (mask & X_OK) {
      if (!(stbuf.st_mode & S_IXOTH)) return -EACCES;
    }
    return 0;
  }
  */
  return 0;
}

static int ossfs_readlink(const char *path, char *buf, size_t size)
{
	gint res;
	struct stat st;
	OssObject *object;
	GError *error;
	gsize cnt;

        g_debug("ossfs_readlink(path=%s, size=%d)", path, size);
	g_return_val_if_fail(size >= 0, -EINVAL);

	object = oss_object_new(path);
	if (!object) return -ENOMEM;

	error = NULL;
	res = oss_object_get(service, object, &error);
	if (res) {
	  if (error->code == OSS_ERROR_NO_SUCH_KEY) res = -ENOENT;
	  else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
	  else res = -EIO;

	  oss_object_destroy(object);
	  g_error_free(error);
	  return res;
	}
	
	if (object->size < (off_t)size) size = object->size;
	cnt = fread(buf, 1, size, object->content);
	if (ferror(object->content)) return -EIO;
	buf[cnt] = '\0';
        g_debug("read %d bytes '%s'", size, buf);

	oss_object_destroy(object);
	return 0;
}


static int ossfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
  OssListBucketResult *lbr;
  OssObject *src;
  GError *error;
  gint res;
  /*GString *query;*/
  GSList *cur;
  struct stat stbuf;
  gchar *name;
  gchar prefix[PATH_MAX];
  gsize len;
  OssListBucketQuery *query;

  g_debug("ossfs_readdir(path=%s)", path);
  res = 0;
  /*
  query = g_string_sized_new(48);
  if (!query) return -ENOMEM;

  g_string_append(query, "/");
  if (g_strcmp0(path, "/")) {
    g_string_append(query, "?prefix=");

    if (g_str_has_prefix(path, "/")) {
      len = g_strlcpy(prefix, path + 1, PATH_MAX);
    } else {
      len = g_strlcpy(prefix, path, PATH_MAX);
    }
    if (!g_str_has_suffix(path, "/")) {
      prefix[len] = '/';
      prefix[len+1] = '\0';
    }
    g_string_append(query, prefix);
    g_string_append(query, "&");
  } else {
    prefix[0] = '\0';
    g_string_append_c(query, '?');
  }
  g_string_append(query, "delimiter=/");
  */

  if (g_str_has_prefix(path, "/")) {
    len = g_strlcpy(prefix, path + 1, PATH_MAX);
  } else {
    len = g_strlcpy(prefix, path, PATH_MAX);
  }
  if (!g_str_has_suffix(path, "/")) {
    prefix[len] = '/';
    prefix[len+1] = '\0';
  }
  query = oss_list_bucket_query_new();
  if (query == NULL) return -ENOMEM;
  query->prefix = g_strdup(prefix);
  query->delimiter = g_strdup("/");

  lbr = NULL;
  do {
    if (lbr != NULL) {
      if (query->marker) g_free(query->marker);
      query->marker = g_strdup(lbr->next_marker);

      oss_bucket_get_destroy(lbr);
    }

    error = NULL;
    lbr = oss_bucket_get(service, bucket, query, &error);
    if (!lbr) {
      if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
      else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
      else {
        g_message("oss_bucket_get return %d: %s", error->code, error->message);
        res = -EIO;
      }

      /*g_string_free(query, TRUE);*/
      if (lbr) oss_bucket_get_destroy(lbr);
      oss_list_bucket_query_destroy(query);
      g_error_free(error);
      return res;
    }
    /*g_string_free(query, TRUE);*/

    cur = lbr->contents;
    while (cur) {
      src = (OssObject*)cur->data;
      g_debug("ossfs_readdir process object '%s'", src->key);
      memset(&stbuf, 0, sizeof(struct stat));
      res = ossfs_getattr(src->key, &stbuf);
      if (res) {
	g_warning("ossfs_readdir get object '%s' attribute failed, ignore it", src->key);
	cur = cur->next;
	continue;
      }
      if (g_str_has_prefix(src->key, prefix)) {
        name = src->key + strlen(prefix);
      } else {
        name = src->key;
      }
      if (name == NULL || *name == '\0' || g_strcmp0(name, "/") == 0) {
        cur = cur->next;
        continue;
      }
      filler(buf, name, &stbuf, 0);
      cur = cur->next;
    }
    cur = lbr->common_prefixes;
    while (cur) {
      g_debug("ossfs_readdir process directory '%s'", (gchar*)cur->data);
      memset(&stbuf, 0, sizeof(struct stat));
      res = ossfs_getattr((gchar*)cur->data, &stbuf);
      if (res) {
	g_warning("ossfs_readdir get object '%s' attribute failed, ignore it", (gchar*)cur->data);
        cur = cur->next;
        continue;
      }
      if (g_str_has_prefix((gchar*)cur->data, prefix)) {
        name = (gchar*)cur->data + strlen(prefix);
      } else {
        name = (gchar*)cur->data;
      }
      filler(buf, name, &stbuf, 0);
      cur = cur->next;
    }
  } while (lbr->next_marker && strlen(lbr->next_marker) > 0);

  oss_list_bucket_query_destroy(query);
  oss_bucket_get_destroy(lbr);
  return res;
}

static int ossfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
  gint res;
  OssObject *object;
  GError *error;
  GString *dir;

  g_debug("ossfs_mknod(path=%s, mode=%d)", path, mode);
  dir = g_string_new(path);
  if (S_ISDIR(mode)) { /* mkdir */
    g_string_append_c(dir, '/');
  }
  object = oss_object_new(dir->str);
  g_string_free(dir, TRUE);
  if (!object) return -ENOMEM;

  g_hash_table_insert(object->meta, g_strdup(OSS_META_MODE), ltos((long)mode));
  error = NULL;
  res = oss_object_put(service, object, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
    else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
    else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;

    oss_object_destroy(object);
    g_error_free(error);
    return res;
  }

  oss_object_destroy(object);
  return 0;
}

static int ossfs_mkdir(const char *path, mode_t mode)
{
  gint res;
  OssObject *object;
  GError *error;
  gchar buf[24];
  gint cnt;
  GString *dir;

  g_debug("ossfs_mkdir(path=%s, mode=%d)", path, mode);
  dir = g_string_new(path);
  g_string_append_c(dir, '/'); /* dir has suffix / in oss */
  object = oss_object_new(dir->str);
  g_string_free(dir, TRUE);
  if (!object) return -ENOMEM;

  cnt = g_snprintf(buf, 23, "%ld", (glong)(mode|S_IFDIR));
  buf[cnt] = '\0';

  g_hash_table_insert(object->meta, g_strdup(OSS_META_MODE), g_strdup(buf));
  error = NULL;
  res = oss_object_put(service, object, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
    else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
    else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;

    oss_object_destroy(object);
    g_error_free(error);
    return res;
  }

  oss_object_destroy(object);
  return 0;
}

static int ossfs_unlink(const char *path)
{
  gint res;
  GError *error;

  g_debug("ossfs_unlink(path=%s)", path);
  error = NULL;
  res = oss_object_delete(service, path, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
    else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
    else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;

    g_error_free(error);
    return res;
  }

  cache_remove((gpointer)path);
  return 0;
}

static int ossfs_rmdir(const char *path)
{
  OssListBucketResult *lbr;
  GError *error;
  /*GString *query;*/
  gint res;
  gchar prefix[PATH_MAX];
  gsize len;
  OssListBucketQuery *query;

  g_debug("ossfs_rmdir(path=%s)", path);
  /*query = g_string_sized_new(48);
  if (!query) return -ENOMEM;

  g_string_append(query, "/");
  g_string_append(query, "?prefix=");
  if (g_str_has_prefix(path, "/")) {
    len = g_strlcpy(prefix, path+1, PATH_MAX);
  } else {
    len = g_strlcpy(prefix, path, PATH_MAX);
  }
  if (!g_str_has_suffix(path, "/")) {
    prefix[len] = '/';
    prefix[len+1] = '\0';
  }
  g_string_append(query, prefix);
  g_string_append(query, "&delimiter=/&max-keys=2");*/

  if (g_str_has_prefix(path, "/")) {
    len = g_strlcpy(prefix, path+1, PATH_MAX);
  } else {
    len = g_strlcpy(prefix, path, PATH_MAX);
  }
  if (!g_str_has_suffix(path, "/")) {
    prefix[len] = '/';
    prefix[len+1] = '\0';
  }
  query = oss_list_bucket_query_new();
  if (query == NULL) return -ENOMEM;
  query->prefix = g_strdup(prefix);
  query->delimiter = g_strdup("/");
  query->max_keys = 2;

  error = NULL;
  lbr = oss_bucket_get(service, bucket, query, &error);
  if (!lbr) {
    if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
    else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
    else res = -EIO;

    /*g_string_free(query, TRUE);*/
    oss_list_bucket_query_destroy(query);
    g_error_free(error);
    return res;
  }
  /*g_string_free(query, TRUE);*/
  oss_list_bucket_query_destroy(query);
  g_error_free(error);

  if (g_slist_length(lbr->contents) > 1 || g_slist_length(lbr->common_prefixes)) {
    oss_bucket_get_destroy(lbr);
    return -ENOTEMPTY;
  }
  oss_bucket_get_destroy(lbr);

  error = NULL;
  res = oss_object_delete(service, prefix, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
    else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
    else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;
    g_error_free(error);
    return res;
  }

  return 0;
}

static int ossfs_symlink(const char *from, const char *to)
{
  gint res;
  OssObject *object;
  GError *error;
  FILE *f;
  gsize cnt;

  g_debug("ossfs_symlink(from=%s, to=%s)", from, to);
  object = oss_object_new(to);
  if (!object) return -ENOMEM;

  g_hash_table_insert(object->meta, g_strdup(OSS_META_MODE), ltos((long)(default_mode | S_IFLNK)));
  f = tmpfile();
  if (f == NULL) {
    oss_object_destroy(object);
    return -errno;
  }
  object->content = f;

  cnt = fwrite(from, 1, strlen(from), f);
  if (cnt < strlen(from)) {
    oss_object_destroy(object);
    return -EIO;
  }
  rewind(f);

  error = NULL;
  res = oss_object_put(service, object, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
    else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
    else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;

    oss_object_destroy(object);
    g_error_free(error);
    return res;
  }

  cache_remove(object->key);
  oss_object_destroy(object);
  return 0;
}

static int ossfs_rename(const char *from, const char *to)
{
  gint res;
  struct stat stbuf;

  g_debug("ossfs_rename(from=%s, to=%s)", from, to);
  res = 0;
  res = ossfs_getattr(from, &stbuf);
  if (res) return res;
  
  if (S_ISDIR(stbuf.st_mode)) {
    res = rename_directory(from, to);
  } else {
    res = rename_object(from, to);
  }

  cache_remove((gpointer)from);
  cache_remove((gpointer)to);
  return res;
}

static int ossfs_link(const char *from, const char *to)
{
  return -EPERM;
}

static int ossfs_chmod(const char *path, mode_t mode)
{
  gint res;
  OssObject *object;
  GError *error;
  GString *dir;
  struct stat stbuf;

  g_debug("ossfs_chmod(path=%s, mode=%d)", path, mode);
  dir = g_string_new(path);
  if (S_ISDIR(mode)) { /* path is a directory */
    g_debug("%s is a directory", path);
    g_string_append_c(dir, '/');
  }
  object = oss_object_new(dir->str);
  g_string_free(dir, TRUE);
  if (!object) return -ENOMEM;
  error = NULL;
  res = oss_object_head(service, object, &error);
  if (res) {
    oss_object_destroy(object);
    g_error_free(error);
    switch (error->code) {
    case OSS_ERROR_NO_SUCH_KEY:
      return -ENOENT;
    }
    return -EIO;
  }

  g_hash_table_insert(object->meta, g_strdup(OSS_META_MODE), ltos((long)mode));
   
  error = NULL;
  res = oss_object_copy(service, object, bucket, object, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
    else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
    else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;

    oss_object_destroy(object);
    g_error_free(error);
    return res;
  }

  cache_remove(object->key);
  oss_object_destroy(object);
  return 0;
}

static int ossfs_chown(const char *path, uid_t uid, gid_t gid)
{
  /* TODO: need to implement */
  return 0;
}

static int ossfs_truncate(const char *path, off_t size)
{
  gint res;
  OssObject *object;
  GError *error;
  struct stat stbuf;

  g_debug("ossfs_truncate(path=%s, size=%ld)", path, (long)size);
  object = oss_object_new(path);
  if (!object) return -ENOMEM;

  error = NULL;
  res = oss_object_get(service, object, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_KEY) res = -ENOENT;
    else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;
    
    oss_object_destroy(object);
    g_error_free(error);
    return res;
  }

  if (object->content == NULL) {
    oss_object_destroy(object);
    return -EIO;
  }

  res = ftruncate(fileno(object->content), size);
  if (res == -1)
    return -errno;

  res = ossfs_getattr(object->key, &stbuf);
  if (res) {
    oss_object_destroy(object);
    return res;
  }
  g_hash_table_insert(object->meta, g_strdup(OSS_META_MODE), ltos((long)stbuf.st_mode));
  error = NULL;
  res = oss_object_put(service, object, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
    else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
    else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;

    oss_object_destroy(object);
    g_error_free(error);
    return res;
  }

  cache_remove(object->key);
  oss_object_destroy(object);
  return 0;
}

#ifdef HAVE_UTIMENSAT
static int ossfs_utimens(const char *path, const struct timespec ts[2])
{
  /* TODO */
  return 0;
}
#endif

static int ossfs_open(const char *path, struct fuse_file_info *fi)
{
  gint res;
  OssObject *object;
  GError *error;

  g_debug("ossfs_open(path=%s)", path);
  object = oss_object_new(path);
  if (!object) return -ENOMEM;

  error = NULL;
  res = oss_object_get(service, object, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_KEY) {
      if (fi->flags & O_CREAT) {
        g_debug("with O_CREAT: create not exited file %s", object->key);
	object->content = tmpfile();
	res = 0;
      } else {
	res = -ENOENT;
      }
    } else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;
    
    if (res) {
      oss_object_destroy(object);
      g_error_free(error);
      return res;
    } else {
      g_error_free(error);
    }
  }

  if (object->content == NULL) {
    object->content = tmpfile();
  } else if (fi->flags & O_TRUNC) {
    g_debug("with O_TRUNC: ftruncate file content");
    res = ftruncate(fileno(object->content), 0);
    if (res == -1) {
      oss_object_destroy(object);
      return -errno;
    }
  }
  g_debug("set file flags: %d", fi->flags);
  res = fcntl(fileno(object->content), F_SETFL, fi->flags);
  if (res == -1) {
    oss_object_destroy(object);
    return -errno;
  }
  fi->fh = GPOINTER_TO_INT((gpointer)object);

  return 0;
}

static int ossfs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
  int res;
  int fd;

  g_debug("ossfs_read(path=%s, size=%d, offset=%ld)", path, size, (long)offset);
  if (fi->fh == 0) return -EIO;
  fd = fileno(((OssObject*)GINT_TO_POINTER(fi->fh))->content);
  if (fd == -1) return -errno;

  res = pread(fd, buf, size, offset);
  if (res == -1)
    res = -errno;

  return res;
}

static int ossfs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
  int res;
  int fd;

  g_debug("ossfs_write(path=%s, size=%d, offset=%ld)", path, size, (long)offset);
  if (fi->fh == 0) return -EIO;
  fd = fileno(((OssObject*)GINT_TO_POINTER(fi->fh))->content);
  if (fd == -1) return -errno;

  res = pwrite(fd, buf, size, offset);
  if (res == -1)
    res = -errno;

  return res;
}

static int ossfs_statfs(const char *path, struct statvfs *stbuf)
{
  /* TODO: how to get oss stat info */
  stbuf->f_bsize = 0x1000000;
  stbuf->f_blocks = 0x1000000;
  stbuf->f_bfree = 0x1000000;
  stbuf->f_bavail = 0x1000000;
  stbuf->f_namemax = OSS_OBJECT_KEY_MAX;
  return 0;
}

static int ossfs_flush(const char *path, struct fuse_file_info *fi)
{
  gint res;
  OssObject *object;
  GError *error;

  g_debug("ossfs_flush(path=%s)", path);
  if (fi->fh == 0) return -EIO;
  object = (OssObject*)GINT_TO_POINTER(fi->fh);
  error = NULL;
  res = oss_object_put(service, object, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
    else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
    else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;

    g_error_free(error);
    return res;
  }

  if (cache_contains(object->key)) {  
    cache_remove(object->key);
  }
  return 0;
}

static int ossfs_release(const char *path, struct fuse_file_info *fi)
{
  gint res;
  OssObject *object;
  GError *error;

  g_debug("ossfs_release(path=%s)", path);
  if (fi->fh == 0) return -EIO;
  object = (OssObject*)GINT_TO_POINTER(fi->fh);
  if (cache_contains(object->key)) {
    cache_remove(object->key);
  }
  oss_object_destroy(object);
  return 0;
}

static int ossfs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
  /* TODO */
  return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int ossfs_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
  /* TODO */
  return 0;
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int ossfs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
  /* TODO */
  return 0;
}

static int ossfs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
  /* TODO */
  return 0;
}

static int ossfs_listxattr(const char *path, char *list, size_t size)
{
  /* TODO */
  return 0;
}

static int ossfs_removexattr(const char *path, const char *name)
{
  /* TODO */
  return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations ossfs_oper = {
        .getattr	= ossfs_getattr,
	.access		= ossfs_access,
	.readlink	= ossfs_readlink,
	.readdir	= ossfs_readdir,
	.mknod		= ossfs_mknod,
	.mkdir		= ossfs_mkdir,
	.symlink	= ossfs_symlink,
	.unlink		= ossfs_unlink,
	.rmdir		= ossfs_rmdir,
	.rename		= ossfs_rename,
	.link		= ossfs_link,
	.chmod		= ossfs_chmod,
	.chown		= ossfs_chown,
	.truncate	= ossfs_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= ossfs_utimens,
#endif
	.open		= ossfs_open,
	.read		= ossfs_read,
	.write		= ossfs_write,
	.statfs		= ossfs_statfs,
	.flush          = ossfs_flush,
	.release	= ossfs_release,
	.fsync		= ossfs_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= ossfs_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= ossfs_setxattr,
	.getxattr	= ossfs_getxattr,
	.listxattr	= ossfs_listxattr,
	.removexattr	= ossfs_removexattr,
#endif
};

static void show_help() {
  printf("Usage: %s -b <bucket name> [options] <mount point>\n", PROGRAME_NAME);
  printf("\n"
	 "Mount an Aliyun OSS bucket, which's name is <bucket name>, as a filesystem to <mount point>.\n"
	 "Options:\n"
	 "\t-b, --bucket\n"
	 "\t\tThe bucket name to mount.\n"
	 "\t-l, --log\n"
	 "\t\tThe file path to save log message.\n"
	 "\t-e, --level\n"
"\t\tThe log level, which can be one of [error, critical, warning, message, info, debug].\n"
	 "\t-h, --help\n"
	 "\t\tShow this help.\n"
	 "\t-v, --version\n"
	 "\t\tShow version.\n"
	 "\t[options]\n"
	 "\t\tRefer to fuse help info. man fusermount.\n"
	 "\n"
	 "OSS service configurations, such as host, access id, access key etc, are loaded from ~/.config/ossfs/conf file.\n"
	 "\n"
	 "Report bugs to <samsong8610@gmail.com>\n");
  exit(-1);
}

static void show_version() {
  printf(
  "Aliyun Open Storage Service File System %s\n"
  "Copyright (C) 2012 Sam Song <samsong8610@gmail.com>\n"
  "License GPL2: GNU GPL version 2 <http://gnu.org/licenses/gpl.html>\n"
  "This is free software: you are free to change and redistribute it.\n"
  "There is NO WARRANTY, to the extent permitted by law.\n", VERSION );
  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
  GHashTable *conf;
  GString *path;
  GKeyFile *kf;
  GError *error;
  int index;
  int opt;
  gchar *home;
  int fargc;
  char* fargv[10];
  int i;
  gchar *logfile;
  FILE *flog;
  int fd;
  gboolean debug;

  setlocale(LC_ALL, "");


  /*
  service = oss_service_new(NULL, NULL);
  gint r;
  OssBucket *bucket;
  OssListBucketResult *list;
  OssObject *object, *copied, *stat;
  gchar buf[255];
  GHashTableIter iter;
  gpointer key, value;
  error = NULL;
  GSList *buckets =  oss_service_get(service, &error);
  if (error) {
      g_print("oss_service_get failed: %d (%s)\n", error->code, error->message);
    g_error_free(error);
    error = NULL;
  }

  bucket = oss_bucket_new("sam-pub", OSS_ACL_PUBLIC_RW);
  error = NULL;
  r = oss_bucket_put(service, bucket, &error);
  if (r) {
    g_print("oss_service_put failed: %d (%s)\n", error->code, error->message);
    g_error_free(error);
    error = NULL;
  }
  oss_bucket_destroy(bucket);
  error = NULL;
  bucket = oss_bucket_get_acl(service, "307865669", &error);
  if (bucket == NULL) {
    g_print("oss_bucket_get_acl failed: %d (%s)\n", error->code, error->message);
    g_error_free(error);
    error = NULL;
  }
  g_print("%s has %s privilege\n", bucket->name, bucket->acl);
  oss_bucket_destroy(bucket);

  service->bucket = "307865669";
  error = NULL;
  list = oss_bucket_get(service, "/?prefix=/&delimiter=/", &error);
  if (list == NULL) {
    g_print("oss_bucket_get failed: %d (%s)\n", error->code, error->message);
    g_error_free(error);
    error = NULL;
  }
  oss_bucket_get_destroy(list);
  list = NULL;

  object = oss_object_new_file("ossfs.c", "ossfs.c", "r");
  g_hash_table_insert(object->meta, g_strdup("x-oss-meta-uid"), g_strdup("sam"));
  error = NULL;
  r = oss_object_put(service, object, &error);
  if (r) {
    g_print("oss_object_put failed: %d (%s)\n", error->code, error->message);
    g_error_free(error);
    error = NULL;
  }
  oss_object_destroy(object);
  object = NULL;

  object = oss_object_new("haha/");
  error = NULL;
  r = oss_object_put(service, object, &error);
  oss_object_destroy(object);
  object = NULL;

  object = oss_object_new("ossfs.c");
  error = NULL;
  r = oss_object_get(service, object, &error);
  if (r) {
    g_print("oss_object_get failed: %d (%s)\n", error->code, error->message);
    g_error_free(error);
    error = NULL;
  }
  while (fgets(buf, 254, object->content)) {
    fputs(buf, stdout);
  }

  copied = oss_object_new("ossfs.c.bak");
  error = NULL;
  r = oss_object_copy(service, copied, "307865669", object, &error);
  if (r) {
    g_print("oss_object_copy failed: %d (%s)\n", error->code, error->message);
    g_error_free(error);
    error = NULL;
  }
  stat = oss_object_new("ossfs.c.bak");
  error = NULL;
  r = oss_object_head(service, stat, &error);
  if (r) {
    g_print("oss_object_head failed: %d (%s)\n", error->code, error->message);
    g_error_free(error);
    error = NULL;
  }
  if (stat->meta) {
    g_hash_table_iter_init(&iter, stat->meta);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      g_print("meta[%s] = %s\n", (gchar*)key, (gchar*)value);
    }
  }

  oss_object_destroy(stat);

  error = NULL;
  r = oss_object_delete(service, copied->key, &error);
  if (r) {
    g_print("oss_object_delete failed: %d (%s)\n", error->code, error->message);
    g_error_free(error);
    error = NULL;
  }

  oss_object_destroy(copied);
  oss_object_destroy(object);
  object = NULL;

  if (buckets) {
    g_print("Got %d buckets.\n", g_slist_length(buckets));
  }

  oss_service_get_destroy(buckets);
  return 0;
  */
 
  cache_lock = g_mutex_new();
  cache_init();

  static const struct option opts[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"bucket", no_argument, NULL, 'b'},
    {"log", no_argument, NULL, 'l'},
    {"level", no_argument, NULL, 'e'},
    {0, 0, 0, 0}};
  fargc = 0;
  logfile = NULL;
  flog = NULL;
  level = G_LOG_LEVEL_MESSAGE;
  debug = FALSE;

  while ((opt = getopt_long(argc, argv, "do:fsub:vhl:e:", opts, &index)) != -1) {
    switch (opt) {
    case 0:
      break;
    case 'd':
      debug = TRUE;
      break;
    case 'o':
      break;
    case 'f':
      break;
    case 's':
      break;
    case 'u':
      break;
    case 'h':
      show_help();
      break;
    case 'v':
      show_version();
      break;
    case 'b':
      bucket = g_strdup((gchar*)optarg);
      break;
    case 'l':
      logfile = g_strdup((gchar*)optarg);
      break;
    case 'e':
      if (g_strcmp0(optarg, "error") == 0) level = G_LOG_LEVEL_ERROR;
      else if (g_strcmp0(optarg, "critical") == 0) level = G_LOG_LEVEL_CRITICAL;
      else if (g_strcmp0(optarg, "warning") == 0) level = G_LOG_LEVEL_WARNING;
      else if (g_strcmp0(optarg, "message") == 0) level = G_LOG_LEVEL_MESSAGE;
      else if (g_strcmp0(optarg, "info") == 0) level = G_LOG_LEVEL_INFO;
      else if (g_strcmp0(optarg, "debug") == 0) level = G_LOG_LEVEL_DEBUG;
      break;
    default:
      exit(EXIT_FAILURE);
    }
  }

  if (logfile) {
    flog = g_fopen((const gchar*)logfile, "a");
    if (flog == NULL) {
      g_print("open log file %s fail: %s\n", optarg, g_strerror(errno));
      exit(EXIT_FAILURE);
    }
    g_debug("log to file %s", logfile);
    g_log_set_handler(G_LOG_DOMAIN, G_LOG_LEVEL_MASK, log_to_file, flog);
  } 
 
  for (i = 0; i < argc; i++) {
    if (g_strcmp0(argv[i], "-b") && g_strcmp0(argv[i], "--bucket")
	&& g_strcmp0(argv[i], "-l") && g_strcmp0(argv[i], "--log")
	&& g_strcmp0(argv[i], "-e") && g_strcmp0(argv[i], "--level")) {
      fargv[fargc++] = argv[i];
    } else {
      i++; 
    }
  }

  home = getenv("HOME");
  if (home == NULL) {
    g_error("get home directory failed");
    exit(EXIT_FAILURE);
  }

  path = g_string_new(home);
  g_string_append_c(path, '/');
  g_string_append(path, CONFIG_PATH);
  if (g_mkdir_with_parents(path->str, 0755) == -1) {
    g_error("create config path '%s' failed: %s", path->str, g_strerror(errno));
    exit(EXIT_FAILURE);
  }
  kf = g_key_file_new();
  g_string_append_c(path, '/');
  g_string_append(path, CONFIG_FILENAME);
  error = NULL;
  if (!g_key_file_load_from_file(kf, path->str, G_KEY_FILE_NONE, &error)) {
    g_error("load config from '%s' failed: %s", path->str, error->message);
    exit(EXIT_FAILURE);
  }
  conf = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  if (g_key_file_has_key(kf, "common", "public", NULL)) {
    g_hash_table_insert(conf, OSS_CONFIG_PUBLIC, g_key_file_get_value(kf, "common", "public", NULL));
  }
  if (g_key_file_has_key(kf, "service", "scheme", NULL)) {
    g_hash_table_insert(conf, OSS_CONFIG_SCHEME, g_key_file_get_value(kf, "service", "scheme", NULL));
  }
  if (g_key_file_has_key(kf, "service", "host", NULL)) {
    g_hash_table_insert(conf, OSS_CONFIG_HOST, g_key_file_get_value(kf, "service", "host", NULL));
  }
  if (g_key_file_has_key(kf, "service", "port", NULL)) {
    g_hash_table_insert(conf, OSS_CONFIG_PORT, g_key_file_get_value(kf, "service", "port", NULL));
  }
  if (g_key_file_has_key(kf, "service", "accessid", NULL)) {
    g_hash_table_insert(conf, OSS_CONFIG_ACCESSID, g_key_file_get_value(kf, "service", "accessid", NULL));
  }
  if (g_key_file_has_key(kf, "service", "accesskey", NULL)) {
    g_hash_table_insert(conf, OSS_CONFIG_ACCESSKEY, g_key_file_get_value(kf, "service", "accesskey", NULL));
  }

  service = oss_service_new(bucket, conf);

  umask(0);
  return fuse_main(fargc, fargv, &ossfs_oper, NULL);

 }

static void print_header(gpointer key, gpointer value, gpointer user_data)
{
  g_print("%s : %s\n", (char*)key, (char*)value);
}

static void destroyer(gpointer data)
{
  g_free(data);
}

static gchar *get_current_date_time_gmt()
{
  gchar buf[50];
  time_t t = time(NULL);
  strftime(buf, sizeof(buf), GMT_FORMAT, gmtime(&t));
  return g_strdup(buf);

  /*
  GDateTime *now = g_date_time_new_now_utc();
  gchar *result = g_date_time_format(now, "%a, %d %b %Y %H:%M:%S GMT");
  g_date_time_unref(now);
  return result;
  */
}

static time_t parse_date_time_gmt(const gchar *gmt)
{
  struct tm t;
  struct tm l;
  time_t v;
  char *tz;

  tz = getenv("TZ");
  setenv("TZ", "", 1);
  strptime(gmt, GMT_FORMAT, &t);
  v = mktime(&t);

  if (tz) setenv("TZ", tz, 1);
  else unsetenv("TZ");

  tzset();
  localtime_r(&v, &l);
  return mktime(&l);
}

static gchar* ltos(glong l)
{
  gchar buf[24];
  gsize cnt;

  cnt = g_snprintf(buf, 23, "%ld", l);
  buf[cnt] = '\0';

  return g_strdup(buf);
}

static int rename_object(const char *from, const char *to)
{
  gint res;
  OssObject *src, *dst;
  GError *error;

  g_debug("rename_object(from=%s, to=%s)", from, to);
  src = oss_object_new(from);
  if (!src) return -ENOMEM;
  dst = oss_object_new(to);
  if (!dst) {
    oss_object_destroy(src);
    return -ENOMEM;
  }
  g_hash_table_insert(dst->meta, g_strdup("x-oss-metadata-directive"), g_strdup("COPY"));

  error = NULL;
  res = oss_object_copy(service, dst, bucket, src, &error);
  if (res) {
    if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
    else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
    else if (error->code == OSS_ERROR_INVALID_OBJECT_NAME) res = -ENAMETOOLONG;
    else res = -EIO;

    oss_object_destroy(src);
    oss_object_destroy(dst);
    g_error_free(error);
    return res;
  }

  res = ossfs_unlink(src->key);
  
  oss_object_destroy(src);
  oss_object_destroy(dst);
  return res;
}

static int rename_directory(const char *from, const char *to)
{
  OssListBucketResult *lbr;
  OssObject *src;
  GError *error;
  gint res;
  /*GString *query;*/
  GSList *cur;
  GString *name;
  gchar *pos;
  gchar prefix[PATH_MAX];
  gsize len;
  struct stat stbuf;
  gchar *dst;
  OssListBucketQuery *query;

  g_debug("rename_directory(from=%s, to=%s)", from, to);
  res = 0;
  /*
  query = g_string_sized_new(48);
  if (!query) return -ENOMEM;

  g_string_append(query, "/");
  g_string_append(query, "?prefix=");
  if (g_str_has_prefix(from, "/")) {
    len = g_strlcpy(prefix, from+1, PATH_MAX);
  } else {
    len = g_strlcpy(prefix, from, PATH_MAX);
  }
  if (!g_str_has_suffix(from, "/")) {
    prefix[len] = '/';
    prefix[len+1] = '\0';
  }
  g_string_append(query, prefix);
  */

  query = oss_list_bucket_query_new();
  if (query == NULL) return -ENOMEM;
  if (g_str_has_prefix(from, "/")) {
    len = g_strlcpy(prefix, from+1, PATH_MAX);
  } else {
    len = g_strlcpy(prefix, from, PATH_MAX);
  }
  if (!g_str_has_suffix(from, "/")) {
    prefix[len] = '/';
    prefix[len+1] = '\0';
  }
  query->prefix = g_strdup(prefix);  

  dst = g_strdup(to);
  if (g_str_has_suffix(dst, "/")) dst[strlen(dst)-1] = '\0';
  do {
    res = ossfs_mkdir(dst, default_mode);
    pos = strrchr(dst, '/');
    if (pos == NULL) break;
    *pos = '\0';
  } while(strlen(dst));

  error = NULL;
  lbr = NULL;
  do {
    if (lbr != NULL) {
      if (query->marker) g_free(query->marker);
      query->marker = g_strdup(lbr->next_marker);
      oss_bucket_get_destroy(lbr);
    }

    lbr = oss_bucket_get(service, bucket, query, &error);
    if (!lbr) {
      if (error->code == OSS_ERROR_NO_SUCH_BUCKET) res = -ENOENT;
      else if (error->code == OSS_ERROR_ACCESS_DENIED) res = -EACCES;
      else res = -EIO;

      /*g_string_free(query, TRUE);*/
      if (lbr) oss_bucket_get_destroy(lbr);
      oss_list_bucket_query_destroy(query);
      g_error_free(error);
      return res;
    }
    /*g_string_free(query, TRUE);*/

    name = g_string_sized_new(48);
    cur = lbr->contents;
    while (cur) {
      src = (OssObject*)cur->data;
      /*
      if (g_strcmp0(src->key, prefix) == 0) {
        cur = cur->next;
        continue;
      }
      */
      if (g_str_has_prefix(to, "/")) {
        g_string_append(name, to+1);
      } else {
        g_string_append(name, to);
      }
      if (!g_str_has_suffix(to, "/")) {
        g_string_append_c(name, '/');
      }
      g_string_append(name, src->key + strlen(prefix));
      res = rename_object(src->key, name->str);
      if (res) break;
      g_string_erase(name, 0, name->len);
      cur = cur->next;
    }

    g_string_free(name, TRUE);
  } while (lbr->next_marker && strlen(lbr->next_marker) > 0);

  oss_list_bucket_query_destroy(query);
  oss_bucket_get_destroy(lbr);
  return res;
}

static void cache_init(void)
{
  g_mutex_lock(cache_lock);
  if (cache == NULL) {
    cache = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_free);
  }
  g_mutex_unlock(cache_lock);
}

static void cache_add(gpointer key, gpointer value)
{
  g_message("cache_add(key='%s')", (gchar*)key);
  g_mutex_lock(cache_lock);
  g_hash_table_insert(cache, key, value);
  g_mutex_unlock(cache_lock);
}
static void cache_remove(gpointer key)
{
  g_message("cache_remove(key='%s')", (gchar*)key);
  g_mutex_lock(cache_lock);
  g_hash_table_remove(cache, key);
  g_mutex_unlock(cache_lock);
}
static gboolean cache_contains(gpointer key)
{
  return g_hash_table_contains(cache, key);
}
static gpointer cache_lookup(gpointer key)
{
  return g_hash_table_lookup(cache, key);
}

void log_to_file(const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
  gchar *level_message;
  FILE *f;

  if (log_level > level) return;

  if (log_level & G_LOG_LEVEL_ERROR) level_message = "Error";
  else if (log_level & G_LOG_LEVEL_CRITICAL) level_message = "Critical";
  else if (log_level & G_LOG_LEVEL_WARNING) level_message = "Warning";
  else if (log_level & G_LOG_LEVEL_MESSAGE) level_message = "Message";
  else if (log_level & G_LOG_LEVEL_INFO) level_message = "Info";
  else if (log_level & G_LOG_LEVEL_DEBUG) level_message = "Debug";

  f = (FILE*)user_data;
  g_fprintf(f, "[%ld][%s] - %s\n", (long)time(NULL), level_message, message);
  fflush(f);
}
