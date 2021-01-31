/*
 * conf.h
 *
 * copyright (c) 2021 Xiongfei Shi
 *
 * author: Xiongfei Shi <xiongfei.shi(a)icloud.com>
 * license: Apache-2.0
 *
 * https://github.com/shixiongfei/conf
 */

#ifndef __CONF_H__
#define __CONF_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct conf_t conf_t;
typedef struct conf_iter_t conf_iter_t;

typedef struct conf_value_t {
  int values_free;
  int values_cnt;
  char *comment;
  char *key;
  char **values;
} conf_value_t;

void conf_setalloc(void *(*allocator)(void *, size_t));

conf_t *conf_create(void);
void conf_destroy(conf_t *conf);

conf_value_t *conf_get(conf_t *conf, const char *key);
int conf_set(conf_t *conf, const char *key, const char **values, int count);
int conf_erase(conf_t *conf, const char *key, int index);
int conf_comment(conf_t *conf, const char *key, const char *comment);

int conf_save(conf_t *conf, const char *path);
int conf_load(conf_t *conf, const char *path);
int conf_count(conf_t *conf);

conf_iter_t *conf_iter(conf_t *conf);
conf_value_t *conf_next(conf_iter_t *iter);
void conf_final(conf_iter_t *iter);

#ifdef __cplusplus
};
#endif

#endif /* __CONF_H__ */
