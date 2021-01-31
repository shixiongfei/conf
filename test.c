/*
 * test.c
 *
 * copyright (c) 2021 Xiongfei Shi
 *
 * author: Xiongfei Shi <xiongfei.shi(a)icloud.com>
 * license: Apache-2.0
 *
 * https://github.com/shixiongfei/conf
 */

#include "conf.h"
#include <stdio.h>

static void show_conf(const char *conf_file) {
  conf_t *l;
  conf_iter_t *iter;
  conf_value_t *value;
  int i;

  l = conf_create();
  conf_load(l, conf_file);

  printf("%s Key Count: %d\n", conf_file, conf_count(l));
  printf("------------------------------\n");

  iter = conf_iter(l);

  while (!!(value = conf_next(iter))) {
    if (value->comment)
      printf("# %s\n", value->comment);

    printf("%s(%d) =", value->key, value->values_cnt);

    for (i = 0; i < value->values_cnt; ++i)
      printf(" %s", value->values[i]);

    printf("\n");
  }

  conf_final(iter);
  conf_destroy(l);

  printf("------------------------------\n");
}

int main(int argc, char *argv[]) {
  conf_t *s;
  const char *v;

  s = conf_create();

  v = "test-value1";
  conf_set(s, "test-key1", &v, 1);

  v = "test-value2";
  conf_set(s, "test-key1", &v, 1);

  v = "test-value3";
  conf_set(s, "test-key1", &v, 1);

  conf_erase(s, "test-key1", 1);
  conf_comment(s, "test-key1", "test 1");

  v = "world!";
  conf_set(s, "hello", &v, 1);
  conf_comment(s, "hello", "Hello World");

  v = "中文测试";
  conf_set(s, "中文健", &v, 1);

  v = "The is a text line.\nSecond line!";
  conf_set(s, "line", &v, 1);
  conf_comment(s, "line", "REPR");

  conf_save(s, "test.conf");
  conf_destroy(s);

  show_conf("sample.conf");
  show_conf("test.conf");

  return 0;
}
