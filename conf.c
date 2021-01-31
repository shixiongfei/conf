/*
 * conf.c
 *
 * copyright (c) 2021 Xiongfei Shi
 *
 * author: Xiongfei Shi <xiongfei.shi(a)icloud.com>
 * license: Apache-2.0
 *
 * https://github.com/shixiongfei/conf
 */

#include "conf.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONF_LINE_MAX_SIZE 1024

typedef struct conf_node_t {
  struct conf_node_t *prev;
  struct conf_node_t *next;
  conf_value_t value;
} conf_node_t;

struct conf_t {
  conf_node_t root;
};

struct conf_iter_t {
  conf_t *conf;
  conf_node_t *p, *t;
};

static void *alloc_emul(void *ptr, size_t size) {
  if (size)
    return realloc(ptr, size);
  free(ptr);
  return NULL;
}

static void *(*conf_realloc)(void *, size_t) = alloc_emul;

void conf_setalloc(void *(*allocator)(void *, size_t)) {
  conf_realloc = allocator ? allocator : alloc_emul;
}

#define conf_malloc(size) conf_realloc(NULL, size)
#define conf_free(ptr) conf_realloc(ptr, 0)

static char *conf_strdup(const char *src) {
  char *dest;
  if (!src)
    return NULL;
  dest = (char *)conf_malloc(strlen(src) + 1);
  return strcpy(dest, src);
}

#define node_init(node)                                                        \
  do {                                                                         \
    (node)->prev = (node);                                                     \
    (node)->next = (node);                                                     \
    memset(&(node)->value, 0, sizeof(conf_value_t));                           \
  } while (0)

#define node_push(root, node)                                                  \
  do {                                                                         \
    (node)->next = (root);                                                     \
    (node)->prev = (root)->prev;                                               \
    (root)->prev->next = (node);                                               \
    (root)->prev = (node);                                                     \
  } while (0)

#define node_erase(node)                                                       \
  do {                                                                         \
    (node)->prev->next = (node)->next;                                         \
    (node)->next->prev = (node)->prev;                                         \
  } while (0)

#define node_foreach(r, p, t)                                                  \
  for ((p) = (r)->next, (t) = (p)->next; (r) != (p); (p) = (t), (t) = (p)->next)

static void node_free(conf_node_t *node) {
  conf_value_t *conf_value = &node->value;
  int i, values_capacity = conf_value->values_cnt + conf_value->values_free;

  node_erase(node);

  if (conf_value->values) {
    for (i = 0; i < values_capacity; ++i)
      if (conf_value->values[i])
        conf_free(conf_value->values[i]);
    conf_free(conf_value->values);
  }

  if (conf_value->key)
    conf_free(conf_value->key);

  if (conf_value->comment)
    conf_free(conf_value->comment);

  conf_free(node);
}

conf_t *conf_create(void) {
  conf_t *conf = (conf_t *)conf_malloc(sizeof(struct conf_t));
  node_init(&conf->root);
  return conf;
}

static void conf_clear(conf_t *conf) {
  conf_node_t *p, *t;
  node_foreach(&conf->root, p, t) { node_free(p); }
}

void conf_destroy(conf_t *conf) {
  conf_clear(conf);
  conf_free(conf);
}

static conf_node_t *conf_find(conf_t *conf, const char *key) {
  conf_node_t *p, *t;

  node_foreach(&conf->root, p, t) {
    if (0 == strcmp(key, p->value.key))
      return p;
  }
  return NULL;
}

conf_value_t *conf_get(conf_t *conf, const char *key) {
  conf_node_t *n = conf_find(conf, key);
  return n ? &n->value : NULL;
}

int conf_set(conf_t *conf, const char *key, const char **values, int count) {
  conf_value_t *conf_value = conf_get(conf, key);
  int i;

  if ((!values) || (0 == count))
    return -1;

  if (!conf_value) {
    conf_node_t *n = (conf_node_t *)conf_malloc(sizeof(struct conf_node_t));

    node_init(n);
    conf_value = &n->value;
    conf_value->key = conf_strdup(key);

    node_push(&conf->root, n);
  }

  if (conf_value->values_free < count) {
    int capacity = conf_value->values_cnt + conf_value->values_free;
    int grow_size = count - conf_value->values_free;

    conf_value->values = (char **)conf_realloc(
        conf_value->values, sizeof(char *) * (capacity + grow_size));

    for (i = 0; i < grow_size; ++i)
      conf_value->values[capacity + i] = NULL;

    conf_value->values_free += grow_size;
  }

  for (i = 0; i < count; ++i) {
    if (conf_value->values[conf_value->values_cnt + i])
      conf_free(conf_value->values[conf_value->values_cnt + i]);

    conf_value->values[conf_value->values_cnt + i] = conf_strdup(values[i]);
  }

  conf_value->values_cnt += count;
  conf_value->values_free -= count;

  return 0;
}

int conf_erase(conf_t *conf, const char *key, int index) {
  conf_node_t *n = conf_find(conf, key);
  conf_value_t *conf_value;
  int i;

  if (!n)
    return -1;

  if (index < 0) {
    node_free(n);
    return 0;
  }

  conf_value = &n->value;

  if (!conf_value)
    return -1;

  if (index >= conf_value->values_cnt)
    return -1;

  if (1 == conf_value->values_cnt) {
    node_free(n);
    return 0;
  }

  conf_free(conf_value->values[index]);
  conf_value->values[index] = NULL;

  for (i = index; i < conf_value->values_cnt - 1; ++i) {
    conf_value->values[i] = conf_value->values[i + 1];
    conf_value->values[i + 1] = NULL;
  }

  conf_value->values_cnt -= 1;
  conf_value->values_free += 1;

  return 0;
}

int conf_comment(conf_t *conf, const char *key, const char *comment) {
  conf_value_t *conf_value = conf_get(conf, key);

  if (!conf_value)
    return -1;

  if (conf_value->comment) {
    conf_free(conf_value->comment);
    conf_value->comment = NULL;
  }

  if (comment)
    conf_value->comment = conf_strdup(comment);

  return 0;
}

static void frepr(FILE *fp, const char *str) {
  static const char hextable[16] = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  };

  if (!str)
    return;

  while (*str) {
    switch (*str) {
    case '\\':
      fprintf(fp, "\\\\");
      break;
    case '\n':
      fprintf(fp, "\\n");
      break;
    case '\r':
      fprintf(fp, "\\r");
      break;
    case '\t':
      fprintf(fp, "\\t");
      break;
    case '\a':
      fprintf(fp, "\\a");
      break;
    case '\b':
      fprintf(fp, "\\b");
      break;
    case ' ':
      fprintf(fp, "\\ ");
      break;
    default:
      if (isprint(*str))
        fprintf(fp, "%c", *str);
      else {
        fprintf(fp, "\\x");
        fprintf(fp, "%c", hextable[((*str) >> 4) & 0x0f]);
        fprintf(fp, "%c", hextable[(*str) & 0x0f]);
      }
      break;
    }
    str += 1;
  }
}

int conf_save(conf_t *conf, const char *path) {
  conf_value_t *value;
  conf_iter_t *iter;
  int i;

  FILE *fp = fopen(path, "wt");

  if (!fp)
    return -1;

  iter = conf_iter(conf);

  while (!!(value = conf_next(iter))) {
    if (value->comment)
      fprintf(fp, "# %s\n", value->comment);

    fprintf(fp, "%s ", value->key);

    for (i = 0; i < value->values_cnt - 1; ++i) {
      frepr(fp, value->values[i]);
      fprintf(fp, " ");
    }

    frepr(fp, value->values[value->values_cnt - 1]);
    fprintf(fp, "\n");
  }

  conf_final(iter);
  fclose(fp);

  return 0;
}

typedef struct conf_buffer_t {
  int size, offset;
  char *data;
} conf_buffer_t;

static void buffer_init(conf_buffer_t *buffer) {
  buffer->size = 0;
  buffer->offset = 0;
  buffer->data = NULL;
}
static void buffer_destroy(conf_buffer_t *buffer) {
  if (buffer->data)
    conf_free(buffer->data);
  buffer_init(buffer);
}

static int next_power(int size) {
  if (0 == size)
    return 2;

  /* fast check if power of two */
  if (0 == (size & (size - 1)))
    return size;

  size -= 1;
  size |= size >> 1;
  size |= size >> 2;
  size |= size >> 4;
  size |= size >> 8;
  size |= size >> 16;
  size += 1;

  return size;
}

#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif

static void buffer_expandifneeded(conf_buffer_t *buffer, int len) {
  if (buffer->offset + len >= buffer->size) {
    int newsize = next_power(buffer->size << 1);

    buffer->size = max(newsize, 8);
    buffer->data = (char *)conf_realloc(buffer->data, buffer->size);
  }
}

static void buffer_append(conf_buffer_t *buffer, int ch) {
  buffer_expandifneeded(buffer, 2);

  buffer->data[buffer->offset++] = (char)ch;
  buffer->data[buffer->offset] = '\0';
}

static void buffer_reset(conf_buffer_t *buffer) {
  buffer->offset = 0;

  if (buffer->data)
    buffer->data[buffer->offset] = '\0';
}

static void buffer_trim(conf_buffer_t *buffer) {
  char *begin, *end;
  int newlen;

  if (!buffer->data)
    return;

  begin = buffer->data;
  end = begin + buffer->offset - 1;

  while (begin <= end) {
    if (!isspace(*begin))
      break;
    begin += 1;
  }

  while (end > begin) {
    if (!isspace(*end))
      break;
    end -= 1;
  }

  newlen = (int)((begin <= end) ? ((end - begin) + 1) : 0);

  if ((newlen > 0) && (buffer->data != begin))
    memmove(buffer->data, begin, newlen);

  buffer->offset = newlen;
  buffer->data[newlen] = '\0';
}

#define CONF_STATE_MAX_SIZE 8
#define CONF_VALUES_CNT 4

struct conf_token_t;
typedef int (*conf_state_cb)(conf_t *conf, struct conf_token_t *token, int ch);

typedef struct conf_token_t {
  int current_state;
  int current_value;
  int values_cnt;
  char escape[5];
  conf_state_cb state_cb[CONF_STATE_MAX_SIZE];
  conf_buffer_t comment;
  conf_buffer_t key;
  conf_buffer_t *values;
} conf_token_t;

#define conf_state_push(c, t, cb)                                              \
  do {                                                                         \
    if (((t)->current_state + 1) < CONF_STATE_MAX_SIZE) {                      \
      (t)->current_state += 1;                                                 \
      (t)->state_cb[(t)->current_state] = cb;                                  \
    }                                                                          \
  } while (0)

#define conf_state_pop(c, t)                                                   \
  do {                                                                         \
    if ((t)->current_state >= 0)                                               \
      (t)->current_state -= 1;                                                 \
  } while (0)

#define conf_state_get(c, t)                                                   \
  ((((t)->current_state >= 0) && ((t)->current_state < CONF_STATE_MAX_SIZE))   \
       ? (t)->state_cb[(t)->current_state]                                     \
       : NULL)

#define conf_state_switch(c, t, cb)                                            \
  do {                                                                         \
    (t)->current_state = 0;                                                    \
    (t)->state_cb[(t)->current_state] = cb;                                    \
  } while (0)

#define conf_state_clear(c, t)                                                 \
  do {                                                                         \
    (t)->current_state = -1;                                                   \
  } while (0)

static int conf_state_execute(conf_t *conf, conf_token_t *token, int ch) {
  conf_state_cb cb = conf_state_get(conf, token);
  if (cb)
    return cb(conf, token, ch);
  return -1;
}

static int conf_state_read_comment(conf_t *conf, conf_token_t *token, int ch) {
  buffer_append(&token->comment, ch);
  return 0;
}

static int conf_state_read_key(conf_t *conf, conf_token_t *token, int ch) {
  if (isspace(ch)) {
    conf_state_pop(conf, token);
    return 0;
  }

  if (ispunct(ch) && '-' != ch && '_' != ch)
    return -1;

  buffer_append(&token->key, ch);
  return 0;
}

static void conf_token_add_value(conf_t *conf, conf_token_t *token) {
  token->current_value += 1;

  if (token->current_value >= token->values_cnt) {
    int i, new_cnt = token->values_cnt << 1;

    token->values = (conf_buffer_t *)conf_realloc(
        token->values, sizeof(conf_buffer_t) * new_cnt);

    for (i = 0; i < (new_cnt - token->values_cnt); ++i)
      buffer_init(&token->values[token->values_cnt + i]);

    token->values_cnt = new_cnt;
  }
}

#define conf_token_append_value(c, t, ch)                                      \
  do {                                                                         \
    buffer_append(&(t)->values[(t)->current_value], ch);                       \
  } while (0)

static void conf_token_append_escape(conf_t *conf, conf_token_t *token) {
  int esc;

  switch (token->escape[0]) {
  case 'x':
    esc = (int)strtol(token->escape + 1, NULL, 16);
    break;
  case 'o':
    esc = (int)strtol(token->escape + 1, NULL, 8);
    break;
  default:
    return;
  }

  conf_token_append_value(conf, token, esc);
  conf_state_pop(conf, token);

  memset(token->escape, 0, sizeof(token->escape));
}

static int conf_token_read_digit(conf_t *conf, conf_token_t *token, int ch) {
  int ap = 0;

  switch (token->escape[0]) {
  case 'x':
    if (((ch < '0') || (ch > '9')) &&
        ((toupper(ch) < 'A') || (toupper(ch) > 'F'))) {
      if (!token->escape[1])
        return -1;
      ap = 1;
    } else {
      if ((token->escape[1]) && (token->escape[2]))
        ap = 1;
      else {
        if (!token->escape[1])
          token->escape[1] = ch;
        else if (!token->escape[2])
          token->escape[2] = ch;
      }
    }
    break;
  case 'o':
    if ((ch < '0') || (ch > '7')) {
      if (!token->escape[1])
        return -1;
      ap = 1;
    } else {
      if ((token->escape[1]) && (token->escape[2]) && (token->escape[3]))
        ap = 1;
      else {
        if (!token->escape[1])
          token->escape[1] = ch;
        else if (!token->escape[2])
          token->escape[2] = ch;
        else if (!token->escape[3])
          token->escape[3] = ch;
      }
    }
    break;
  }

  if (!ap)
    return 0;

  conf_token_append_escape(conf, token);

  return conf_state_execute(conf, token, ch);
}

static int conf_state_read_escape(conf_t *conf, conf_token_t *token, int ch) {
  switch (ch) {
  case 'b':
    ch = '\b';
    break;
  case 'r':
    ch = '\r';
    break;
  case 'n':
    ch = '\n';
    break;
  case 't':
    ch = '\t';
    break;
  case ' ':
    ch = ' ';
    break;
  case 'x':
    token->escape[0] = 'x';
    conf_state_pop(conf, token);
    conf_state_push(conf, token, conf_token_read_digit);
    return 0;
  case '0':
  case 'o':
    token->escape[0] = 'o';
    conf_state_pop(conf, token);
    conf_state_push(conf, token, conf_token_read_digit);
    return 0;
  default:
    break;
  }

  conf_token_append_value(conf, token, ch);
  conf_state_pop(conf, token);

  return 0;
}

static int conf_state_read_quote(conf_t *conf, conf_token_t *token, int ch) {
  switch (ch) {
  case '"':
    conf_state_pop(conf, token);
    break;
  case '\\':
    memset(token->escape, 0, sizeof(token->escape));
    conf_state_push(conf, token, conf_state_read_escape);
    break;
  default:
    conf_token_append_value(conf, token, ch);
  }
  return 0;
}

static int conf_state_read_values(conf_t *conf, conf_token_t *token, int ch) {
  switch (ch) {
  case '"':
    if (token->values[token->current_value].offset > 0)
      return -1;
    conf_state_push(conf, token, conf_state_read_quote);
    break;
  case '\\':
    memset(token->escape, 0, sizeof(token->escape));
    conf_state_push(conf, token, conf_state_read_escape);
    break;
  default:
    conf_token_append_value(conf, token, ch);
    break;
  }
  return 0;
}

#define CONF_STATE_IS_EMPTY(c, t) (NULL == conf_state_get(c, t))
#define CONF_STATE_IS_READ_COMMENT(c, t)                                       \
  (conf_state_read_comment == conf_state_get(c, t))
#define CONF_STATE_IS_READ_KEY(c, t)                                           \
  (conf_state_read_key == conf_state_get(c, t))
#define CONF_STATE_IS_READ_VALUE(c, t)                                         \
  (conf_state_read_values == conf_state_get(c, t))
#define CONF_STATE_IS_READ_QUOTE(c, t)                                         \
  (conf_state_read_quote == conf_state_get(c, t))
#define CONF_STATE_IS_READ_ESCAPE(c, t)                                        \
  (conf_state_read_escape == conf_state_get(c, t))
#define CONF_STATE_IS_READ_DIGIT(c, t)                                         \
  (conf_token_read_digit == conf_state_get(c, t))

static int conf_read_char(conf_t *conf, conf_token_t *token, int ch) {
  switch (ch) {
  case '#':
    if (CONF_STATE_IS_EMPTY(conf, token) ||
        CONF_STATE_IS_READ_VALUE(conf, token)) {
      buffer_reset(&token->comment); /* Clear old comment */
      conf_state_switch(conf, token, conf_state_read_comment);
      return 0;
    }
    break;
  case '=':
    if (CONF_STATE_IS_EMPTY(conf, token) ||
        CONF_STATE_IS_READ_KEY(conf, token)) {
      if (token->key.offset <= 0)
        return -1;
      conf_token_add_value(conf, token);
      conf_state_switch(conf, token, conf_state_read_values);
      return 0;
    }
    break;
  case ',':
    if (CONF_STATE_IS_EMPTY(conf, token))
      return 0;
    if (CONF_STATE_IS_READ_VALUE(conf, token)) {
      if (token->key.offset <= 0)
        return -1;
      conf_token_add_value(conf, token);
      return 0;
    }
    if (CONF_STATE_IS_READ_DIGIT(conf, token)) {
      conf_token_append_escape(conf, token);
      conf_token_add_value(conf, token);
      return 0;
    }
    break;
  case ' ':
  case '\t':
  case '\r':
  case '\n':
    if (CONF_STATE_IS_EMPTY(conf, token))
      return 0;
    if (CONF_STATE_IS_READ_KEY(conf, token)) {
      if (token->key.offset > 0)
        conf_state_pop(conf, token);
      return 0;
    }
    if (CONF_STATE_IS_READ_VALUE(conf, token)) {
      if (token->values[token->current_value].offset > 0)
        conf_state_pop(conf, token);
      return 0;
    }
    break;
  default:
    if (CONF_STATE_IS_EMPTY(conf, token)) {
      if (token->key.offset > 0) {
        conf_token_add_value(conf, token);
        conf_state_switch(conf, token, conf_state_read_values);
      } else
        conf_state_switch(conf, token, conf_state_read_key);
    }
    break;
  }

  return conf_state_execute(conf, token, ch);
}

static int conf_endline(conf_t *conf, conf_token_t *token) {
  if (CONF_STATE_IS_READ_DIGIT(conf, token))
    conf_token_append_escape(conf, token);
  return (CONF_STATE_IS_EMPTY(conf, token) ||
          CONF_STATE_IS_READ_COMMENT(conf, token) ||
          CONF_STATE_IS_READ_VALUE(conf, token))
             ? 0
             : -1;
}

static const char *conf_skip_whitespace(char *p) {
  char *end = p + strlen(p) - 1;

  while (*p) {
    if (!isspace(*p))
      break;
    p += 1;
  }

  while (end > p) {
    if (!isspace(*end))
      break;
    *end-- = '\0';
  }

  return p;
}

int conf_load(conf_t *conf, const char *path) {
  char line[CONF_LINE_MAX_SIZE] = {0};
  conf_token_t token;
  FILE *fp;
  const char *p;
  int i, retval = -1, lines = 0;

  conf_clear(conf);
  fp = fopen(path, "rt");

  if (!fp)
    return -1;

  token.current_state = -1;
  for (i = 0; i < CONF_STATE_MAX_SIZE; ++i)
    token.state_cb[i] = NULL;

  buffer_init(&token.comment);
  buffer_init(&token.key);

  token.current_value = -1;
  token.values_cnt = CONF_VALUES_CNT;
  token.values =
      (conf_buffer_t *)conf_malloc(sizeof(conf_buffer_t) * token.values_cnt);

  for (i = 0; i < token.values_cnt; ++i)
    buffer_init(&token.values[i]);

  while (fgets(line, sizeof(line), fp)) {
    lines += 1;
    p = conf_skip_whitespace(line);

    while (*p) {
      retval = conf_read_char(conf, &token, (*p++));

      if (0 != retval) {
        conf_clear(conf);
        goto break_loop;
      }
    }

    retval = conf_endline(conf, &token);

    if (0 != retval) {
      conf_clear(conf);
      goto break_loop;
    }

    if (token.key.offset > 0 && token.current_value < 0) {
      retval = -1;
      conf_clear(conf);
      goto break_loop;
    }

    if (token.key.offset > 0 && token.current_value >= 0) {
      buffer_trim(&token.comment);

      for (i = 0; i < token.current_value + 1; ++i)
        conf_set(conf, token.key.data, (const char **)&token.values[i].data, 1);

      if (token.comment.offset > 0)
        conf_comment(conf, token.key.data, token.comment.data);

      buffer_reset(&token.comment);
      buffer_reset(&token.key);

      for (i = 0; i < token.current_value + 1; ++i)
        buffer_reset(&token.values[i]);

      token.current_value = -1;
    }

    conf_state_clear(conf, &token);
  }

break_loop:

  fclose(fp);

  buffer_destroy(&token.comment);
  buffer_destroy(&token.key);

  for (i = 0; i < token.values_cnt; ++i)
    buffer_destroy(&token.values[i]);

  conf_free(token.values);

  return (0 == retval) ? retval : (lines * (-1));
}

int conf_count(conf_t *conf) {
  conf_node_t *p, *t;
  int counter = 0;

  node_foreach(&conf->root, p, t) counter += 1;
  return counter;
}

conf_iter_t *conf_iter(conf_t *conf) {
  conf_iter_t *iter = (conf_iter_t *)conf_malloc(sizeof(struct conf_iter_t));

  iter->conf = conf;
  iter->p = conf->root.next;
  iter->t = iter->p->next;

  return iter;
}

conf_value_t *conf_next(conf_iter_t *iter) {
  conf_node_t *n;

  if (iter->p == &iter->conf->root)
    return NULL;

  n = iter->p;

  iter->p = iter->t;
  iter->t = iter->p->next;

  return &n->value;
}

void conf_final(conf_iter_t *iter) { conf_free(iter); }
