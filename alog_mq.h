#ifndef _ALOG_MQ_H_
#define _ALOG_MQ_H_

#include <ngx_core.h>

typedef struct alog_mq_msg_s alog_mq_msg_t;
struct alog_mq_msg_s {
        ngx_str_t msg;
        alog_mq_msg_t *next;
};

typedef struct alog_mq_s alog_mq_t;

alog_mq_t *alog_mq_create(void);
void alog_mq_release(alog_mq_t *mq);

ngx_uint_t alog_mq_empty(alog_mq_t *mq);

void alog_mq_push(alog_mq_t *mq, alog_mq_msg_t *mq_msg);
void alog_mq_pop(alog_mq_t *mq, alog_mq_msg_t **mq_msg);

#endif

/* 
 * vim: ts=8 sw=8 expandtab fenc=utf-8
 */

