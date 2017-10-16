#ifndef _ALOG_MQ_H_
#define _ALOG_MQ_H_

#include <ngx_core.h>

typedef struct alog_mq_msg_s alog_mq_msg_t;

struct alog_mq_msg_s {
    ngx_str_t msg;
    ngx_queue_t queue;
};

typedef struct alog_mq_s alog_mq_t;

struct alog_mq_s {
    ngx_queue_t queue;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};


alog_mq_t *alog_mq_create(ngx_cycle_t *cycle);
void alog_mq_release(alog_mq_t *mq);


void alog_mq_push(alog_mq_t *mq, alog_mq_msg_t *mq_msg);
void alog_mq_pop(alog_mq_t *mq, alog_mq_msg_t **mq_msg);
#endif
