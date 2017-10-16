#include "alog_mq.h"
#include <pthread.h>

alog_mq_t *alog_mq_create(ngx_cycle_t *cycle)
{
    alog_mq_t *alog_mq;
    alog_mq = ngx_pcalloc(cycle->pool, sizeof(alog_mq_t));
    if (alog_mq == NULL) {
        return NULL;
    }

    ngx_queue_init(&alog_mq->queue);

    pthread_mutex_init(&alog_mq->lock, NULL);
    pthread_cond_init(&alog_mq->cond, NULL);

    return alog_mq;
}

void alog_mq_release(alog_mq_t *mq)
{
    if (mq == NULL) {
        return;
    }

    pthread_mutex_destroy(&mq->lock);
    pthread_cond_destroy(&mq->cond);

    free(mq);
}


void alog_mq_push(alog_mq_t *mq, alog_mq_msg_t *mq_msg)
{
    u_char *p;
    alog_mq_msg_t *it;

    if (mq == NULL || mq_msg == NULL) {
        return ;
    }
    //To optimize
    it = (alog_mq_msg_t *)malloc(sizeof(alog_mq_msg_t));

    /* allow pushing a empty msg to wakeup log thread */
    if (mq_msg->msg.len != 0) {
        it->msg.data = (u_char *)malloc(mq_msg->msg.len);

        if (it->msg.data == NULL) {
            return;
        }

        p = ngx_cpymem(it->msg.data, mq_msg->msg.data, mq_msg->msg.len);
        it->msg.len = mq_msg->msg.len;
    } else {
        it->msg.data = NULL;
        it->msg.len = 0;
    }

    pthread_mutex_lock(&mq->lock);

    ngx_queue_init(&it->queue);
    ngx_queue_insert_head(&mq->queue, &it->queue);

    pthread_cond_signal(&mq->cond);
    pthread_mutex_unlock(&mq->lock);
}

void alog_mq_pop(alog_mq_t *mq, alog_mq_msg_t **mq_msg)
{
    alog_mq_msg_t *it;
    ngx_queue_t *q;
    *mq_msg = NULL;

    pthread_mutex_lock(&mq->lock);

    while (ngx_queue_empty(&mq->queue)) {
        pthread_cond_wait(&mq->cond, &mq->lock);
    }

    q = ngx_queue_last(&mq->queue);
    it=ngx_queue_data(q, alog_mq_msg_t, queue);
    if (it) {
        *mq_msg = it;
    }
    ngx_queue_remove(q);

    pthread_mutex_unlock(&mq->lock);
}

