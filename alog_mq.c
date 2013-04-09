#include "alog_mq.h"
#include <pthread.h>

struct alog_mq_s {
        alog_mq_msg_t *head;
        alog_mq_msg_t *tail;

        pthread_mutex_t lock;
        pthread_cond_t cond;
};

alog_mq_t *alog_mq_create(void)
{
        alog_mq_t *alog_mq;

        alog_mq = (alog_mq_t *)malloc(sizeof(alog_mq_t));

        if (alog_mq == NULL) {
                return NULL;
        }

        alog_mq->head = NULL;
        alog_mq->tail = NULL;

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

        mq->head = NULL;
        mq->tail = NULL;

        free(mq);
}

ngx_uint_t alog_mq_empty(alog_mq_t *mq)
{
        ngx_uint_t empty;

        if (mq == NULL) {
                return 1;
        }

        pthread_mutex_lock(&mq->lock);
        empty = (mq->head == NULL) ? 1 : 0;
        pthread_mutex_unlock(&mq->lock);

        return empty;
}

void alog_mq_push(alog_mq_t *mq, alog_mq_msg_t *mq_msg)
{
        u_char *p;
        alog_mq_msg_t *msg;

        if (mq == NULL || mq_msg == NULL) {
                return; 
        }

        msg = (alog_mq_msg_t *)malloc(sizeof(alog_mq_msg_t));

        if (msg == NULL) {
                return; 
        }

        msg->next = NULL; 

        /* allow pushing a empty msg to wakeup log thread */
        if (mq_msg->msg.len != 0) {
                msg->msg.data = (u_char *)malloc(mq_msg->msg.len);

                if (msg->msg.data == NULL) {
                        return; 
                }

                p = ngx_cpymem(msg->msg.data, mq_msg->msg.data, mq_msg->msg.len);
                msg->msg.len = mq_msg->msg.len;
        } else {
                msg->msg.data = NULL;
                msg->msg.len = 0;
        }

        pthread_mutex_lock(&mq->lock);

        if (mq->tail == NULL) {
                mq->head = msg;
        } else {
                mq->tail->next = msg;
        }

        mq->tail = msg;

        pthread_cond_signal(&mq->cond);
        pthread_mutex_unlock(&mq->lock);
}

void alog_mq_pop(alog_mq_t *mq, alog_mq_msg_t **mq_msg)
{
        alog_mq_msg_t *msg;

        if (mq == NULL || (*mq_msg) == NULL) {
                return;
        }
        
        pthread_mutex_lock(&mq->lock);

        while (mq->head == NULL) {
                pthread_cond_wait(&mq->cond, &mq->lock);
        }

        msg = mq->head;

        if (msg != NULL) {
                mq->head = msg->next;

                if (mq->head == NULL) {
                        mq->tail = NULL;
                }
        }

        pthread_mutex_unlock(&mq->lock);

        *mq_msg = NULL;
        
        if (msg != NULL) {
                /* pop zero copy */
                *mq_msg = msg;
        }
}

/* 
 * vim: ts=8 sw=8 expandtab fenc=utf-8
 */

