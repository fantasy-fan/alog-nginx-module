#include "alog_mq.h"

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <pthread.h>

#define NGX_ALOG_ERR     0
#define NGX_ALOG_WARN    1
#define NGX_ALOG_INFO    2
#define NGX_ALOG_DEBUG   3

typedef struct {
        u_char *start;
        u_char *pos;
} ngx_http_alog_buf_t;

typedef struct {
        int log_level;
        size_t buf_size;

        ngx_http_alog_buf_t log_buf;
} ngx_http_alog_main_conf_t;

typedef struct {
        ngx_str_t raw_value;    /* store raw str value */
        
        ngx_array_t *lengths;
        ngx_array_t *values;
} ngx_http_alog_script_t;

typedef struct {
        ngx_http_alog_script_t *script; /* nginx variables */
        int level;

        unsigned flush:1;
} ngx_http_alog_t;

typedef struct {
        ngx_array_t *logs;      /* array of ngx_http_alog_t */
} ngx_http_alog_loc_conf_t;

typedef struct {
        pthread_t tid;  /* pthread id, not real thread id */
        ngx_open_file_t *log_file;
        alog_mq_t *mq;

        unsigned stop:1;
} alog_log_thread_ctx_t;

alog_log_thread_ctx_t alog_log_thread_ctx = { 0, NULL, NULL, 0 };

static char *ngx_http_alog_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_alog_write_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_alog_commands[] = {

      { ngx_string("alog_set"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_1MORE,
        ngx_http_alog_set_log,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },

      { ngx_string("alog"),
        NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
        ngx_http_alog_write_log,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

        ngx_null_command
};

static ngx_int_t ngx_http_alog_init(ngx_conf_t *cf);
static void *ngx_http_alog_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_alog_create_loc_conf(ngx_conf_t *cf);

static ngx_http_module_t ngx_http_alog_module_ctx = {
        NULL,                           /* preconfiguration */
        ngx_http_alog_init,             /* postconfiguration */

        ngx_http_alog_create_main_conf, /* create main configuration */
        NULL,                           /* init main configuration */

        NULL,                           /* create server configuration */
        NULL,                           /* merge server configuration */

        ngx_http_alog_create_loc_conf,  /* create location configuration */
        NULL,                           /* merge location configuration */
};

static ngx_int_t ngx_http_alog_process_init(ngx_cycle_t * cycle);
static void ngx_http_alog_process_exit(ngx_cycle_t * cycle);

ngx_module_t ngx_http_alog_module = {
    NGX_MODULE_V1,
    &ngx_http_alog_module_ctx,          /* module context */
    ngx_http_alog_commands,             /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    ngx_http_alog_process_init,         /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    ngx_http_alog_process_exit,         /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_alog_write(ngx_http_request_t *r, u_char *buf, size_t len, unsigned flush);

static ngx_int_t ngx_http_alog_handler(ngx_http_request_t *r)
{
        u_char *line, *p;
        ngx_str_t *computed_log;

        ngx_uint_t l, log_msg_len;
        ngx_http_alog_t *log;

        ngx_http_alog_main_conf_t *lmcf;
        ngx_http_alog_loc_conf_t *llcf;

        lmcf = ngx_http_get_module_main_conf(r, ngx_http_alog_module);
        llcf = ngx_http_get_module_loc_conf(r, ngx_http_alog_module);

        if (lmcf->log_level == NGX_CONF_UNSET || llcf->logs == NULL) {
                return NGX_OK;
        }

        log = llcf->logs->elts;

        for (l = 0; l < llcf->logs->nelts; l++) {

                /* if current log level less than log_level setting, just skip.
                 * actually, low level logs should already have been skipped befroe */
                if (log[l].level < lmcf->log_level) {
                        continue;
                }

                computed_log = NULL;

                if (log[l].script->lengths == NULL) {
                        computed_log = &(log[l].script->raw_value);
                } else {
                        computed_log = ngx_pcalloc(r->pool, sizeof(ngx_str_t));

                        if (computed_log == NULL) {
                                return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        if (ngx_http_script_run(r, computed_log, log[l].script->lengths->elts, 0, log[l].script->values->elts) == NULL) {
                                return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        } 
                }

                if (computed_log == NULL) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                log_msg_len = computed_log->len;
                log_msg_len += NGX_LINEFEED_SIZE;

                line = ngx_pcalloc(r->pool, log_msg_len);

                if (line == NULL) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                p = line;
                p = ngx_cpymem(line, computed_log->data, computed_log->len);
                ngx_linefeed(p);

                if (ngx_http_alog_write(r, line, log_msg_len, log[l].flush) != (ngx_int_t)log_msg_len) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
        }

        return NGX_OK;
}

static ngx_int_t ngx_http_alog_write(ngx_http_request_t *r, u_char *buf, size_t len, unsigned flush)
{
        ngx_http_alog_main_conf_t *lmcf;
        size_t write_bytes, retval_len;
        
        lmcf = ngx_http_get_module_main_conf(r, ngx_http_alog_module);

        if (lmcf->buf_size == 0) {
                alog_mq_msg_t mq_msg;
                mq_msg.msg.data = buf;
                mq_msg.msg.len = len;
                alog_mq_push(alog_log_thread_ctx.mq, &mq_msg);

                retval_len = len;
        } else {
                /* log msg is too long to put into log buffer */
                if (len > lmcf->buf_size) {
                        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, 
                                        "log msg is too long to put into log buffer. log len: %lu, buf size: %lu", len, lmcf->buf_size);
                        return 0;
                }

                /* left space of log buffer can not store current log msg */
                if (((lmcf->log_buf.pos - lmcf->log_buf.start) + len) > lmcf->buf_size) {
                        write_bytes = lmcf->log_buf.pos - lmcf->log_buf.start;

                        alog_mq_msg_t mq_msg;
                        mq_msg.msg.data = lmcf->log_buf.start;
                        mq_msg.msg.len = write_bytes;
                        alog_mq_push(alog_log_thread_ctx.mq, &mq_msg);

                        lmcf->log_buf.pos = lmcf->log_buf.start;
                }

                lmcf->log_buf.pos = ngx_cpymem(lmcf->log_buf.pos, buf, len);
                retval_len = len;

                if (flush) {
                        write_bytes = lmcf->log_buf.pos - lmcf->log_buf.start;

                        alog_mq_msg_t mq_msg;
                        mq_msg.msg.data = lmcf->log_buf.start;
                        mq_msg.msg.len = write_bytes;
                        alog_mq_push(alog_log_thread_ctx.mq, &mq_msg);

                        lmcf->log_buf.pos = lmcf->log_buf.start;
                }
        }

        return retval_len;
}

static void *ngx_http_alog_create_main_conf(ngx_conf_t *cf)
{
        ngx_http_alog_main_conf_t *conf;

        conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_alog_main_conf_t));

        if (conf == NULL) {
                return NULL;
        }

        /*
         * set by ngx_pcalloc():
         *
         *      conf->log_buf.start = NULL;
         *      conf->log_buf.pos = NULL;
         */

        conf->log_level = NGX_CONF_UNSET;
        conf->buf_size = NGX_CONF_UNSET_SIZE;

        return conf; 
}

static void *ngx_http_alog_create_loc_conf(ngx_conf_t *cf)
{
        ngx_http_alog_loc_conf_t *conf;

        conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_alog_loc_conf_t));

        if (conf == NULL) {
                return NULL;
        }

        /*
         * set by ngx_pcalloc():
         *
         *      conf->logs = NULL;
         */

        return conf; 
}

static int alog_parse_log_level(ngx_str_t *s)
{
        int log_level;

        if (s->data == NULL || s->len == 0) {
                return NGX_CONF_UNSET; 
        }

        if (ngx_strncasecmp(s->data, (u_char *) "DEBUG", 5) == 0) {
                log_level = NGX_ALOG_DEBUG;
        } else if (ngx_strncasecmp(s->data, (u_char *) "INFO", 4) == 0) {
                log_level = NGX_ALOG_INFO;
        } else if (ngx_strncasecmp(s->data, (u_char *) "WARN", 4) == 0 || ngx_strncasecmp(s->data, (u_char *) "WARNING", 7) == 0) {
                log_level = NGX_ALOG_WARN;
        } else if (ngx_strncasecmp(s->data, (u_char *) "ERR", 3) == 0 || ngx_strncasecmp(s->data, (u_char *) "ERROR", 5) == 0) {
                log_level = NGX_ALOG_ERR;
        } else {
                return NGX_CONF_UNSET; 
        }

        return log_level;
}

static char *ngx_http_alog_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
        ngx_http_alog_main_conf_t *lmcf = conf;  
        ngx_str_t *value;

        if (cf->cmd_type != NGX_HTTP_MAIN_CONF) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"alog_set\" directive can be used only on \"http\" level");
                return NGX_CONF_ERROR;
        }

        if (cf->args->nelts > 4) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid alog_set setting, usage: alog_set [file_path] [log_level] [buffer_size]");
                return NGX_CONF_ERROR;
        }
        
        value = cf->args->elts;

        if (value[1].data == NULL || value[1].len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "alog log file path can not be empty");
                return NGX_CONF_ERROR;
        }

        if (lmcf->log_level != NGX_CONF_UNSET) {
                return "is duplicate";
        }

        alog_log_thread_ctx.log_file = ngx_conf_open_file(cf->cycle, &value[1]);

        if (alog_log_thread_ctx.log_file == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, ngx_open_file_n" \"%s\" failed", value[1].data);
                return NGX_CONF_ERROR;
        }

        lmcf->log_level = NGX_ALOG_INFO; /* defalut log level */

        if (cf->args->nelts >= 3) {
                lmcf->log_level = alog_parse_log_level(&value[2]);

                if (lmcf->log_level == NGX_CONF_UNSET) {
                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid alog level \"%s\"", value[2].data);
                        return NGX_CONF_ERROR;
                }
        }

        lmcf->buf_size = 0;     /* default not use buffer */

        if (cf->args->nelts == 4) {
                ssize_t size = ngx_parse_size(&value[3]);

                if (size == NGX_ERROR) { 
                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid alog buffer size \"%V\"", &value[3]); 
                        return NGX_CONF_ERROR;
                }

                lmcf->buf_size = size;

                if (size != 0) {
                        lmcf->log_buf.start = ngx_pcalloc(cf->pool, size);

                        if (lmcf->log_buf.start == NULL) {
                                return NGX_CONF_ERROR;
                        }

                        lmcf->log_buf.pos = lmcf->log_buf.start;
                }
        }

        return NGX_CONF_OK;
}

static char *ngx_http_alog_write_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
        ngx_http_alog_loc_conf_t *llcf = conf;
        ngx_http_alog_main_conf_t *lmcf;

        ngx_str_t *value;
        ngx_http_alog_t *log;

        int log_level;
        unsigned flush;

        ngx_http_script_compile_t sc;
        ngx_uint_t n;

        lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_alog_module);

        if (cf->cmd_type != NGX_HTTP_LOC_CONF) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"alog\" directive can be used only on \"location\" level");
                return NGX_CONF_ERROR;
        }

        if (cf->args->nelts > 4) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid alog setting, usage: alog [log_level] [log_msg] [flush]");
                return NGX_CONF_ERROR;
        }

        if (lmcf->log_level == NGX_CONF_UNSET || alog_log_thread_ctx.log_file == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"alog_set\" directive is missing. You should set it in \"http\" before using alog");
                return NGX_CONF_ERROR;
        }

        value = cf->args->elts;

        log_level = alog_parse_log_level(&value[1]);

        if (log_level == NGX_CONF_UNSET) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid alog level \"%s\"", value[1].data);
                return NGX_CONF_ERROR;
        }

        flush = 0;

        if (cf->args->nelts == 4) {
                if (ngx_strncasecmp(value[3].data, (u_char *) "FLUSH", 4) == 0) {
                        flush = 1;
                } else {
                        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid alog flush flag value, use \"flush\" only");
                        return NGX_CONF_ERROR;
                }
        }

        if (log_level < lmcf->log_level) {
                return NGX_CONF_OK;
        }

        if (llcf->logs == NULL) {
                llcf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_alog_t));

                if (llcf->logs == NULL) {
                        return NGX_CONF_ERROR;
                }
        }

        log = ngx_array_push(llcf->logs);

        if (log == NULL) {
                return NGX_CONF_ERROR;
        }

        log->level = log_level;
        log->flush = flush;

        log->script = ngx_pcalloc(cf->pool, sizeof(ngx_http_alog_script_t));

        if (log->script == NULL) {
                return NGX_CONF_ERROR;
        }
        
        /* store raw str value of arg */
        log->script->raw_value = value[2];

        n = ngx_http_script_variables_count(&value[2]);

        if (n > 0) {
                ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

                sc.cf = cf;
                sc.source = &(log->script->raw_value);
                sc.lengths = &(log->script->lengths);
                sc.values = &(log->script->values);
                sc.variables = n;
                sc.complete_lengths = 1;
                sc.complete_values = 1;

                if (ngx_http_script_compile(&sc) != NGX_OK) {
                        return NGX_CONF_ERROR;
                }
        }

        return NGX_CONF_OK;
}

static ngx_int_t ngx_http_alog_init(ngx_conf_t *cf)
{
        ngx_http_core_main_conf_t *cmcf;
        ngx_http_handler_pt *h;

        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

        h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);

        if (h == NULL) {
                return NGX_ERROR;
        }

        *h = ngx_http_alog_handler;

        return NGX_OK;
}

static void* disk_write_thread(void* para)
{
        while (!alog_log_thread_ctx.stop) {
                alog_mq_msg_t *mq_msg;
                alog_mq_pop(alog_log_thread_ctx.mq, &mq_msg);

                if (mq_msg != NULL) {
                        /* be careful! pop zero copy, so disk thread free memory */
                        if (mq_msg->msg.len != 0) {
                                write(alog_log_thread_ctx.log_file->fd, mq_msg->msg.data, mq_msg->msg.len);
                                free(mq_msg->msg.data);
                        }

                        free(mq_msg);
                }
        }

        return NULL;
}

static ngx_int_t ngx_http_alog_process_init(ngx_cycle_t *cycle)
{
        alog_log_thread_ctx.mq = alog_mq_create();

        if (alog_log_thread_ctx.mq == NULL) {
                return NGX_ERROR; 
        }

        if (pthread_create(&alog_log_thread_ctx.tid, NULL, disk_write_thread, NULL)) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "alog module process init fail, log thread init fail");
                alog_mq_release(alog_log_thread_ctx.mq);
                return NGX_ERROR; 
        }

        return NGX_OK;
}

static void ngx_http_alog_process_exit(ngx_cycle_t *cycle)
{
        ngx_http_alog_main_conf_t *lmcf;
        size_t write_bytes;

        alog_log_thread_ctx.stop = 1;

        alog_mq_msg_t mq_msg;
        mq_msg.msg.data = NULL;
        mq_msg.msg.len = 0;

        /* wakeup log thread */
        alog_mq_push(alog_log_thread_ctx.mq, &mq_msg);

        /* wait thread stop */
        pthread_join(alog_log_thread_ctx.tid, NULL);
        
        lmcf = (ngx_http_alog_main_conf_t *) ngx_http_cycle_get_module_main_conf(cycle, ngx_http_alog_module);

        if (lmcf == NULL) {
                return;
        }

        if (lmcf->buf_size != 0 && lmcf->log_buf.pos != lmcf->log_buf.start) {
                write_bytes = lmcf->log_buf.pos - lmcf->log_buf.start;
                write(alog_log_thread_ctx.log_file->fd, lmcf->log_buf.start, write_bytes);

                lmcf->log_buf.pos = lmcf->log_buf.start;
        }

        alog_mq_release(alog_log_thread_ctx.mq);

        ngx_memzero(&alog_log_thread_ctx, sizeof(alog_log_thread_ctx_t));
        alog_log_thread_ctx.stop = 1;
}

/* 
 * vim: ts=8 sw=8 expandtab fenc=utf-8
 */

