## alog-nginx-module

一个Nginx日志模块，目的是便于使用Nginx作为日志收集服务器

## 模块特点：

* 支持多种日志级别和日志路径设置
* 支持写日志缓冲，缓冲区大小可自定义
* 采用单独的日志线程写磁盘，Nginx Worker主线程和日志线程通过阻塞队列通讯

## 模块用途

模块包含如下两条指令：

* alog_set

格式：alog_set [file_path] [log_level] [buffer_size]
说明：本指令只能出现在http中。[log_level]和[buffer_size]可选，默认日志结拜为info，默认缓冲大小为0.
例子：alog_set /usr/local/nginx/logs/test.log info 32k;

* alog

格式：alog [log_level] [log_msg] [flush]
说明：[flush]可选，如果需要强制刷新，输入“flush”。其中[log_msg]既可以为原始字符串，也可以为Nginx变量。
例子：alog info “Hello World”；

## 例子：

```C
...

http {
  alog_set /export/servers/openresty/nginx/logs/clickstream.log info 1M;

  ...

  server {
    listen 80;

    ...

    location /log {
      access_log off;
      set $u_log "Hello World";
      alog info $u_log;
      ...
    }
  }
}
```

## 说明

最初并无再写一个日志模块的意愿，毕竟Nginx自带的日志模块已经很好用了。但是在利用Nginx记点击流日志时，发现一个问题无法解决。点击流日志分隔符，我效仿网上一篇文章用了Ascii不可见字符^A。测试中发现如果直接将^A写入log_format，则日志打印没有问题；但如果在lua中对输入字符串进行处理（比如原先分隔符是|，替换为^A），最终经过nginx打印，会发现打印出的不是^A，而是\x001。经过调研发现，似乎是Nginx的日志模块对Ascii字符进行了转义，颇让人为难。

在Openresty中文邮件列表提问后，得到了包括agentzh在内的众多朋友帮助，发现这个问题可以使用专门的lua日志模块解决。但经过测试发现确实解决了字符转义的问题，非常高兴。但是经过简单测试，发现使用lua模块写日志，比使用Nginx的日志模块性能有所下降。考虑到日志收集响应速度很重要，因此决定自己开发一个模块。

模块的设计思路很明确，采用专门的日志线程写日志，Nginx Worker进程的主线程将日志写入内存缓冲区后返回。当缓冲区满后，主线程会将缓冲区中日志通过阻塞队列（Blocking Queue）交给日志线程，然后由日志线程写入磁盘。开发完成后，经过测试，性能功能性都满足要求。意外的是我发现自己写的日志模块性能，相比Nginx原生的日志模块并无明显的性能优势。并不是说本模块性能不好，而是发现Nginx原生的日志模块性能其实并不差。原先担心的性能问题，有杞人忧天之嫌，纯粹臆想。因为现在的磁盘顺序写速度已今非昔比，而且像Linux这样的系统会使用大量的内存作为写磁盘缓冲，因此像Nginx这样顺序追加写磁盘，速度并没有想象中糟糕。感觉自己的知识结构似乎还停留在那遥远的年代。

由此看来，这个模块主要的意义，除了解决转义字符的问题，更主要的是供广大Nginx开发者参考。如果能对社区中朋友有所帮助，善莫大焉。
