#ifndef _NGX_TCP_FORWARD_SOURCE_IP_H_INCLUDED_
#define _NGX_TCP_FORWARD_SOURCE_IP_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>
#include <ngx_buf.h>

struct ngx_tcp_forward_source_ip_state_s{

    ngx_buf_t  *buffer;
};

/*
 * Prepend packet (in data) with IPFP (ip forwarding protocol) header.
 * @note if buffer doesn't contain enough space for header, overflowing bytes
 * will be saved in state buffer.
 * @return number of bytes, saved in state buffer,
 * or value < 0 on error
 */
int ngx_tcp_proxy_handle_ip_forwarding(ngx_connection_t  *c,
                                       ngx_tcp_forward_source_ip_state_t *state, ngx_buf_t *data);
/*
 * Write back all bytes, stored in ngx_tcp_proxy_handle_ip_forwarding().
 * @return 0 on success, any other value on fail
 */
int ngx_tcp_proxy_forwarding_restore_buffer(ngx_connection_t *c,
                                            ngx_tcp_forward_source_ip_state_t *state, ngx_buf_t *data);

#endif // _NGX_TCP_FORWARD_SOURCE_IP_H_INCLUDED_
