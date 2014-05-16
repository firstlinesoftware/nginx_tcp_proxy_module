#include <ngx_tcp_forward_source_ip.h>
#include <ip_forwarding/ip_forwarding_protocol.h>

static int buffer_append_begin(u_char* data, size_t data_size, ngx_buf_t *buffer)
{
    size_t buff_free;

    buff_free = buffer->pos - buffer->start;

    if(buff_free < data_size)
        return -7;

    buffer->pos -= data_size;

    memcpy(buffer->pos, data, data_size);

    return 0;
}

static int apply_forward_header(u_char* packet_start, ngx_connection_t *c, IPFPHeader_t *header,
                                 ngx_tcp_forward_source_ip_state_t *state, ngx_buf_t *data)
{
    size_t in_buff_free, packet_available;
    int result, temp, temp2;

    in_buff_free = data->end - data->last;
    packet_available = data->last - packet_start;

    result = (int)IPFPHeaderLength(header);

    if(result < 0) {

        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ip forwarding, %s", IPFPGetErrorMessage(result));
        return -4;
    }

    if(result > (int)in_buff_free) {

        temp = result;
        temp2 = result - in_buff_free;

        ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                      "ip forwarding, input buffer not enough free space(%d), storing part(%d) for future",
                      in_buff_free, temp2);

        result = buffer_append_begin(data->last - temp2, temp2, state->buffer);

        if(result < 0) {

            ngx_log_error(NGX_LOG_ERR, c->log, 0, "ip forwarding, buffer overflow (can't copy to state buffer)");
            return result;
        }

        memmove(packet_start + temp, packet_start, packet_available - temp2);
        data->last += in_buff_free;

    } else {

        ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                      "ip forwarding, input buffer enough free space(%d) to store header(%d)",
                      in_buff_free, result);

        memmove(packet_start + result, packet_start, packet_available);
        data->last += result;
    }

    result = IPFPHeaderWrite(header, packet_start);

    if(result < 0) {

        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ip forwarding, %s", IPFPGetErrorMessage(result));
        return -5;
    }

    return 0;
}

int ngx_tcp_proxy_forwarding_restore_buffer(ngx_connection_t *c,
                                            ngx_tcp_forward_source_ip_state_t *state, ngx_buf_t *data)
{
    char              *action;
    size_t             in_buff_free, in_buff_data, state_buff_data;

    action = c->log->action;
    c->log->action = "restoring buffer";
    in_buff_free = data->end - data->last + data->pos - data->start;
    in_buff_data = data->last - data->pos;
    state_buff_data = state->buffer->last - state->buffer->pos;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx tcp proxy restoring buffer");

    // copy data stored from previos call into input buffer
    if(state_buff_data) {

        if(state_buff_data > in_buff_free) {

            ngx_log_error(NGX_LOG_ERR, c->log, 0, "ip forwarding, buffer overflow (can't copy from state buffer)");
            c->log->action = action;
            return -6;
        }

        if(data->end - data->last < (int)state_buff_data) {

            memmove(data->start, data->pos, in_buff_data);
            data->pos = data->start;
            data->last = data->pos + in_buff_data;
        }

        memcpy(data->last, state->buffer->pos, state_buff_data);
        data->last += state_buff_data;
        state->buffer->pos = state->buffer->end;
        state->buffer->last = state->buffer->end;
        state_buff_data = state->buffer->last - state->buffer->pos;
    }

    c->log->action = action;

    return state_buff_data;
}

int ngx_tcp_proxy_handle_ip_forwarding(ngx_connection_t *c,
                                          ngx_tcp_forward_source_ip_state_t *state, ngx_buf_t *data)
{
    char              *action;
    struct sockaddr   *src_addr;
    unsigned char      addr_buff[16];
    IPFPHeader_t        forwarding_header;
    size_t             in_buff_data, state_buff_data;
    int                result;

    action = c->log->action;
    c->log->action = "forwarding ip";
    src_addr = c->sockaddr;
    in_buff_data = data->last - data->pos;
    state_buff_data = state->buffer->last - state->buffer->pos;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx tcp proxy handle ip forwarding");

    if(state_buff_data) {

        result = ngx_tcp_proxy_forwarding_restore_buffer(c, state, data);

        if(result < 0)
        {
            c->log->action = action;
            return result;
        }

        if(result > 0) {

          ngx_log_error(NGX_LOG_ERR, c->log, 0, "ip forwarding, can't restore buffer");
          c->log->action = action;
          return -6;
        }

        state_buff_data = 0;
        in_buff_data = data->last - data->pos;
    }

    if(in_buff_data == 0) {

        c->log->action = action;
        return 0;
    }

    if(src_addr == 0) {

        ngx_log_error(NGX_LOG_ERR, c->log, 0, "ip forwarding, can't get sockaddr");
        c->log->action = action;
        return -1;
    }

    switch(src_addr->sa_family) {

    case AF_INET :

        memcpy(addr_buff, &(((struct sockaddr_in *)src_addr)->sin_addr.s_addr), 4);
        result = IPFPHeaderCreate(&forwarding_header, 4, addr_buff);

        if(result < 0) {

            ngx_log_error(NGX_LOG_ERR, c->log, 0, "ip forwarding, %s", IPFPGetErrorMessage(result));
            c->log->action = action;
            return -2;
        }

        ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "forwarding address %d.%d.%d.%d",
                      (int)addr_buff[0], (int)addr_buff[1], (int)addr_buff[2], (int)addr_buff[3]);
        break;

    case AF_INET6 :

        memcpy(addr_buff, &(((struct sockaddr_in6 *)src_addr)->sin6_addr.s6_addr), 16);
        result = IPFPHeaderCreate(&forwarding_header, 6, addr_buff);

        if(result < 0) {

            ngx_log_error(NGX_LOG_ERR, c->log, 0, "ip forwarding, %s", IPFPGetErrorMessage(result));
            c->log->action = action;
            return -3;
        }

        ngx_log_error(NGX_LOG_DEBUG, c->log, 0,
                      "forwarding address %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                      (int)addr_buff[0], (int)addr_buff[1], (int)addr_buff[2], (int)addr_buff[3],
                      (int)addr_buff[4], (int)addr_buff[5], (int)addr_buff[6], (int)addr_buff[7],
                      (int)addr_buff[8], (int)addr_buff[9], (int)addr_buff[10], (int)addr_buff[11],
                      (int)addr_buff[12], (int)addr_buff[13], (int)addr_buff[14], (int)addr_buff[15]);
        break;
    }

    result = apply_forward_header(data->pos, c, &forwarding_header, state, data);

    if(result < 0) {

        IPFPHeaderRelease(&forwarding_header);
        c->log->action = action;
        return result;
    }

    IPFPHeaderRelease(&forwarding_header);

    state_buff_data = state->buffer->last - state->buffer->pos;

    c->log->action = action;

    return state_buff_data;
}
