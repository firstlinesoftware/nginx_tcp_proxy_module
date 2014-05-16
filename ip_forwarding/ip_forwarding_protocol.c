#include "ip_forwarding_protocol.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static const uint16_t IPFP_APP_CODE = 0x11A6;
static const size_t DATA_OFFSET_BYTE_MULTIPLIER = 4;
static const size_t DATA_OFFSET_IPV4 = 2;
static const size_t DATA_OFFSET_IPV6 = 5;
static const size_t ADDR_LENGTH_IPV4 = 4;
static const size_t ADDR_LENGTH_IPV6 = 16;

static const char * unknown_error = "unknown error";
static const char * const error_msg[] = {
                    "Invalid APP_CODE",
                    "No such IP version known",
                    "Malformed header",
                    "Out of buffer's range"
                    };

static int checkHeader(const IPFPHeader_t* header)
{
  size_t data_offset;
  size_t source_ip_length;

  if(header->app_code != IPFP_APP_CODE)
    return -1;
    
  if(header->ip_version != 4 && header->ip_version != 6)
    return -2;
    
  data_offset = (header->ip_version == 4 ? DATA_OFFSET_IPV4 : DATA_OFFSET_IPV6)
                        * DATA_OFFSET_BYTE_MULTIPLIER;
                        
  source_ip_length = header->ip_version == 4 ? ADDR_LENGTH_IPV4 : ADDR_LENGTH_IPV6;
    
  if(header->data_offset != data_offset 
      || header->source_ip_length != source_ip_length
      || header->source_ip == 0)
    return -3;
    
  return 0;
}

int IPFPHeaderCreate(IPFPHeader_t* header, uint8_t ip_version, const uint8_t* source_ip)
{
  if(ip_version != 4 && ip_version != 6)
    return -2;
    
  if(source_ip == 0)
    return -3;
  
  header->app_code = IPFP_APP_CODE;
  header->ip_version = ip_version;
  header->data_offset = (ip_version == 4 ? DATA_OFFSET_IPV4 : DATA_OFFSET_IPV6) 
                        * DATA_OFFSET_BYTE_MULTIPLIER;
  header->source_ip_length = header->ip_version == 4 ? ADDR_LENGTH_IPV4 : ADDR_LENGTH_IPV6;
  header->source_ip = (uint8_t*)malloc(header->source_ip_length);
  memcpy(header->source_ip, source_ip, header->source_ip_length);
  
  return 0;
}

int IPFPHeaderRelease(IPFPHeader_t* header)
{
  int result;

  result = checkHeader(header);
  
  if(result < 0)
    return result;
  
  free(header->source_ip);
  header->source_ip = 0;
  
  return 0;
}

int IPFPHeaderLength(const IPFPHeader_t* header)
{
  int result;

  result = checkHeader(header);
  
  if(result < 0)
    return result;
    
  return header->data_offset;
}


int IPFPHeaderWrite(const IPFPHeader_t* header, uint8_t* buffer)
{
  int result;
  uint16_t net_app_code;
  size_t net_data_offs;
  uint8_t ip_ver_data_offs;

  result = checkHeader(header);
  
  if(result < 0)
    return result;
  
  net_app_code = htons(header->app_code);
  net_data_offs = (header->ip_version == 4 ? DATA_OFFSET_IPV4 : DATA_OFFSET_IPV6);
  ip_ver_data_offs = (header->ip_version << 4) | (uint8_t)(net_data_offs & 0x0F);
  
  memcpy(buffer, &net_app_code, 2);
  buffer[2] = ip_ver_data_offs;
  buffer[3] = 0;
  memcpy(buffer + 4, header->source_ip, header->source_ip_length);
  
  if(header->ip_version == 6)
  {
    buffer[11] = buffer[10] = 0;
    return DATA_OFFSET_IPV6 * DATA_OFFSET_BYTE_MULTIPLIER;
  } 
  else
  {
    return DATA_OFFSET_IPV4 * DATA_OFFSET_BYTE_MULTIPLIER;
  }
}

int IPFPPacketWrite(const IPFPHeader_t* header,
                      const uint8_t* payload, size_t payload_length, uint8_t* buffer)
{
  int bytes_written;

  bytes_written = IPFPHeaderWrite(header, buffer);
  
  if(bytes_written < 0)
    return bytes_written;
    
  memcpy(buffer + bytes_written, payload, payload_length);
  
  return bytes_written + payload_length;
}

int IPFPHeaderRead(IPFPHeader_t* header, const uint8_t* buffer, size_t buffer_length)
{
  int header_length;
  uint16_t net_app_code;
  uint8_t ip_ver_data_offs;
  int result;

  header_length = IPFPTryReadHeaderLength(buffer, buffer_length);
  
  if(header_length < 0)
    return header_length;
  
  if(header_length > (int)buffer_length)
    return -4;
  
  memcpy(&net_app_code, buffer, 2);
  ip_ver_data_offs = buffer[2];
  
  header->app_code = ntohs(net_app_code);
  header->ip_version = (ip_ver_data_offs >> 4) & 0x0F;
  header->data_offset = (ip_ver_data_offs & 0x0F) * DATA_OFFSET_BYTE_MULTIPLIER;
  
  if(header->app_code != IPFP_APP_CODE)
    return -1;
    
  if(header->ip_version != 4 && header->ip_version != 6)
    return -2;
  
  header->source_ip_length = header->ip_version == 4 ? ADDR_LENGTH_IPV4 : ADDR_LENGTH_IPV6;
  header->source_ip = (uint8_t*)malloc(header->source_ip_length);
  memcpy(header->source_ip, buffer + 4, header->source_ip_length);
  
  result = checkHeader(header);
  
  if(result < 0)
    return result;
    
  return header_length;
}

size_t IPFPMinHeaderLength()
{
  return 8;
}

int IPFPTryReadHeaderLength(const uint8_t* buffer, size_t buffer_length)
{
  uint16_t net_app_code;
  uint8_t ip_ver_data_offs;
  uint8_t data_offset;

  if(buffer_length < 3)
    return -4;
  
  memcpy(&net_app_code, buffer, 2);
  
  if(ntohs(net_app_code) != IPFP_APP_CODE)
    return -1;
  
  ip_ver_data_offs = buffer[2];
  data_offset = (ip_ver_data_offs & 0x0F) * DATA_OFFSET_BYTE_MULTIPLIER;
  
  if(data_offset < IPFPMinHeaderLength())
    return -3;
  
  return data_offset;
}

const char* IPFPGetErrorMessage(int error_code)
{
  int offset;

  offset = error_code * (-1) - 1;
  
  if(offset < 0 || offset >= (int)(sizeof(error_msg) / sizeof(*error_msg)))
    return unknown_error;
    
  return error_msg[offset];
}


