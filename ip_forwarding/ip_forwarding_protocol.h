#ifndef __IP_FORWARDING_PROTOCOL
#define __IP_FORWARDING_PROTOCOL

#include <stdint.h>
#include <stddef.h>

/*
 * Simple protocol for forwarding original ip
 * address to clients through proxy.
 */

typedef struct
{
  uint16_t  app_code;         // allways 0x11a6
  uint8_t   ip_version;       // 4 or 6
  size_t    data_offset;      // offset (in bytes) of payload (same as header length).
  size_t    source_ip_length; // length (in bytes) of source ip.
  uint8_t*  source_ip;        // source ip (big-endian).
                              // Ex. "127.0.0.1" -> source_ip[0] = 127; source_ip[1] = 0;
                              // source_ip[2] = 0; source_ip[3] = 1;
} IPFPHeader_t;

// ==== ip forwarding protocol ====
/*
 * Create header.
 * source_ip param must be big-endian.
 * Ex. "127.0.0.1" -> source_ip[0] = 127; source_ip[1] = 0; source_ip[2] = 0; source_ip[3] = 1;
 * @return 0 on success, value < 0 on fail.
 * @note if this method succeed, IPFPHeaderRelease() must be called to free resources later.
 */
int IPFPHeaderCreate(IPFPHeader_t* header, uint8_t ip_version, const uint8_t* source_ip);
/*
 * Deallocate resources used by header.
 * @return 0 on success, value < 0 on fail.
 */
int IPFPHeaderRelease(IPFPHeader_t* header);
/*
 * Length this header will take when written to byte buffer.
 * @return length of header or value < 0 on fail.
 */
int IPFPHeaderLength(const IPFPHeader_t* header);
/*
 * Write IPFP header to byte buffer.
 * @return bytes written or value < 0 on fail.
 */
int IPFPHeaderWrite(const IPFPHeader_t* header, uint8_t* buffer);
/*
 * Write IPFP header plus it's payload to byte buffer.
 * @return bytes written or value < 0 on fail.
 */
int IPFPPacketWrite(const IPFPHeader_t* header,
                      const uint8_t* payload, size_t payload_length, uint8_t* buffer);
/*
 * Read header from byte buffer.
 * @return bytes utilised (header length) or value < 0 on fail.
 */
int IPFPHeaderRead(IPFPHeader_t* header, const uint8_t* buffer, size_t buffer_length);
/*
 * @return minimum length of byte buffer, with which
 * IPFPTryReadHeaderLength can work.
 */
size_t IPFPMinHeaderLength();
/*
 * Number of bytes that contain IPFP header.
 * @return header length or value < 0 on fail.
 */
int IPFPTryReadHeaderLength(const uint8_t* buffer, size_t buffer_length);
/*
 * String representation of error.
 */
const char* IPFPGetErrorMessage(int error_code);

#endif // __IP_FORWARDING_PROTOCOL
