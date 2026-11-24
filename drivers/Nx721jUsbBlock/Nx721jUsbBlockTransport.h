// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once

#include <stdint.h>

// Each callback performs one complete bulk transfer, with a bounded timeout.
// The caller serializes operations and keeps this context alive until detach.
struct Nx721jUsbBlockTransport {
  using Send = bool(void *, const void *, uint32_t);
  using Receive = bool(void *, void *, uint32_t);

  Send *send;
  Receive *receive;
  void *context;
  uint32_t capacity = 0;
  uint32_t sequence = 0;
  bool online = false;

  bool open();
  bool close();
  bool read(uint64_t firstBlock, uint32_t blockCount, void *destination);

private:
  bool exchange(uint32_t operation, uint32_t index, uint32_t count, void *destination);
};

inline bool Nx721jUsbBlockTransport::exchange(uint32_t operation, uint32_t index,
                                             uint32_t count, void *destination)
{
  static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "USB records are little-endian");
  constexpr uint32_t requestMagic = 0x3351584e; // NXQ3.
  constexpr uint32_t responseMagic = 0x3352584e; // NXR3.
  constexpr uint32_t bytesPerBlock = 4096;
  const uint32_t bytes = count * bytesPerBlock;
  const uint32_t token = ++sequence;
  const uint32_t request[16] = {requestMagic, token, operation, index, count};
  uint32_t response[16] = {};
  if (!send(context, request, sizeof request) || !receive(context, response, sizeof response) ||
      response[0] != responseMagic || response[1] != token || response[2] != 0 ||
      response[3] != index || response[4] != count || response[5] != bytes ||
      response[7] == 0 || (operation != 0 && response[7] != capacity)) {
    online = false;
    return false;
  }

  if (bytes == 0) {
    if (operation == 0) {
      capacity = response[7];
    }
    return true;
  }

  auto *payload = static_cast<unsigned char *>(destination);
  uint32_t crc = ~0U;
  for (uint32_t offset = 0; offset < bytes; offset += bytesPerBlock) {
    if (!receive(context, payload + offset, bytesPerBlock)) {
      online = false;
      return false;
    }
    for (uint32_t j = 0; j < bytesPerBlock; ++j) {
      crc ^= payload[offset + j];
      for (uint32_t bit = 0; bit < 8; ++bit) {
        crc = (crc >> 1) ^ ((0U - (crc & 1U)) & 0xedb88320U);
      }
    }
  }
  online = (~crc == response[6]);
  return online;
}

inline bool Nx721jUsbBlockTransport::open()
{
  if (online || !send || !receive) {
    return false;
  }
  online = exchange(0, 0, 0, nullptr);
  return online;
}

inline bool Nx721jUsbBlockTransport::close()
{
  const bool acknowledged = online && exchange(2, 0, 0, nullptr);
  online = false;
  return acknowledged;
}

inline bool Nx721jUsbBlockTransport::read(uint64_t index, uint32_t count, void *destination)
{
  if (!online || !destination || index >= capacity || count == 0 || count > 16 ||
      count > capacity - index) {
    return false;
  }
  return exchange(1, static_cast<uint32_t>(index), count, destination);
}
