// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once

#include <IOKit/IOService.h>

// A synchronous transport read, serialized by the block device. Return
// success only after all requested 4 KiB blocks have been validated and copied.
using Nx721jUsbReadBlocks = IOReturn(void *context, UInt64 firstBlock,
                                   UInt32 blockCount, void *destination);

// Call after the transport knows its capacity. The caller owns the returned
// reference and must synchronously terminate the service before retiring the
// callback context. The callback must not re-enter this storage service.
extern "C" IOService *nx721j_usb_publish_block(IOService *provider, UInt64 blockCount,
                                              Nx721jUsbReadBlocks *reader, void *context);
struct Nx721jUsbBlockTransport;

// The endpoint owner calls this from a thread after USB configuration, then
// synchronously terminates the returned service before destroying the transport.
extern "C" IOService *nx721j_usb_publish_transport(IOService *provider,
                                                  Nx721jUsbBlockTransport *transport);
