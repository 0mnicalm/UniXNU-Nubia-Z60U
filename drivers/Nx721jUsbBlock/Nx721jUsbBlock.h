// SPDX-License-Identifier: BSD-2-Clause-Patent
#pragma once

#include <IOKit/IOService.h>

// A synchronous transport read, serialized by the block device. Return
// success only after all requested 4 KiB blocks have been validated and copied.
// Return kIOReturnNoDevice if the transport is permanently lost.
using Nx721jUsbReadBlocks = IOReturn(void *context, UInt64 firstBlock,
                                   UInt32 blockCount, void *destination);

// Call after the transport knows its capacity. The caller owns the returned
// reference. The callback must not re-enter this storage service.
extern "C" IOService *nx721j_usb_publish_block(IOService *provider, UInt64 blockCount,
                                              Nx721jUsbReadBlocks *reader, void *context);

// Call from the endpoint owner before freeing its context or stopping DMA.
// Waits for the current read, rejects new reads, and marks media absent.
// The caller still owns the reference and must terminate and release it.
extern "C" void nx721j_usb_quiesce_block(IOService *device);

struct Nx721jUsbBlockTransport;

// The endpoint owner calls this from a thread after USB configuration and
// quiesces the returned service before destroying the transport.
extern "C" IOService *nx721j_usb_publish_transport(IOService *provider,
                                                  Nx721jUsbBlockTransport *transport);

// Run from the endpoint worker after USB configuration with a live transport.
// Returns after removing the service's callback references to the transport.
extern "C" unsigned nx721j_usb_run_registration_probe(Nx721jUsbBlockTransport *transport);
