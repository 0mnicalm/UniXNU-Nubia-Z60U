// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "Nx721jUsbBlock.h"
#include "Nx721jUsbBlockTransport.h"

#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/storage/IOBlockStorageDevice.h>

namespace {
constexpr UInt64 blockBytes = 4096;
constexpr UInt32 maxBlocksPerRead = 16;
constexpr IOByteCount stagingBytes = blockBytes * maxBlocksPerRead;
}

class Nx721jUsbBlock : public IOBlockStorageDevice {
  OSDeclareDefaultStructors(Nx721jUsbBlock)

  IOLock *gate = nullptr;
  void *staging = nullptr;
  Nx721jUsbReadBlocks *readBlocks = nullptr;
  void *context = nullptr;
  UInt64 capacity = 0;
  bool online = false;

public:
  bool configure(UInt64 blocks, Nx721jUsbReadBlocks *reader, void *readerContext)
  {
    if (!reader || !blocks || blocks > 0xffffffffULL) {
      return false;
    }
    gate = IOLockAlloc();
    staging = IOMalloc(stagingBytes);
    if (!gate || !staging) {
      return false;
    }
    capacity = blocks;
    readBlocks = reader;
    context = readerContext;
    return true;
  }

  bool start(IOService *provider) override
  {
    if (!IOBlockStorageDevice::start(provider)) {
      return false;
    }
    IOLockLock(gate);
    online = true;
    IOLockUnlock(gate);
    registerService();
    return true;
  }

  void stop(IOService *provider) override
  {
    // Wait for the serialized transport call before retiring its context.
    IOLockLock(gate);
    online = false;
    IOLockUnlock(gate);
    IOBlockStorageDevice::stop(provider);
  }

  void free() override
  {
    if (staging) {
      IOFree(staging, stagingBytes);
    }
    if (gate) {
      IOLockFree(gate);
    }
    IOBlockStorageDevice::free();
  }

  IOReturn doEjectMedia() override { return kIOReturnUnsupported; }
  IOReturn doFormatMedia(UInt64) override { return kIOReturnNotWritable; }
  UInt32 doGetFormatCapacities(UInt64 *, UInt32) const override { return 0; }
  char *getVendorString() override { return const_cast<char *>("UniXNU"); }
  char *getProductString() override { return const_cast<char *>("NX721J USB SystemOS"); }
  char *getRevisionString() override { return const_cast<char *>("1.0"); }
  char *getAdditionalDeviceInfoString() override { return const_cast<char *>("Read-only USB image"); }
  IOReturn reportBlockSize(UInt64 *value) override { *value = blockBytes; return kIOReturnSuccess; }
  IOReturn reportMaxValidBlock(UInt64 *value) override { *value = capacity - 1; return kIOReturnSuccess; }
  IOReturn reportEjectability(bool *value) override { *value = false; return kIOReturnSuccess; }
  IOReturn reportRemovability(bool *value) override { *value = true; return kIOReturnSuccess; }
  IOReturn reportWriteProtection(bool *value) override { *value = true; return kIOReturnSuccess; }
  IOReturn getWriteCacheState(bool *value) override { *value = false; return kIOReturnSuccess; }
  IOReturn setWriteCacheState(bool) override { return kIOReturnUnsupported; }

  IOReturn reportMediaState(bool *present, bool *changed) override
  {
    IOLockLock(gate);
    *present = online;
    *changed = false;
    IOLockUnlock(gate);
    return kIOReturnSuccess;
  }

  IOReturn doSynchronizeCache() override
  {
    IOLockLock(gate);
    const bool active = online;
    IOLockUnlock(gate);
    return active ? kIOReturnSuccess : kIOReturnNotReady;
  }

  IOReturn doSynchronize(UInt64, UInt64, IOOptionBits) override
  {
    return doSynchronizeCache();
  }

  IOReturn doAsyncReadWrite(IOMemoryDescriptor *buffer, UInt64 block, UInt64 count,
                           IOStorageAttributes *, IOStorageCompletion *completion) override
  {
    if (!buffer || !completion || !completion->action || !count ||
        block >= capacity || count > capacity - block ||
        buffer->getLength() < count * blockBytes) {
      return kIOReturnBadArgument;
    }
    if (buffer->getDirection() != kIODirectionIn) {
      return kIOReturnNotWritable;
    }

    IOByteCount done = 0;
    IOLockLock(gate);
    IOReturn result = online ? kIOReturnSuccess : kIOReturnNotReady;
    while (result == kIOReturnSuccess && done < count * blockBytes) {
      const UInt64 completedBlocks = done / blockBytes;
      const UInt64 remaining = count - completedBlocks;
      const UInt32 burst = static_cast<UInt32>(remaining < maxBlocksPerRead ? remaining : maxBlocksPerRead);
      const IOByteCount length = burst * blockBytes;
      result = readBlocks(context, block + completedBlocks, burst, staging);
      if (result == kIOReturnSuccess) {
        const IOByteCount copied = buffer->writeBytes(done, staging, length);
        done += copied;
        if (copied != length) {
          result = kIOReturnIOError;
        }
      }
    }
    IOLockUnlock(gate);
    completion->action(completion->target, completion->parameter, result, done);
    return kIOReturnSuccess;
  }
};

OSDefineMetaClassAndStructors(Nx721jUsbBlock, IOBlockStorageDevice)

IOService *nx721j_usb_publish_block(IOService *provider, UInt64 blocks,
                                   Nx721jUsbReadBlocks *reader, void *context)
{
  if (!provider) {
    return nullptr;
  }
  auto *device = new Nx721jUsbBlock;
  if (!device) {
    return nullptr;
  }
  if (!device->init() || !device->configure(blocks, reader, context) || !device->attach(provider)) {
    device->release();
    return nullptr;
  }
  if (!device->start(provider)) {
    device->detach(provider);
    device->release();
    return nullptr;
  }
  return device;
}


static IOReturn readUsbBlocks(void *context, UInt64 block, UInt32 count, void *destination)
{
  auto *transport = static_cast<Nx721jUsbBlockTransport *>(context);
  if (!transport->online) {
    return kIOReturnNotReady;
  }
  return transport->read(block, count, destination) ? kIOReturnSuccess : kIOReturnIOError;
}

IOService *nx721j_usb_publish_transport(IOService *provider, Nx721jUsbBlockTransport *transport)
{
  if (!provider || !transport || !transport->open()) {
    return nullptr;
  }
  auto *device = nx721j_usb_publish_block(provider, transport->capacity, readUsbBlocks, transport);
  if (!device) {
    transport->online = false;
  }
  return device;
}
