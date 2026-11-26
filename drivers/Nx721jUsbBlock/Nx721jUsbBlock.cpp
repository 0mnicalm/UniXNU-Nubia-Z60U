// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "Nx721jUsbBlock.h"
#include "Nx721jUsbBlockTransport.h"

#include <IOKit/IOCatalogue.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSOrderedSet.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSymbol.h>
#include <sys/vnode.h>

extern "C" uint32_t nx721j_apfs_match_trace();
extern "C" int nx721j_usb_apfs_readonly_check(const char *devicePath, int *readError, int *unmountError);

namespace {
constexpr UInt64 blockBytes = 4096;
constexpr UInt32 maxBlocksPerRead = 16;
constexpr IOByteCount stagingBytes = blockBytes * maxBlocksPerRead;
constexpr unsigned probeSeconds = 45;
constexpr unsigned probeIntervalSeconds = 5;
constexpr char apfsContentHint[] = "7C3457EF-0000-11AA-AA11-00306543ECAC";
constexpr UInt32 mountStatusTag = 0x4e580000;
constexpr UInt32 mountAttempt = 34;
enum ProbePhase : UInt32 {
  kProbePublished = 1,
  kProbeReadCompleted,
  kProbeDetached,
  kProbeDetachPending,
  kProbeGptScheme,
  kProbeApfsPartition,
  kProbeApfsContainer,
  kProbeApfsVolume,
  kProbeApfsBsdName,
  kProbePartitionBsdName,
  kProbeApfsPersonality,
  kProbeApfsClassRegistered,
  kProbeHighBlockRequest = 28,
  kProbeInvalidBlockRequest,
  kProbeNonReadRequest,
  kProbeBlockIoFailed,
  kProbeApfsDevfsBlock,
  kProbeApfsMountPoint,
};
constexpr UInt64 mountPrerequisites = (1ULL << kProbeApfsDevfsBlock) | (1ULL << kProbeApfsMountPoint);
enum MountStage : UInt32 {
  kMountVolume = 1,
  kMountReadFile,
  kMountUnmount,
};

bool hasApfsPartitionPersonality(IOService *partition)
{
  if (!gIOCatalogue) {
    return false;
  }
  SInt32 generation = 0;
  auto *drivers = gIOCatalogue->findDrivers(partition, &generation);
  if (!drivers) {
    return false;
  }
  bool found = false;
  for (unsigned i = 0; !found && i < drivers->getCount(); ++i) {
    auto *personality = OSDynamicCast(OSDictionary, drivers->getObject(i));
    if (!personality) {
      continue;
    }
    auto *name = OSDynamicCast(OSString, personality->getObject("IOClass"));
    auto *properties = OSDynamicCast(OSArray, personality->getObject("IOPropertyMatch"));
    if (!name || !name->isEqualTo("AppleAPFSContainerScheme") || !properties) {
      continue;
    }
    for (unsigned j = 0; j < properties->getCount(); ++j) {
      auto *match = OSDynamicCast(OSDictionary, properties->getObject(j));
      auto *hint = match ? OSDynamicCast(OSString, match->getObject("Content Hint")) : nullptr;
      if (hint && hint->isEqualTo(apfsContentHint)) {
        found = true;
        break;
      }
    }
  }
  drivers->release();
  return found;
}

UInt64 storageTopology(IOService *device, char (&devicePath)[64])
{
  UInt64 seen = 0;
  devicePath[0] = '\0';
  auto entries = IORegistryIterator::iterateOver(device, gIOServicePlane, kIORegistryIterateRecursively);
  if (!entries) {
    return seen;
  }
  while (auto *entry = entries->getNextObject()) {
    if (entry->metaCast("IOGUIDPartitionScheme")) {
      seen |= 1U << kProbeGptScheme;
    }
    if (entry->metaCast("IOMedia")) {
      if (auto *hint = entry->copyProperty("Content Hint")) {
        auto *type = OSDynamicCast(OSString, hint);
        if (type && type->isEqualTo(apfsContentHint)) {
          seen |= 1U << kProbeApfsPartition;
          if (auto *name = entry->copyProperty("BSD Name")) {
            seen |= 1U << kProbePartitionBsdName;
            name->release();
          }
          if (auto *partition = OSDynamicCast(IOService, entry)) {
            if (hasApfsPartitionPersonality(partition)) {
              seen |= 1U << kProbeApfsPersonality;
            }
          }
          if (auto *name = OSSymbol::withCString("AppleAPFSContainerScheme")) {
            if (OSMetaClass::getMetaClassWithName(name)) {
              seen |= 1U << kProbeApfsClassRegistered;
            }
            name->release();
          }
        }
        hint->release();
      }
    }
    if (entry->metaCast("AppleAPFSContainerScheme") || entry->metaCast("AppleAPFSContainer")) {
      seen |= 1U << kProbeApfsContainer;
    }
    if (entry->metaCast("AppleAPFSVolume")) {
      seen |= 1U << kProbeApfsVolume;
      if (auto *name = entry->copyProperty("BSD Name")) {
        seen |= 1U << kProbeApfsBsdName;
        auto *bsd = OSDynamicCast(OSString, name);
        if (!devicePath[0] && bsd && bsd->getLength() &&
            bsd->getLength() <= sizeof(devicePath) - sizeof("/dev/")) {
          snprintf(devicePath, sizeof(devicePath), "/dev/%s", bsd->getCStringNoCopy());
        }
        name->release();
      }
    }
  }
  const bool valid = entries->isValid();
  entries->release();
  if (!valid) {
    return nx721j_apfs_match_trace();
  }

  // Do not hold the USB I/O lock across VFS operations.
  if (devicePath[0]) {
    auto ctx = vfs_context_current();
    vnode_t vnode = nullptr;
    if (vnode_lookup(devicePath, 0, &vnode, ctx) == 0) {
      if (vnode_vtype(vnode) == VBLK) {
        seen |= 1ULL << kProbeApfsDevfsBlock;
      }
      vnode_put(vnode);
    }
    constexpr int flags = VNODE_LOOKUP_NOFOLLOW | VNODE_LOOKUP_NOCROSSMOUNT;
    if (vnode_lookup("/mnt", flags, &vnode, ctx) == 0) {
      if (vnode_vtype(vnode) == VDIR && !vnode_mountedhere(vnode)) {
        seen |= 1ULL << kProbeApfsMountPoint;
      }
      vnode_put(vnode);
    }
  }
  return seen | nx721j_apfs_match_trace();
}
}

class Nx721jUsbBlock : public IOBlockStorageDevice {
  OSDeclareDefaultStructors(Nx721jUsbBlock)

  IOLock *gate = nullptr;
  void *staging = nullptr;
  Nx721jUsbReadBlocks *readBlocks = nullptr;
  void *context = nullptr;
  UInt64 capacity = 0;
  bool online = false;
  bool mediaChanged = false;
  bool completedRead = false;
  UInt32 requestTrace = 0;

  void traceRequest(ProbePhase phase)
  {
    __atomic_fetch_or(&requestTrace, 1U << phase, __ATOMIC_RELAXED);
  }

  // The caller holds gate and can retire the context after releasing it.
  void clearTransport()
  {
    mediaChanged |= online;
    online = false;
    readBlocks = nullptr;
    context = nullptr;
  }

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
    if (!gate || !readBlocks || !IOBlockStorageDevice::start(provider)) {
      return false;
    }
    IOLockLock(gate);
    online = true;
    IOLockUnlock(gate);
    registerService();
    return true;
  }

  void quiesce()
  {
    // Wait for the serialized transport call before retiring its context.
    IOLockLock(gate);
    clearTransport();
    IOLockUnlock(gate);
  }

  bool reportProbeProgress(Nx721jUsbBlockTransport &transport, UInt64 topology)
  {
    IOLockLock(gate);
    bool reported = online && transport.report(completedRead ? kProbeReadCompleted : kProbePublished);
    for (UInt32 phase = kProbeGptScheme; reported && phase <= kProbeApfsMountPoint; ++phase) {
      if (topology & (1ULL << phase)) {
        reported = transport.report(phase);
      }
    }
    if (!reported) {
      clearTransport();
    }
    IOLockUnlock(gate);
    return reported;
  }

  bool reportMountStatus(Nx721jUsbBlockTransport &transport, UInt32 status)
  {
    IOLockLock(gate);
    const bool reported = online && transport.report(status);
    if (!reported) {
      clearTransport();
    }
    IOLockUnlock(gate);
    return reported;
  }

  bool reportMountResult(Nx721jUsbBlockTransport &transport, MountStage stage, int error)
  {
    return reportMountStatus(transport, mountStatusTag | (stage << 8) | (static_cast<UInt32>(error) & 0xff));
  }

  UInt32 blockRequestTrace() const
  {
    return __atomic_load_n(&requestTrace, __ATOMIC_RELAXED);
  }

  bool observedRead()
  {
    IOLockLock(gate);
    const bool observed = completedRead;
    IOLockUnlock(gate);
    return observed;
  }

  void stop(IOService *provider) override
  {
    quiesce();
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
  // The backing image is fixed for this device's lifetime. USB removal detaches the device itself.
  IOReturn reportRemovability(bool *value) override { *value = false; return kIOReturnSuccess; }
  IOReturn reportWriteProtection(bool *value) override { *value = true; return kIOReturnSuccess; }
  IOReturn getWriteCacheState(bool *value) override { *value = false; return kIOReturnSuccess; }
  IOReturn setWriteCacheState(bool) override { return kIOReturnUnsupported; }

  IOReturn reportMediaState(bool *present, bool *changed) override
  {
    IOLockLock(gate);
    *present = online;
    if (changed) {
      *changed = mediaChanged;
      mediaChanged = false;
    }
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

  IOReturn doSynchronize(UInt64, UInt64, IOStorageSynchronizeOptions) override
  {
    return doSynchronizeCache();
  }

  IOReturn doAsyncReadWrite(IOMemoryDescriptor *buffer, UInt64 block, UInt64 count,
                           IOStorageAttributes *, IOStorageCompletion *completion) override
  {
    // The host's GPT experiment places the APFS container at logical block 256.
    if (block >= 256 || count > 256 - block) {
      traceRequest(kProbeHighBlockRequest);
    }
    if (!buffer || !completion || !completion->action || !count ||
        block >= capacity || count > capacity - block ||
        buffer->getLength() < count * blockBytes) {
      traceRequest(kProbeInvalidBlockRequest);
      return kIOReturnBadArgument;
    }
    if (buffer->getDirection() != kIODirectionIn) {
      traceRequest(kProbeNonReadRequest);
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
      if (result == kIOReturnNoDevice) {
        clearTransport();
      }
      if (result == kIOReturnSuccess) {
        const IOByteCount copied = buffer->writeBytes(done, staging, length);
        done += copied;
        if (copied != length) {
          result = kIOReturnIOError;
        }
      }
    }
    if (result == kIOReturnSuccess) {
      completedRead = true;
    } else {
      traceRequest(kProbeBlockIoFailed);
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
  if (!device->init(nullptr) || !device->configure(blocks, reader, context) || !device->attach(provider)) {
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

void nx721j_usb_quiesce_block(IOService *device)
{
  if (auto *block = OSDynamicCast(Nx721jUsbBlock, device)) {
    block->quiesce();
  }
}

static IOReturn readUsbBlocks(void *context, UInt64 block, UInt32 count, void *destination)
{
  auto *transport = static_cast<Nx721jUsbBlockTransport *>(context);
  if (!transport->online) {
    return kIOReturnNoDevice;
  }
  if (transport->read(block, count, destination)) {
    return kIOReturnSuccess;
  }
  return transport->online ? kIOReturnIOError : kIOReturnNoDevice;
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

unsigned nx721j_usb_run_registration_probe(Nx721jUsbBlockTransport *transport)
{
  const auto *storage = static_cast<const OSMetaClass *>(&IOBlockStorageDevice::gMetaClass);
  const auto *block = static_cast<const OSMetaClass *>(&Nx721jUsbBlock::gMetaClass);
  if (storage->getClassSize() != sizeof(IOBlockStorageDevice) ||
      block->getClassSize() != sizeof(Nx721jUsbBlock)) {
    return 51;
  }
  auto *device = static_cast<Nx721jUsbBlock *>(
      nx721j_usb_publish_transport(IOService::getServiceRoot(), transport));
  if (!device) {
    return 52;
  }

  UInt64 reportedTopology = 0;
  bool mountAttempted = false;
  int mountError = 0;
  int readError = 0;
  int unmountError = 0;
  char devicePath[64];
  for (unsigned elapsed = 0; elapsed < probeSeconds; elapsed += probeIntervalSeconds) {
    const UInt64 topology = storageTopology(device, devicePath) | device->blockRequestTrace();
    if (!device->reportProbeProgress(*transport, topology & ~reportedTopology)) {
      break;
    }
    reportedTopology |= topology;
    if (!mountAttempted && (topology & mountPrerequisites) == mountPrerequisites) {
      if (!device->reportMountStatus(*transport, mountAttempt)) {
        break;
      }
      mountAttempted = true;
      mountError = nx721j_usb_apfs_readonly_check(devicePath, &readError, &unmountError);
      if (!device->reportMountResult(*transport, kMountVolume, mountError) ||
          (!mountError &&
           (!device->reportMountResult(*transport, kMountReadFile, readError) ||
            !device->reportMountResult(*transport, kMountUnmount, unmountError)))) {
        break;
      }
    }
    IOSleep(probeIntervalSeconds * 1000);
  }
  device->quiesce();
  const bool read = device->observedRead();
  const bool terminationRequested = device->terminate();
  if (terminationRequested) {
    for (unsigned attempt = 0; attempt < 30 && device->getProvider(); ++attempt) {
      IOSleep(100);
    }
  }
  const bool detached = device->getProvider() == nullptr;
  transport->report(detached ? kProbeDetached : kProbeDetachPending);
  const bool closed = transport->close();
  device->release();
  if (!detached) {
    return 53;
  }
  if (!read) {
    return 54;
  }
  if (!mountAttempted || mountError || readError || unmountError) {
    return 56;
  }
  return closed ? 0 : 55;
}
