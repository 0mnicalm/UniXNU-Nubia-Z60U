// SPDX-License-Identifier: BSD-2-Clause-Patent
// Included into the NX721J diagnostic service after the NativeUfs helpers.

static uint32_t nx721jGptHeaderCrc (const uint8_t *bytes, uint32_t length)
{
  uint32_t crc = ~0U;
  for (uint32_t offset = 0; offset < length; ++offset) {
    uint8_t value = offset >= 16 && offset < 20 ? 0 : bytes[offset];
    crc ^= value;
    for (unsigned bit = 0; bit < 8; ++bit) {
      crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320U : 0);
    }
  }
  return ~crc;
}

static uint32_t nx721jReadLe32 (const uint8_t *bytes)
{
  return uint32_t (bytes[0]) | (uint32_t (bytes[1]) << 8) |
         (uint32_t (bytes[2]) << 16) | (uint32_t (bytes[3]) << 24);
}

struct Nx721jScsiSense {
  unsigned segmentBytes = 0;
  unsigned senseBytes = 0;
  unsigned format = 0;
  unsigned key = 0xff;
  unsigned asc = 0xff;
  unsigned ascq = 0xff;
};

static Nx721jScsiSense nx721jDecodeSense (const uint8_t *response, unsigned responseBytes)
{
  Nx721jScsiSense result;
  constexpr unsigned senseOffset = 34;
  if (responseBytes < senseOffset || response[0] != 0x21 || response[7] != 2) {
    return result;
  }
  result.segmentBytes = (unsigned (response[10]) << 8) | response[11];
  result.senseBytes = (unsigned (response[32]) << 8) | response[33];
  if (result.segmentBytes <= 2 || result.senseBytes == 0 || responseBytes == senseOffset) {
    return result;
  }
  unsigned available = result.segmentBytes - 2;
  if (available > result.senseBytes) {
    available = result.senseBytes;
  }
  if (available > responseBytes - senseOffset) {
    available = responseBytes - senseOffset;
  }
  const uint8_t *sense = response + senseOffset;
  result.format = sense[0] & 0x7f;
  if (result.format == 0x70 || result.format == 0x71) {
    if (available >= 3) {
      result.key = sense[2] & 0xf;
    }
    if (available >= 14 && sense[7] >= 6) {
      result.asc = sense[12];
      result.ascq = sense[13];
    }
  } else if ((result.format == 0x72 || result.format == 0x73) && available >= 4) {
    result.key = sense[1] & 0xf;
    result.asc = sense[2];
    result.ascq = sense[3];
  }
  return result;
}

static OSSharedPtr<IOMemoryMap> nx721jMapDma (uint64_t base, unsigned size)
{
  IOMemoryDescriptor *memory = IOMemoryDescriptor::withPhysicalAddress (base, size, kIODirectionInOut);
  if (!memory) {
    return {};
  }
  OSSharedPtr<IOMemoryMap> map (memory->map (kIOMapAnywhere), OSNoRetain);
  memory->release ();
  return map;
}

static bool nx721jUfsIdle (uintptr_t host, uint64_t queue)
{
  uint32_t cap = read32 (host, 0x00);
  if ((cap & (1U << 30)) && (read32 (host, 0x300) & 1)) {
    return false;
  }
  uint64_t currentQueue = uint64_t (read32 (host, 0x54)) << 32 | read32 (host, 0x50);
  return currentQueue == queue && (read32 (host, 0x34) & 1) &&
         (read32 (host, 0x30) & 3) == 3 && (read32 (host, 0x60) & 1) &&
         read32 (host, 0x24) == 0 && read32 (host, 0x58) == 0 && read32 (host, 0x78) == 0;
}

struct Nx721jUfsCompletion {
  uint32_t ocs;
  unsigned type;
  unsigned tag;
  unsigned response;
  unsigned status;
  uint32_t residual;
  Nx721jScsiSense sense;

  bool good () const {
    return ocs == 0 && type == 0x21 && tag == 0 && response == 0 && status == 0 && residual == 0;
  }

  bool needsInitialization () const {
    return ocs == 0 && type == 0x21 && tag == 0 && status == 2 &&
           sense.key == 2 && sense.asc == 4 && sense.ascq == 2;
  }
};

[[noreturn]] static void nx721jUfsReadOne ()
{
  constexpr unsigned page = 4096;
  constexpr unsigned scratchBytes = 16384;
  constexpr unsigned slotBytes = 32;
  constexpr unsigned responseOffset = 512;
  constexpr unsigned prdtOffset = 1024;
  uint64_t scratch = 0;
  uint64_t queue = 0;
  if (!PE_parse_boot_argn ("nx721j-ufs-dma", &scratch, sizeof (scratch)) ||
      !PE_parse_boot_argn ("nx721j-ufs-utrl", &queue, sizeof (queue)) ||
      !scratch || (scratch & (scratchBytes - 1)) || scratch > 0x100000000ULL - scratchBytes ||
      !queue || (queue & (page - 1)) || queue > 0x100000000ULL - page ||
      (queue >= scratch && queue < scratch + scratchBytes)) {
    panic ("NX721J XNU READ(10): missing or invalid DMA hand-off");
  }

  OSSharedPtr<IOMemoryMap> hostMap;
  uintptr_t host = mapPhys (NX721J_UFS_HOST_BASE, NX721J_UFS_HOST_SIZE, hostMap);
  if (!host || !nx721jUfsIdle (host, queue)) {
    panic ("NX721J XNU READ(10): host or inherited queue unavailable");
  }
  auto queueMap = nx721jMapDma (queue, page);
  auto scratchMap = nx721jMapDma (scratch, scratchBytes);
  if (!queueMap || !scratchMap) {
    panic ("NX721J XNU READ(10): DMA page map failed");
  }

  auto *utrd = reinterpret_cast<uint32_t *> (queueMap->getVirtualAddress ());
  auto *command = reinterpret_cast<uint8_t *> (scratchMap->getVirtualAddress ());
  auto *data = command + page;
  auto *prd = reinterpret_cast<uint32_t *> (command + prdtOffset);
  uint32_t previous[slotBytes / sizeof (uint32_t)];

  auto submit = [&] (const char *stage, uint8_t lun, const uint8_t *cdb, unsigned cdbBytes,
                     bool readBlock, unsigned polls) -> Nx721jUfsCompletion {
    zero32 (command, 2 * page);
    command[0] = 0x01; // Command UPIU, task tag 0.
    command[2] = lun;
    memcpy (command + 16, cdb, cdbBytes);
    if (readBlock) {
      command[1] = 0x40;
      be32 (command + 12, page);
      prd[0] = uint32_t (scratch + page);
      prd[3] = page - 1;
    }
    cacheCleanInvalidate (command, 2 * page);

    if (!nx721jUfsIdle (host, queue)) {
      panic ("NX721J XNU UFS %s: inherited queue became busy", stage);
    }
    cacheCleanInvalidate (utrd, slotBytes);
    memcpy (previous, utrd, sizeof (previous));
    zero32 (utrd, slotBytes);
    utrd[0] = readBlock ? 0x15000000U : 0x11000000U;
    utrd[2] = 0x0fU;
    utrd[4] = uint32_t (scratch);
    utrd[6] = (responseOffset / 4) | ((responseOffset / 4) << 16);
    utrd[7] = (prdtOffset / 4) << 16 | (readBlock ? 1U : 0U);
    cacheCleanInvalidate (utrd, slotBytes);
    write32 (host, 0x58, 1); // Submit only slot 0. Interrupts remain disabled.
    __asm__ volatile ("dsb sy" ::: "memory");

    while ((read32 (host, 0x58) & 1) && polls) {
      --polls;
      IODelay (10);
    }
    if (read32 (host, 0x58) & 1) {
      // Leave the in-flight descriptor and both buffers intact on timeout.
      panic ("NX721J XNU UFS %s: timeout IS=%08x HCS=%08x DB=%08x",
             stage, read32 (host, 0x20), read32 (host, 0x30), read32 (host, 0x58));
    }

    cacheCleanInvalidate (utrd, slotBytes);
    cacheCleanInvalidate (command, 2 * page);
    const uint8_t *response = command + responseOffset;
    Nx721jUfsCompletion result = {utrd[2] & 0xff, response[0], response[3], response[6], response[7],
                                  getBe32 (response + 12), nx721jDecodeSense (response, responseOffset)};
    memcpy (utrd, previous, sizeof (previous));
    cacheClean (utrd, slotBytes);
    return result;
  };

  const uint8_t read10[] = {0x28, 0, 0, 0, 0, 1, 0, 0, 1, 0};
  Nx721jUfsCompletion read = submit ("READ(10)", 0, read10, sizeof (read10), true, 10000);
  const char *wakeResult = "skipped";
  if (read.needsInitialization ()) {
    const uint8_t active[] = {0x1b, 0, 0, 0, 0x10, 0};
    Nx721jUfsCompletion wake = submit ("START STOP ACTIVE", 0xd0, active, sizeof (active), false, 1000000);
    if (!wake.good ()) {
      panic ("NX721J UFS START STOP ACTIVE FAIL\n"
             "Initial READ sense=02/04/02\nOCS=%02x UPIU=%02x rsp=%02x SCSI=%02x\nsense=%02x/%02x/%02x",
             wake.ocs, wake.type, wake.response, wake.status, wake.sense.key, wake.sense.asc, wake.sense.ascq);
    }
    const uint8_t ready[] = {0, 0, 0, 0, 0, 0};
    Nx721jUfsCompletion tur = submit ("TEST UNIT READY", 0, ready, sizeof (ready), false, 100000);
    if (!tur.good ()) {
      panic ("NX721J UFS TEST UNIT READY FAIL\n"
             "START STOP ACTIVE PASS\nOCS=%02x UPIU=%02x rsp=%02x SCSI=%02x\nsense=%02x/%02x/%02x",
             tur.ocs, tur.type, tur.response, tur.status, tur.sense.key, tur.sense.asc, tur.sense.ascq);
    }
    wakeResult = "ACTIVE PASS / TUR PASS";
    read = submit ("READ(10) retry", 0, read10, sizeof (read10), true, 10000);
  }

  uint32_t size = nx721jReadLe32 (data + 12);
  bool gpt = read.good () && size >= 92 && size <= page && memcmp (data, "EFI PART", 8) == 0 &&
             nx721jReadLe32 (data + 24) == 1 && nx721jReadLe32 (data + 28) == 0 &&
             nx721jGptHeaderCrc (data, size) == nx721jReadLe32 (data + 16);
  if (!read.ocs && read.type == 0x21 && read.status == 2) {
    panic ("NX721J XNU READ(10) CHECK CONDITION\n"
           "Wake: %s\n"
           "sense key=%02x ASC=%02x ASCQ=%02x fmt=%02x\n"
           "OCS=%02x UPIU=%02x rsp=%02x SCSI=%02x",
           wakeResult, read.sense.key, read.sense.asc, read.sense.ascq, read.sense.format,
           read.ocs, read.type, read.response, read.status);
  }
  panic ("NX721J XNU READ(10) %s\nWake: %s\nLUN0 LBA1 DMA=%llx\nOCS=%02x UPIU=%02x rsp=%02x SCSI=%02x GPT CRC=%s",
         gpt ? "PASS" : "FAIL", wakeResult, scratch + page, read.ocs, read.type, read.response, read.status,
         !read.good () ? "SKIP" : gpt ? "PASS" : "FAIL");
}
