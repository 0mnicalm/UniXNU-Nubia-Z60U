// SPDX-License-Identifier: BSD-2-Clause-Patent
// Included into the NX721J diagnostic service after the NativeUfs helpers.

static uint32_t nx721jCrcByte (uint32_t crc, uint8_t value)
{
  crc ^= value;
  for (unsigned bit = 0; bit < 8; ++bit) {
    crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320U : 0);
  }
  return crc;
}

static uint32_t nx721jGptHeaderCrc (const uint8_t *bytes, uint32_t length)
{
  uint32_t crc = ~0U;
  for (uint32_t offset = 0; offset < length; ++offset) {
    uint8_t value = offset >= 16 && offset < 20 ? 0 : bytes[offset];
    crc = nx721jCrcByte (crc, value);
  }
  return ~crc;
}

static uint32_t nx721jReadLe32 (const uint8_t *bytes)
{
  return uint32_t (bytes[0]) | (uint32_t (bytes[1]) << 8) |
         (uint32_t (bytes[2]) << 16) | (uint32_t (bytes[3]) << 24);
}

static uint64_t nx721jReadLe64 (const uint8_t *bytes)
{
  return nx721jReadLe32 (bytes) | (uint64_t (nx721jReadLe32 (bytes + 4)) << 32);
}

struct Nx721jGptHeader {
  uint64_t firstUsable;
  uint64_t lastUsable;
  uint64_t arrayLba;
  uint64_t guidLow;
  uint64_t guidHigh;
  uint32_t entryCount;
  uint32_t entrySize;
  uint32_t arrayCrc;
  uint32_t arrayBytes;
  uint32_t arrayBlocks;
};

static constexpr uint32_t nx721jLun0LastLba = 124002303;
static constexpr uint32_t nx721jLun0BlockBytes = 4096;

static bool nx721jParseGpt (const uint8_t *block, bool primary, Nx721jGptHeader &header)
{
  uint32_t size = nx721jReadLe32 (block + 12);
  if (memcmp (block, "EFI PART", 8) || nx721jReadLe32 (block + 8) != 0x10000 ||
      size < 92 || size > nx721jLun0BlockBytes || nx721jReadLe32 (block + 20) != 0 ||
      nx721jReadLe64 (block + 24) != (primary ? 1U : nx721jLun0LastLba) ||
      nx721jReadLe64 (block + 32) != (primary ? nx721jLun0LastLba : 1U) ||
      nx721jGptHeaderCrc (block, size) != nx721jReadLe32 (block + 16)) {
    return false;
  }
  header = {nx721jReadLe64 (block + 40), nx721jReadLe64 (block + 48), nx721jReadLe64 (block + 72),
            nx721jReadLe64 (block + 56), nx721jReadLe64 (block + 64), nx721jReadLe32 (block + 80),
            nx721jReadLe32 (block + 84), nx721jReadLe32 (block + 88), 0, 0};
  uint64_t arrayBytes = uint64_t (header.entryCount) * header.entrySize;
  if (header.entrySize < 128 || header.entrySize > nx721jLun0BlockBytes ||
      (header.entrySize & (header.entrySize - 1)) || !arrayBytes || arrayBytes > 64 * nx721jLun0BlockBytes ||
      header.firstUsable < 2 || header.firstUsable > header.lastUsable ||
      header.lastUsable >= nx721jLun0LastLba || header.arrayLba < 2 || header.arrayLba >= nx721jLun0LastLba) {
    return false;
  }
  header.arrayBytes = uint32_t (arrayBytes);
  header.arrayBlocks = (header.arrayBytes + nx721jLun0BlockBytes - 1) / nx721jLun0BlockBytes;
  uint64_t arrayEnd = header.arrayLba + header.arrayBlocks;
  return primary ? arrayEnd <= header.firstUsable :
                   header.arrayLba > header.lastUsable && arrayEnd <= nx721jLun0LastLba;
}

static bool nx721jGptSlotName (const uint8_t *entry)
{
  const uint8_t *name = entry + 56;
  unsigned end = 0;
  while (end < 72 && (name[end] || name[end + 1])) {
    end += 2;
  }
  return end >= 4 && name[end - 4] == '_' && !name[end - 3] && !name[end - 1] &&
         (name[end - 2] == 'a' || name[end - 2] == 'b');
}

static bool nx721jGptSuperName (const uint8_t *entry)
{
  static constexpr uint8_t name[] = {'s', 0, 'u', 0, 'p', 0, 'e', 0, 'r', 0, 0, 0};
  return memcmp (entry + 56, name, sizeof (name)) == 0;
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
  constexpr unsigned page = nx721jLun0BlockBytes;
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

  auto readBlock = [&] (const char *stage, uint32_t lba) {
    uint8_t cdb[] = {0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0};
    be32 (cdb + 2, lba);
    return submit (stage, 0, cdb, sizeof (cdb), true, 10000);
  };
  Nx721jUfsCompletion read = readBlock ("READ(10)", 1);
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
    read = readBlock ("READ(10) retry", 1);
  }

  if (!read.ocs && read.type == 0x21 && read.status == 2) {
    panic ("NX721J XNU READ(10) CHECK CONDITION\n"
           "Wake: %s\n"
           "sense key=%02x ASC=%02x ASCQ=%02x fmt=%02x\n"
           "OCS=%02x UPIU=%02x rsp=%02x SCSI=%02x",
           wakeResult, read.sense.key, read.sense.asc, read.sense.ascq, read.sense.format,
           read.ocs, read.type, read.response, read.status);
  }
  Nx721jGptHeader primary, backup;
  if (!read.good () || !nx721jParseGpt (data, true, primary)) {
    panic ("NX721J XNU READ(10) %s\nWake: %s\nOCS=%02x UPIU=%02x rsp=%02x SCSI=%02x primary GPT invalid",
           "FAIL", wakeResult, read.ocs, read.type, read.response, read.status);
  }
  auto getBlock = [&] (const char *stage, uint32_t lba) {
    Nx721jUfsCompletion done = readBlock (stage, lba);
    if (!done.good ()) {
      panic ("NX721J XNU GPT %s read failed LBA=%u\nOCS=%02x UPIU=%02x rsp=%02x SCSI=%02x\nsense=%02x/%02x/%02x",
             stage, lba, done.ocs, done.type, done.response, done.status, done.sense.key, done.sense.asc, done.sense.ascq);
    }
  };
  getBlock ("backup header", nx721jLun0LastLba);
  if (!nx721jParseGpt (data, false, backup) || primary.guidLow != backup.guidLow || primary.guidHigh != backup.guidHigh ||
      primary.firstUsable != backup.firstUsable || primary.lastUsable != backup.lastUsable ||
      primary.entryCount != backup.entryCount || primary.entrySize != backup.entrySize || primary.arrayCrc != backup.arrayCrc) {
    panic ("NX721J XNU GPT backup header invalid or disagrees\nWake: %s", wakeResult);
  }

  // The third scratch page is CPU-only. Save each primary block there before
  // the next READ(10) reuses the tested DMA buffer for the backup block.
  uint8_t *saved = data + page;
  uint32_t raw = ~0U;
  uint32_t normalized = ~0U;
  uint64_t superFirst = 0;
  uint64_t superLast = 0;
  for (uint32_t i = 0; i < primary.arrayBlocks; ++i) {
    uint32_t remaining = primary.arrayBytes - i * page;
    uint32_t valid = remaining < page ? remaining : page;
    getBlock ("primary entries", uint32_t (primary.arrayLba) + i);
    memcpy (saved, data, valid);
    getBlock ("backup entries", uint32_t (backup.arrayLba) + i);
    if (memcmp (saved, data, valid) != 0) {
      panic ("NX721J XNU GPT primary and backup entries differ\nArray block %u", i);
    }
    for (uint32_t at = 0; at < valid; at += primary.entrySize) {
      const uint8_t *entry = data + at;
      if (nx721jGptSuperName (entry) && (nx721jReadLe64 (entry) || nx721jReadLe64 (entry + 8))) {
        if (superFirst) {
          panic ("NX721J XNU duplicate super GPT entry");
        }
        superFirst = nx721jReadLe64 (entry + 32);
        superLast = nx721jReadLe64 (entry + 40);
        if (superFirst < primary.firstUsable || superLast > primary.lastUsable || superLast < superFirst) {
          panic ("NX721J XNU invalid super GPT bounds");
        }
      }
      bool ab = nx721jGptSlotName (entry);
      for (uint32_t byte = 0; byte < primary.entrySize; ++byte) {
        raw = nx721jCrcByte (raw, entry[byte]);
        normalized = nx721jCrcByte (normalized, ab && byte == 54 ? 0 : entry[byte]);
      }
    }
  }
  if (~raw != primary.arrayCrc) {
    panic ("NX721J XNU GPT entry array CRC FAIL\nRead=%08x header=%08x", ~raw, primary.arrayCrc);
  }
  // TWRP has observed both normalized layout CRCs; super has the same bounds in both.
  bool baseline = primary.guidLow == 0xb0b21a6df50b5a95ULL && primary.guidHigh == 0x4716ecf679b676f9ULL &&
                  (~normalized == 0x35d1cb6aU || ~normalized == 0x692e08b8U);
  if (!baseline || superFirst != 8968 || superLast != 3154695) {
    panic ("NX721J XNU super GPT baseline DIFF\nEntries CRC=%08x normalized=%08x\nsuper LBA=%llu..%llu",
           ~raw, ~normalized, (unsigned long long) superFirst, (unsigned long long) superLast);
  }

  // Android liblp places two geometry blocks after a reserved 4 KiB block,
  // followed by the primary metadata slots at a stride of metadata_max_size.
  constexpr uint32_t metadataMaxBytes = 65536;
  struct SuperBlock {
    const char *stage;
    uint32_t offset;
    uint32_t magic;
    uint32_t crc;
  };
  constexpr SuperBlock checks[] = {
    {"super geometry", 1, 0x616c4467, 0x59c8de0f},
    {"super backup geometry", 2, 0x616c4467, 0x59c8de0f},
    {"super metadata A", 3, 0x414c5030, 0xd6cea9a8},
    {"super metadata B", 3 + metadataMaxBytes / page, 0x414c5030, 0xd6cea9a8},
  };
  for (const auto &block : checks) {
    uint32_t lba = uint32_t (superFirst) + block.offset;
    getBlock (block.stage, lba);
    uint32_t crc = ~0U;
    for (uint32_t at = 0; at < page; ++at) {
      crc = nx721jCrcByte (crc, data[at]);
    }
    uint32_t magic = nx721jReadLe32 (data);
    if (magic != block.magic || ~crc != block.crc) {
      panic ("NX721J XNU %s DIFF\nLBA=%u magic=%08x\nCRC=%08x expected=%08x",
             block.stage, lba, magic, ~crc, block.crc);
    }
  }
  panic ("NX721J XNU super metadata PASS\nWake: %s\nGPT sweep PASS normalized=%08x\n"
         "super LBA=%u / 4 blocks MATCH\nGeometry CRC=59c8de0f\nSlot A/B CRC=d6cea9a8",
         wakeResult, ~normalized, uint32_t (superFirst));
}
