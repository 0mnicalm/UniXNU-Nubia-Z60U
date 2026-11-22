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

  zero32 (command, 2 * page);
  command[0] = 0x01;            // Command UPIU, task tag and LUN 0.
  command[1] = 0x40;            // Device-to-host data.
  be32 (command + 12, page);
  command[16] = 0x28;          // READ(10), LBA 1, one logical block.
  command[21] = 1;
  command[24] = 1;
  prd[0] = uint32_t (scratch + page);
  prd[3] = page - 1;
  cacheCleanInvalidate (command, 2 * page);

  if (!nx721jUfsIdle (host, queue)) {
    panic ("NX721J XNU READ(10): inherited queue became busy");
  }
  cacheCleanInvalidate (utrd, slotBytes);
  memcpy (previous, utrd, sizeof (previous));
  zero32 (utrd, slotBytes);
  utrd[0] = 0x15000000U;       // Native UFS command, device to host, interrupt command.
  utrd[2] = 0x0fU;             // OCS invalid until completion.
  utrd[4] = uint32_t (scratch);
  utrd[6] = (responseOffset / 4) | ((responseOffset / 4) << 16);
  utrd[7] = 1U | ((prdtOffset / 4) << 16);
  cacheCleanInvalidate (utrd, slotBytes);
  write32 (host, 0x58, 1);     // Submit only slot 0. The firmware left IE disabled.
  __asm__ volatile ("dsb sy" ::: "memory");

  unsigned polls = 10000;
  while ((read32 (host, 0x58) & 1) && polls) {
    --polls;
    IODelay (10);
  }
  if (read32 (host, 0x58) & 1) {
    // Leave all DMA buffers and the submitted descriptor intact on timeout.
    panic ("NX721J XNU READ(10): timeout IS=%08x HCS=%08x DB=%08x",
           read32 (host, 0x20), read32 (host, 0x30), read32 (host, 0x58));
  }

  cacheCleanInvalidate (utrd, slotBytes);
  cacheCleanInvalidate (command, 2 * page);
  uint32_t ocs = utrd[2] & 0xff;
  memcpy (utrd, previous, sizeof (previous));
  cacheClean (utrd, slotBytes);
  const uint8_t *response = command + responseOffset;
  uint32_t size = nx721jReadLe32 (data + 12);
  bool gpt = size >= 92 && size <= page && memcmp (data, "EFI PART", 8) == 0 &&
             nx721jReadLe32 (data + 24) == 1 && nx721jReadLe32 (data + 28) == 0 &&
             nx721jGptHeaderCrc (data, size) == nx721jReadLe32 (data + 16);
  bool success = !ocs && response[0] == 0x21 && !response[3] && !response[6] &&
                 !response[7] && !getBe32 (response + 12) && gpt;
  panic ("NX721J XNU READ(10) %s\nLUN0 LBA1 DMA=%llx\nOCS=%02x UPIU=%02x rsp=%02x SCSI=%02x GPT CRC=%s",
         success ? "PASS" : "FAIL", scratch + page, ocs, response[0], response[6], response[7], gpt ? "PASS" : "FAIL");
}
