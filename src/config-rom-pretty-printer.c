// config-rom-pretty-printer.c - Pretty printer for content of configuration
// rom
//
// Copyright 2023 Takashi Sakamoto <o-takashi@sakamocchi.jp>
//
// licensed under the terms of the GNU General Public License, version 2

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>

#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <sys/queue.h>

#define CONST_ARRAY_SIZE(entries) (sizeof(entries) / sizeof(entries[0]))

#define LINE_WIDTH                100

//////////////////////////////////////////////////////////////
// Helpers to detect layout of blocks according to IEEE 1212.
//////////////////////////////////////////////////////////////

enum ieee1212_block_type {
    IEEE1212_BUS_INFO_BLOCK = 0,
    IEEE1212_ROOT_DIRECTORY_BLOCK,
    IEEE1212_LEAF_BLOCK,
    IEEE1212_DIRECTORY_BLOCK,
    ORPHAN_BLOCK,
};

struct ieee1212_block {
    size_t offset;
    size_t length;
    enum ieee1212_block_type block_type;
    const uint8_t *content;
    union {
        struct {
            uint8_t key_id;
            const struct ieee1212_block *parent;
        } leaf;
        struct {
            uint8_t key_id;
            const struct ieee1212_block *parent;
        } directory;
    } data;
    LIST_ENTRY(ieee1212_block) list;
};

LIST_HEAD(list_head, ieee1212_block);

static void insert_block_by_offset(struct list_head *head, struct ieee1212_block *entry)
{
    if (LIST_EMPTY(head)) {
        LIST_INSERT_HEAD(head, entry, list);
    } else {
        struct ieee1212_block *cursor = LIST_FIRST(head);

        while (true) {
            struct ieee1212_block *peek = LIST_NEXT(cursor, list);

            if (peek == NULL || peek->offset > entry->offset) {
                LIST_INSERT_AFTER(cursor, entry, list);
                break;
            }
            cursor = peek;
        }
    }
}

#define IEEE1212_BUS_INFO_BLOCK_LENGTH_MASK  0xff000000
#define IEEE1212_BUS_INFO_BLOCK_LENGTH_SHIFT 24
#define IEEE1212_BUS_INFO_CRC_LENGTH_MASK    0x00ff0000
#define IEEE1212_BUS_INFO_CRC_LENGTH_SHIFT   16
#define IEEE1212_BUS_INFO_CRC_MASK           0x0000ffff
#define IEEE1212_BUS_INFO_CRC_SHIFT          0

static int detect_ieee1212_bus_info_block_length(const uint8_t *data, ssize_t length, size_t offset,
                                                 size_t *block_length)
{
    uint32_t quadlet = ((uint32_t *)data)[0];

    *block_length = 4;
    *block_length += 4 * (quadlet & IEEE1212_BUS_INFO_BLOCK_LENGTH_MASK) >>
                     IEEE1212_BUS_INFO_BLOCK_LENGTH_SHIFT;

    if (offset + *block_length > length)
        return -EINVAL;

    return 0;
}

static int detect_ieee1212_bus_info_block(const uint8_t *data, ssize_t length, size_t offset,
                                          size_t block_length, struct list_head *head)
{
    struct ieee1212_block *entry;

    entry = malloc(sizeof(*entry));
    if (entry == NULL)
        return -ENOMEM;

    entry->offset = offset;
    entry->length = block_length;
    entry->block_type = IEEE1212_BUS_INFO_BLOCK;
    entry->content = data + offset;

    insert_block_by_offset(head, entry);

    return 0;
}

#define IEEE1212_BLOCK_LENGTH_MASK  0xffff0000
#define IEEE1212_BLOCK_LENGTH_SHIFT 16
#define IEEE1212_BLOCK_CRC_MASK     0x0000ffff
#define IEEE1212_BLOCK_CRC_SHIFT    0

static int detect_ieee1212_block_length(const uint8_t *data, ssize_t length, size_t offset,
                                        size_t *block_length)
{
    uint32_t quadlet = ((uint32_t *)(data + offset))[0];

    *block_length = 4;
    *block_length += 4 * (quadlet & IEEE1212_BLOCK_LENGTH_MASK) >> IEEE1212_BLOCK_LENGTH_SHIFT;

    if (offset + *block_length > length)
        return -EINVAL;

    return 0;
}

static int detect_ieee1212_leaf_block(const uint8_t *data, ssize_t length, size_t block_offset,
                                      size_t block_length, uint8_t key_id,
                                      const struct ieee1212_block *parent, struct list_head *head)
{
    struct ieee1212_block *entry;

    LIST_FOREACH(entry, head, list)
    {
        if (entry->offset == block_offset)
            return 0;
    }

    entry = malloc(sizeof(*entry));
    if (entry == NULL)
        return -ENOMEM;

    entry->offset = block_offset;
    entry->length = block_length;
    entry->block_type = IEEE1212_LEAF_BLOCK;
    entry->content = data + block_offset;
    entry->data.leaf.key_id = key_id;
    entry->data.leaf.parent = parent;

    insert_block_by_offset(head, entry);

    return 0;
}

#define DIRECTORY_ENTRY_KEY_TYPE_MASK  0xc0000000
#define DIRECTORY_ENTRY_KEY_TYPE_SHIFT 30
#define DIRECTORY_ENTRY_KEY_ID_MASK    0x3f000000
#define DIRECTORY_ENTRY_KEY_ID_SHIFT   24
#define DIRECTORY_ENTRY_VALUE_MASK     0x00ffffff
#define DIRECTORY_ENTRY_VALUE_SHIFT    0

#define KEY_TYPE_IMMEDIATE             0
#define KEY_TYPE_CSR_OFFSET            1
#define KEY_TYPE_LEAF                  2
#define KEY_TYPE_DIRECTORY             3

static void decode_directory_entry(uint32_t quadlet, uint8_t *key_type, uint8_t *key_id,
                                   uint32_t *value)
{
    *key_type = (quadlet & DIRECTORY_ENTRY_KEY_TYPE_MASK) >> DIRECTORY_ENTRY_KEY_TYPE_SHIFT;
    *key_id = (quadlet & DIRECTORY_ENTRY_KEY_ID_MASK) >> DIRECTORY_ENTRY_KEY_ID_SHIFT;
    *value = (quadlet & DIRECTORY_ENTRY_VALUE_MASK) >> DIRECTORY_ENTRY_VALUE_SHIFT;
}

static int detect_ieee1212_directory_block(const uint8_t *data, ssize_t length, size_t offset,
                                           size_t block_length, uint8_t key_id,
                                           const struct ieee1212_block *parent,
                                           struct list_head *head);

static int detect_ieee1212_directory_entries(const uint8_t *data, ssize_t length,
                                             size_t directory_offset, size_t directory_length,
                                             const struct ieee1212_block *parent,
                                             struct list_head *head)
{
    size_t quadlet_count;
    int err;
    int i;

    directory_offset += 4;
    quadlet_count = (directory_length - 4) / 4;

    for (i = 0; i < quadlet_count; ++i) {
        size_t entry_offset = directory_offset + i * 4;
        uint32_t quadlet = *((uint32_t *)(data + entry_offset));
        uint8_t key_type;
        uint8_t key_id;
        uint32_t value;

        decode_directory_entry(quadlet, &key_type, &key_id, &value);

        switch (key_type) {
        case KEY_TYPE_LEAF:
        case KEY_TYPE_DIRECTORY: {
            int (*detect_block)(const uint8_t *data, ssize_t length, size_t block_offset,
                                size_t block_length, uint8_t key_id,
                                const struct ieee1212_block *parent, struct list_head *head);
            size_t block_offset;
            size_t block_length;

            block_offset = entry_offset + 4 * value;
            if (block_offset >= length)
                return -ENOSPC;

            err = detect_ieee1212_block_length(data, length, block_offset, &block_length);
            if (err < 0)
                return err;

            if (key_type == KEY_TYPE_LEAF)
                detect_block = detect_ieee1212_leaf_block;
            else
                detect_block = detect_ieee1212_directory_block;

            err = detect_block(data, length, block_offset, block_length, key_id, parent, head);
            if (err < 0)
                return err;
            break;
        }
        default:
            break;
        }
    }

    return 0;
}

static int detect_ieee1212_directory_block(const uint8_t *data, ssize_t length, size_t block_offset,
                                           size_t block_length, uint8_t key_id,
                                           const struct ieee1212_block *parent,
                                           struct list_head *head)
{
    struct ieee1212_block *entry;

    LIST_FOREACH(entry, head, list)
    {
        if (entry->offset == block_offset)
            return 0;
    }

    entry = malloc(sizeof(*entry));
    if (entry == NULL)
        return -ENOMEM;

    entry->offset = block_offset;
    entry->length = block_length;
    entry->block_type = IEEE1212_DIRECTORY_BLOCK;
    entry->content = data + block_offset;
    entry->data.directory.key_id = key_id;
    entry->data.directory.parent = parent;

    insert_block_by_offset(head, entry);

    return detect_ieee1212_directory_entries(data, length, block_offset, block_length, entry, head);
}

static int detect_ieee1212_root_directory_block(const uint8_t *data, ssize_t length,
                                                size_t block_offset, size_t block_length,
                                                struct list_head *head)
{
    struct ieee1212_block *entry;

    entry = malloc(sizeof(*entry));
    if (entry == NULL)
        return -ENOMEM;

    entry->offset = block_offset;
    entry->length = block_length;
    entry->block_type = IEEE1212_ROOT_DIRECTORY_BLOCK;
    entry->content = data + block_offset;

    insert_block_by_offset(head, entry);

    return detect_ieee1212_directory_entries(data, length, block_offset, block_length, entry, head);
}

static int detect_ieee1212_blocks(const uint8_t *data, ssize_t length, struct list_head *head)
{
    size_t offset = 0;
    size_t block_length;
    int err;

    err = detect_ieee1212_bus_info_block_length(data, length, offset, &block_length);
    if (err < 0)
        return err;

    err = detect_ieee1212_bus_info_block(data, length, offset, block_length, head);
    if (err < 0)
        return err;

    offset += block_length;
    err = detect_ieee1212_block_length(data, length, offset, &block_length);
    if (err < 0)
        return err;

    return detect_ieee1212_root_directory_block(data, length, offset, block_length, head);
}

static void normalize_blocks(struct list_head *head, size_t length)
{
    struct ieee1212_block *entry;

    entry = LIST_FIRST(head);
    while (entry != NULL) {
        struct ieee1212_block *peek = LIST_NEXT(entry, list);
        size_t next_offset;

        if (peek != NULL)
            next_offset = peek->offset;
        else
            next_offset = length;

        if (entry->offset + entry->length > next_offset)
            entry->length = next_offset - entry->offset;

        entry = peek;
    }
}

static int fulfill_orphan_blocks(const uint8_t *data, ssize_t length, struct list_head *head)
{
    struct ieee1212_block *entry;
    int err = 0;

    entry = LIST_FIRST(head);
    while (entry != NULL) {
        struct ieee1212_block *peek = LIST_NEXT(entry, list);
        size_t next_offset;

        if (peek != NULL)
            next_offset = peek->offset;
        else
            next_offset = length;

        if (entry->offset + entry->length >= next_offset) {
            entry = peek;
        } else {
            struct ieee1212_block *orphan;

            orphan = malloc(sizeof(*orphan));
            if (orphan == NULL)
                return -ENOMEM;

            orphan->offset = entry->offset + entry->length;
            orphan->length = next_offset - orphan->offset;
            orphan->block_type = ORPHAN_BLOCK;
            orphan->content = data + orphan->offset;

            insert_block_by_offset(head, orphan);
        }
    }

    return err;
}

static bool bus_info_block_is_big_endian(const uint8_t *data, ssize_t length, size_t offset)
{
    const uint32_t quadlet = ((uint32_t *)data)[offset + 1];

    return quadlet == 0x1394;
}

static int print_blocks(const uint8_t *data, ssize_t data_length, struct list_head *head);

int main(int argc, const char *argv[])
{
    struct list_head head;
    struct ieee1212_block *entry;

    int fd = fileno(stdin);
    int err;

    // The size of region for configuration rom is fixed in IEEE 1212.
    uint8_t data[1024];
    ssize_t length = 0;
    size_t offset = 0;

    bool is_big_endian;

    if (isatty(fd)) {
        fprintf(stderr, "A terminal is detected for standard input. Output from "
                        "any process or shell "
                        "redirection should be referred instead.\n");
        return EXIT_FAILURE;
    }

    length = read(fd, data, sizeof(data));
    if (length <= 0)
        return EXIT_FAILURE;

    is_big_endian = bus_info_block_is_big_endian(data, length, offset);
    if (is_big_endian) {
        uint32_t *quadlet = (uint32_t *)data;
        int i;

        for (i = 0; i < length / 4; ++i)
            quadlet[i] = be32toh(quadlet[i]);
    }

    LIST_INIT(&head);

    err = detect_ieee1212_blocks(data, length, &head);
    if (err < 0)
        goto end;
    normalize_blocks(&head, length);

    err = fulfill_orphan_blocks(data, length, &head);
    if (err < 0)
        goto end;

    err = print_blocks(data, length, &head);
end:
    entry = LIST_FIRST(&head);
    while (entry != NULL) {
        struct ieee1212_block *peek = LIST_NEXT(entry, list);
        free(entry);
        entry = peek;
    }
    LIST_INIT(&head);

    if (err < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

////////////////////////////////////////
// Helpers to format content of blocks.
////////////////////////////////////////

#define IEEE1212_REGISTER_SPACE_ADDRESS 0xfffff0000000
#define IEEE1212_CONFIG_ROM_OFFSET      0x400

#define KEY_ID_CSR_DESCRIPTOR           0x01
#define KEY_ID_CSR_BUS_DEP_INFO         0x02
#define KEY_ID_CSR_VENDOR_INFO          0x03
#define KEY_ID_CSR_HARDWARE_VERSION     0x04
#define KEY_ID_CSR_MODULE_INFO          0x07
#define KEY_ID_CSR_NODE_CAPS            0x0c
#define KEY_ID_CSR_EUI_64               0x0d
#define KEY_ID_CSR_UNIT                 0x11
#define KEY_ID_CSR_SPECIFIER_ID         0x12
#define KEY_ID_CSR_VERSION              0x13
#define KEY_ID_CSR_DEP_INFO             0x14
#define KEY_ID_CSR_UNIT_LOCATION        0x15
#define KEY_ID_CSR_MODEL                0x17
#define KEY_ID_CSR_INSTANCE             0x18
#define KEY_ID_CSR_KEYWORD              0x19
#define KEY_ID_CSR_FEATURE              0x1au
#define KEY_ID_CSR_MODIFIABLE_DESC      0x1f
#define KEY_ID_CSR_DIRECTORY_ID         0x20

#define INVALID_KEY_ID                  0xff // 6 bits are allowed for valid key id.
#define INVALID_KEY_VALUE               0xffffffff // 24 bits are allowed for valid value.

#define UNSPECIFIED_ENTRY_NAME          "(unspecified)"

struct spec_identifier {
    uint32_t specifier_id;
    uint32_t version;
};

struct key_formatter {
    uint8_t key_type;
    uint8_t key_id;
    const char *key_id_name;
    union {
        size_t (*immediate)(char *buf, size_t length, uint32_t value);
        size_t (*leaf)(char **buf, size_t length, size_t offset, const uint32_t *quadlets,
                       size_t quadlet_count, const char *spec_name);
        size_t (*directory)(char **buf, size_t length, size_t offset, const uint32_t *quadlets,
                            size_t quadlet_count, const struct spec_identifier *identifier);
    } format_content;
};

static void detect_key_formatter(const struct key_formatter **formatter, const char **spec_name,
                                 const struct spec_identifier *identifier, uint32_t key_type,
                                 uint32_t key_id);

static size_t format_line_prefix(char *buf, size_t length, size_t offset, uint32_t quadlet,
                                 bool add_delimiter)
{
    size_t consumed;

    offset += IEEE1212_CONFIG_ROM_OFFSET;

    consumed = snprintf(buf, length, "%3lx  %08x", offset, quadlet);

    if (add_delimiter)
        consumed += snprintf(buf + consumed, length - consumed, "  ");

    return consumed;
}

static size_t format_blank_prefix(char *buf, size_t length)
{
    size_t consumed = snprintf(buf, length, "%3x  %08x  ", IEEE1212_CONFIG_ROM_OFFSET, 0u);
    memset(buf, ' ', consumed);
    return consumed;
}

static size_t format_horizontal_line(char *buf, size_t length)
{
    return snprintf(buf, length,
                    "-----------------------------------------------------------------");
}

static uint16_t compute_itu_t_crc_16(const uint32_t *quadlet, size_t quadlet_count)
{
    uint32_t crc = 0;
    int i;

    for (i = 0; i < quadlet_count; ++i) {
        int shift;

        for (shift = 28; shift >= 0; shift -= 4) {
            uint32_t sum = ((crc >> 12) ^ (quadlet[i] >> shift)) & 0x0000000f;

            crc = ((crc << 4) ^ (sum << 12) ^ (sum << 5) ^ sum) & 0x0000ffff;
        }
    }

    return (uint16_t)crc;
}

static size_t format_bus_info_metadata(char *buf, size_t length, const uint32_t *quadlet,
                                       size_t quadlet_count, size_t data_length)
{
    uint8_t block_length = (quadlet[0] & IEEE1212_BUS_INFO_BLOCK_LENGTH_MASK) >>
                           IEEE1212_BUS_INFO_BLOCK_LENGTH_SHIFT;
    uint8_t crc_length = (quadlet[0] & IEEE1212_BUS_INFO_CRC_LENGTH_MASK) >>
                         IEEE1212_BUS_INFO_CRC_LENGTH_SHIFT;
    uint16_t crc = (quadlet[0] & IEEE1212_BUS_INFO_CRC_MASK) >> IEEE1212_BUS_INFO_CRC_SHIFT;
    uint16_t actual_crc;
    size_t consumed;

    consumed = snprintf(buf, length, "bus_info_length %d", block_length);

    consumed += snprintf(buf + consumed, length - consumed, ", crc_length %d", crc_length);
    if (4 * (crc_length + 1) <= data_length) {
        actual_crc = compute_itu_t_crc_16(quadlet + 1, crc_length);
    } else {
        uint8_t effective_crc_length = (data_length - 4) / 4;
        consumed +=
            snprintf(buf + consumed, length - consumed, " (up to %d)", effective_crc_length);
        actual_crc = compute_itu_t_crc_16(quadlet + 1, effective_crc_length);
    }

    consumed += snprintf(buf + consumed, length - consumed, ", crc %d", crc);
    if (crc != actual_crc)
        consumed += snprintf(buf + consumed, length - consumed, " (should be %d)", actual_crc);

    return consumed;
}

static size_t format_ieee1394_bus_dependent_information(char **buf, size_t length, size_t offset,
                                                        uint32_t quadlet)
{
    bool irm_capable = (quadlet & 0x80000000) >> 31;
    bool cm_capable = (quadlet & 0x40000000) >> 30;
    bool is_capable = (quadlet & 0x20000000) >> 29;
    bool bm_capable = (quadlet & 0x10000000) >> 28;
    uint8_t cyc_clk_acc = (quadlet & 0x00ff0000) >> 16;
    uint8_t max_rec = (quadlet & 0x0000f000) >> 12;
    uint8_t generation = (quadlet & 0x000000f0) >> 4;
    size_t lines;
    size_t consumed;

    lines = 0;

    if (generation > 0) {
        bool pm_capable = (quadlet & 0x08000000) >> 27;
        uint8_t max_rom = (quadlet & 0x00000300) >> 8;
        uint8_t spd = quadlet & 0x00000007;

        consumed = format_line_prefix(buf[lines], length, offset, quadlet, true);
        snprintf(buf[lines] + consumed, length - consumed,
                 "irmc %d, cmc %d, isc %d, bmc %d, pmc %d, cyc_clk_acc %d,", irm_capable,
                 cm_capable, is_capable, bm_capable, pm_capable, cyc_clk_acc);
        ++lines;

        consumed = format_blank_prefix(buf[lines], length);
        snprintf(buf[lines] + consumed, length - consumed,
                 "max_rec %d (%d), max_rom %d, gen %d, spd %d (S%d00)", max_rec, 2 << max_rec,
                 max_rom, generation, spd, 1 << spd);
        ++lines;
    } else {
        consumed = format_line_prefix(buf[0], length, offset, quadlet, true);
        snprintf(buf[lines] + consumed, length - consumed,
                 "irmc %d, cmc %d, isc %d, bmc %d, cyc_clk_acc %d, max_rec %d (%d)", irm_capable,
                 cm_capable, is_capable, bm_capable, cyc_clk_acc, max_rec, 2 << max_rec);
        ++lines;
    }

    return lines;
}

static size_t format_unspecified_bus_dependent_information(char **buf, size_t length, size_t offset,
                                                           uint32_t quadlet)
{
    format_line_prefix(buf[0], length, offset, quadlet, false);

    return 1;
}

static size_t format_bus_info_block(char **buf, size_t length,
                                    const struct ieee1212_block *bus_info, size_t data_length)
{
    static const struct {
        uint32_t bus_name_value;
        const char *bus_name;
        size_t (*format)(char **buf, size_t length, size_t offset, uint32_t quadlet);
    } *bus_entry, bus_entries[] = {
        {
            0x31333934,
            "1394",
            format_ieee1394_bus_dependent_information,
        },
        {
            0xffffffff,
            "unspecified",
            format_unspecified_bus_dependent_information,
        },
    };
    size_t offset = bus_info->offset;
    const uint32_t *quadlet = (const uint32_t *)bus_info->content;
    size_t quadlet_count = bus_info->length / 4;
    size_t lines;
    size_t consumed;
    uint32_t company_id;
    uint64_t device_id;
    uint64_t eui64;
    int i;

    lines = 0;

    consumed = format_blank_prefix(buf[lines], length);
    snprintf(buf[lines] + consumed, length - consumed, "ROM header and bus information block");
    ++lines;

    consumed = format_blank_prefix(buf[lines], length);
    format_horizontal_line(buf[lines] + consumed, length - consumed);
    ++lines;

    consumed = format_line_prefix(buf[lines], length, offset, quadlet[0], true);
    format_bus_info_metadata(buf[lines] + consumed, length - consumed, quadlet, quadlet_count,
                             data_length);
    ++lines;

    bus_entry = NULL;
    for (i = 0; i < CONST_ARRAY_SIZE(bus_entries); ++i) {
        if (bus_entries[i].bus_name_value == quadlet[1]) {
            bus_entry = bus_entries + i;
            break;
        }
    }
    if (bus_entry == NULL)
        bus_entry = &bus_entries[CONST_ARRAY_SIZE(bus_entries) - 1];

    consumed = format_line_prefix(buf[lines], length, offset + 4, quadlet[1], true);
    snprintf(buf[lines] + consumed, length - consumed, "bus_name \"%s\"", bus_entry->bus_name);
    ++lines;

    lines += bus_entry->format(buf + lines, length, offset + 8, quadlet[2]);

    company_id = (quadlet[3] & 0xffffff00) >> 8;
    device_id = ((((uint64_t)quadlet[3]) & 0x000000ff) << 32) | quadlet[4];
    eui64 = (((uint64_t)quadlet[3]) << 32) | quadlet[4];

    consumed = format_line_prefix(buf[lines], length, offset + 12, quadlet[3], true);
    snprintf(buf[lines] + consumed, length - consumed, "company_id %06x     | ", company_id);
    ++lines;

    consumed = format_line_prefix(buf[lines], length, offset + 16, quadlet[4], true);
    snprintf(buf[lines] + consumed, length - consumed, "device_id %010lx  | EUI-64 %016lx",
             device_id, eui64);
    ++lines;

    if (quadlet_count > 5) {
        for (i = 5; i < quadlet_count; ++i) {
            format_line_prefix(buf[lines], length, offset + 4 * 5, quadlet[i], false);
            ++lines;
        }
    }

    return lines;
}

static size_t format_block_metadata(char *buf, size_t length, const char *block_name,
                                    const uint32_t *quadlet, size_t quadlet_count)
{
    uint16_t block_length = (quadlet[0] & IEEE1212_BLOCK_LENGTH_MASK) >>
                            IEEE1212_BLOCK_LENGTH_SHIFT;
    uint16_t block_crc = (quadlet[0] & IEEE1212_BLOCK_CRC_MASK) >> IEEE1212_BLOCK_CRC_SHIFT;
    uint16_t actual_block_crc = compute_itu_t_crc_16(quadlet + 1, quadlet_count - 1);
    size_t consumed;

    consumed = snprintf(buf, length, "%s_length %d", block_name, block_length);
    if (1 + block_length != quadlet_count)
        consumed +=
            snprintf(buf + consumed, length - consumed, " (actual length %ld)", quadlet_count - 1);

    consumed += snprintf(buf + consumed, length - consumed, ", crc %d", block_crc);
    if (block_crc != actual_block_crc)
        consumed +=
            snprintf(buf + consumed, length - consumed, " (should be %d)", actual_block_crc);

    return consumed;
}

static size_t format_leaf_block(char **buf, size_t length, const struct ieee1212_block *leaf,
                                size_t data_length)
{
    struct spec_identifier identifier = {
        INVALID_KEY_VALUE,
        INVALID_KEY_VALUE,
    };
    const struct ieee1212_block *base = leaf->data.leaf.parent;
    const struct key_formatter *formatter;
    const char *spec_name = NULL;
    size_t offset;
    const uint32_t *quadlet;
    size_t quadlet_count;
    size_t consumed;
    size_t lines;
    int i;

    while (base != NULL) {
        quadlet = (const uint32_t *)base->content;
        quadlet_count = base->length / 4;

        for (i = 1; i < quadlet_count; ++i) {
            uint8_t key_type;
            uint8_t key_id;
            uint32_t value;

            decode_directory_entry(quadlet[i], &key_type, &key_id, &value);

            if (key_type == KEY_TYPE_IMMEDIATE) {
                switch (key_id) {
                case KEY_ID_CSR_SPECIFIER_ID:
                    if (identifier.specifier_id == INVALID_KEY_VALUE)
                        identifier.specifier_id = value;
                    break;
                case KEY_ID_CSR_VERSION:
                    if (identifier.version == INVALID_KEY_VALUE)
                        identifier.version = value;
                    break;
                case KEY_ID_CSR_VENDOR_INFO:
                    if (identifier.specifier_id == INVALID_KEY_VALUE)
                        identifier.specifier_id = value;
                default:
                    break;
                }
            }
        }

        if (base->block_type == IEEE1212_DIRECTORY_BLOCK)
            base = base->data.directory.parent;
        else
            base = NULL;
    }

    detect_key_formatter(&formatter, &spec_name, &identifier, KEY_TYPE_LEAF,
                         leaf->data.leaf.key_id);

    offset = leaf->offset;
    quadlet = (const uint32_t *)leaf->content;
    quadlet_count = leaf->length / 4;

    lines = 0;

    consumed = format_blank_prefix(buf[lines], length);
    if (spec_name != NULL)
        consumed += snprintf(buf[lines] + consumed, length - consumed, "%s ", spec_name);
    snprintf(buf[lines] + consumed, length - consumed, "%s leaf at %lx", formatter->key_id_name,
             IEEE1212_CONFIG_ROM_OFFSET + offset);
    ++lines;

    consumed = format_blank_prefix(buf[lines], length);
    format_horizontal_line(buf[lines] + consumed, length - consumed);
    ++lines;

    consumed = format_line_prefix(buf[lines], length, offset, quadlet[0], true);
    format_block_metadata(buf[lines] + consumed, length - consumed, "leaf", quadlet, quadlet_count);
    ++lines;

    offset += 4;
    ++quadlet;
    --quadlet_count;

    lines +=
        formatter->format_content.leaf(buf + lines, length, offset, quadlet, quadlet_count, NULL);

    return lines;
}

static size_t format_entry_spec_name(char *buf, size_t length, const char *spec_name)
{
    if (spec_name != NULL)
        return snprintf(buf, length, "%s ", spec_name);

    return 0;
}

static size_t format_immediate_entry(char *buf, size_t length, size_t offset, uint32_t value,
                                     const char *spec_name, const struct key_formatter *formatter)
{
    size_t consumed;

    consumed = format_entry_spec_name(buf, length, spec_name);

    if (formatter->key_id != INVALID_KEY_ID)
        consumed += snprintf(buf + consumed, length - consumed, "%s", formatter->key_id_name);

    if (formatter->format_content.immediate != NULL) {
        if (formatter->key_id != INVALID_KEY_ID)
            consumed += snprintf(buf + consumed, length - consumed, ": ");
        consumed += formatter->format_content.immediate(buf + consumed, length - consumed, value);
    }

    return consumed;
}

static size_t format_csr_offset_entry(char *buf, size_t length, size_t offset, uint32_t value,
                                      const char *spec_name, const struct key_formatter *formatter)
{
    size_t csr_offset = IEEE1212_REGISTER_SPACE_ADDRESS + 4 * value;
    size_t consumed;

    consumed = snprintf(buf, length, "--> ");
    consumed += format_entry_spec_name(buf + consumed, length - consumed, spec_name);

    if (formatter->key_id != INVALID_KEY_ID)
        consumed += snprintf(buf + consumed, length - consumed, "%s ", formatter->key_id_name);
    else
        consumed += snprintf(buf + consumed, length - consumed, "CSR ");

    consumed += snprintf(buf + consumed, length - consumed, "at %012lx", csr_offset);

    return consumed;
}

static size_t format_leaf_entry(char *buf, size_t length, size_t offset, uint32_t value,
                                const char *spec_name, const struct key_formatter *formatter)
{
    size_t leaf_offset = IEEE1212_CONFIG_ROM_OFFSET + offset + 4 * value;
    size_t consumed;

    consumed = snprintf(buf, length, "--> ");
    consumed += format_entry_spec_name(buf + consumed, length - consumed, spec_name);

    if (formatter->key_id != INVALID_KEY_ID)
        consumed += snprintf(buf + consumed, length - consumed, "%s ", formatter->key_id_name);

    consumed += snprintf(buf + consumed, length - consumed, "leaf at %lx", leaf_offset);

    return consumed;
}

static size_t format_directory_entry(char *buf, size_t length, size_t offset, uint32_t value,
                                     const char *spec_name, const struct key_formatter *formatter)
{
    size_t directory_offset = IEEE1212_CONFIG_ROM_OFFSET + offset + 4 * value;
    size_t consumed;

    consumed = snprintf(buf, length, "--> ");
    consumed += format_entry_spec_name(buf + consumed, length - consumed, spec_name);

    if (formatter->key_id != INVALID_KEY_ID)
        consumed += snprintf(buf + consumed, length - consumed, "%s ", formatter->key_id_name);

    consumed += snprintf(buf + consumed, length - consumed, "directory at %lx", directory_offset);

    return consumed;
}

static size_t format_directory_entries(char **buf, size_t length, size_t directory_offset,
                                       const uint32_t *quadlet, size_t quadlet_count,
                                       const struct spec_identifier *identifier)
{
    static size_t (*const format_entry[])(char *buf, size_t length, size_t offset, uint32_t value,
                                          const char *spec_name,
                                          const struct key_formatter *formatter) = {
        [KEY_TYPE_IMMEDIATE] = format_immediate_entry,
        [KEY_TYPE_CSR_OFFSET] = format_csr_offset_entry,
        [KEY_TYPE_LEAF] = format_leaf_entry,
        [KEY_TYPE_DIRECTORY] = format_directory_entry,
    };
    size_t consumed;
    int i;

    consumed = format_line_prefix(buf[0], length, directory_offset, quadlet[0], true);
    format_block_metadata(buf[0] + consumed, length - consumed, "directory", quadlet,
                          quadlet_count);

    for (i = 1; i < quadlet_count; ++i) {
        const struct key_formatter *formatter;
        size_t offset = directory_offset + i * 4;
        uint8_t key_type;
        uint8_t key_id;
        uint32_t value;
        size_t consumed;
        const char *spec_name = NULL;

        decode_directory_entry(quadlet[i], &key_type, &key_id, &value);

        detect_key_formatter(&formatter, &spec_name, identifier, key_type, key_id);

        consumed = format_line_prefix(buf[i], length, offset, quadlet[i], true);
        format_entry[key_type](buf[i] + consumed, length - consumed, offset, value, spec_name,
                               formatter);
    }

    return quadlet_count;
}

static size_t format_directory_block(char **buf, size_t length,
                                     const struct ieee1212_block *directory, size_t data_length)
{
    struct spec_identifier identifier = {
        INVALID_KEY_VALUE,
        INVALID_KEY_VALUE,
    };
    const struct ieee1212_block *base;
    size_t offset;
    const uint32_t *quadlet;
    size_t quadlet_count;
    const struct key_formatter *formatter;
    const char *spec_name = NULL;
    size_t lines;
    size_t consumed;
    int i;

    switch (directory->data.directory.key_id) {
    case KEY_ID_CSR_VENDOR_INFO:
    case KEY_ID_CSR_MODULE_INFO:
    case KEY_ID_CSR_DESCRIPTOR:
    case KEY_ID_CSR_BUS_DEP_INFO:
    case KEY_ID_CSR_DEP_INFO:
    case KEY_ID_CSR_INSTANCE:
        base = directory->data.directory.parent;
        break;
    case KEY_ID_CSR_UNIT:
    case KEY_ID_CSR_FEATURE:
        base = directory;
        break;
    default:
        break;
    }

    while (base != NULL) {
        quadlet = (const uint32_t *)base->content;
        quadlet_count = base->length / 4;

        for (i = 1; i < quadlet_count; ++i) {
            uint8_t key_type;
            uint8_t key_id;
            uint32_t value;

            decode_directory_entry(quadlet[i], &key_type, &key_id, &value);

            if (key_type == KEY_TYPE_IMMEDIATE) {
                switch (key_id) {
                case KEY_ID_CSR_SPECIFIER_ID:
                    if (identifier.specifier_id == INVALID_KEY_VALUE)
                        identifier.specifier_id = value;
                    break;
                case KEY_ID_CSR_VERSION:
                    if (identifier.version == INVALID_KEY_VALUE)
                        identifier.version = value;
                    break;
                case KEY_ID_CSR_VENDOR_INFO:
                    if (identifier.specifier_id == INVALID_KEY_VALUE)
                        identifier.specifier_id = value;
                default:
                    break;
                }
            }
        }

        if (base->block_type == IEEE1212_DIRECTORY_BLOCK)
            base = base->data.directory.parent;
        else
            base = NULL;
    }

    offset = directory->offset;
    quadlet = (const uint32_t *)directory->content;
    quadlet_count = directory->length / 4;

    detect_key_formatter(&formatter, &spec_name, &identifier, KEY_TYPE_DIRECTORY,
                         directory->data.directory.key_id);

    lines = 0;

    consumed = format_blank_prefix(buf[lines], length);
    snprintf(buf[lines] + consumed, length - consumed, "%s directory at %lx",
             formatter->key_id_name, IEEE1212_CONFIG_ROM_OFFSET + offset);
    ++lines;

    consumed = format_blank_prefix(buf[lines], length);
    format_horizontal_line(buf[lines] + consumed, length - consumed);
    ++lines;

    lines += formatter->format_content.directory(buf + lines, length, offset, quadlet,
                                                 quadlet_count, &identifier);

    return lines;
}

static size_t format_root_directory_block(char **buf, size_t length,
                                          const struct ieee1212_block *root, size_t data_length)
{
    struct spec_identifier identifier = {
        INVALID_KEY_VALUE,
        INVALID_KEY_VALUE,
    };
    size_t offset = root->offset;
    const uint32_t *quadlet = (const uint32_t *)root->content;
    size_t quadlet_count = root->length / 4;
    size_t lines;
    size_t consumed;
    int i;

    for (i = 1; i < quadlet_count; ++i) {
        uint8_t key_type;
        uint8_t key_id;
        uint32_t value;

        decode_directory_entry(quadlet[i], &key_type, &key_id, &value);

        if (key_type == KEY_TYPE_IMMEDIATE && key_id == KEY_ID_CSR_VENDOR_INFO)
            identifier.specifier_id = value;
    }

    lines = 0;

    consumed = format_blank_prefix(buf[lines], length);
    snprintf(buf[lines] + consumed, length - consumed, "root directory");
    ++lines;

    consumed = format_blank_prefix(buf[lines], length);
    format_horizontal_line(buf[lines] + consumed, length - consumed);
    ++lines;

    lines +=
        format_directory_entries(buf + lines, length, offset, quadlet, quadlet_count, &identifier);

    return lines;
}

static size_t format_orphan_block(char **buf, size_t length, const struct ieee1212_block *orphan,
                                  size_t data_length)
{
    const uint32_t *quadlet = (const uint32_t *)orphan->content;
    size_t quadlet_count = orphan->length / 4;
    int i;

    for (i = 0; i < quadlet_count; ++i) {
        size_t offset = orphan->offset + i * 4;
        size_t consumed = format_line_prefix(buf[i], length, offset, quadlet[i], true);
        snprintf(buf[i] + consumed, length - consumed, "(unreferenced data)");
    }

    return i;
}

static int print_blocks(const uint8_t *data, ssize_t data_length, struct list_head *head)
{
    static size_t (*const format[])(char **buf, size_t length, const struct ieee1212_block *entry,
                                    size_t data_length) = {
        format_bus_info_block,  format_root_directory_block, format_leaf_block,
        format_directory_block, format_orphan_block,
    };
    struct ieee1212_block *block;
    size_t lines;
    char **buf;
    size_t offset;
    int i;

    lines = 0;
    LIST_FOREACH(block, head, list)
    {
        size_t count = block->length / 4;
        if (lines < count)
            lines = count;
    }
    // Add extra 10 lines for safe.
    lines += 10;

    buf = calloc(sizeof(*buf), lines);
    if (buf == NULL)
        return -ENOMEM;
    for (i = 0; i < lines; ++i) {
        buf[i] = malloc(LINE_WIDTH);
        if (buf[i] == NULL)
            goto end;
    }

    offset = 0;
    LIST_FOREACH(block, head, list)
    {
        size_t count = format[block->block_type](buf, LINE_WIDTH, block, data_length);
        for (i = 0; i < count; ++i)
            printf("%s\n", buf[i]);
        printf("\n");

        offset += block->length;
    }

end:
    for (i = 0; i < lines; ++i) {
        if (buf[i] != NULL)
            free(buf[i]);
    }
    free(buf);

    return 0;
}

//////////////
// Protocols.
//////////////

#define OUI_ICANN_IANA        0x00005e
#define SPEC_VERSION_RFC_2734 0x000001
#define SPEC_VERSION_RFC_3146 0x000002
#define SPEC_NAME_RFC_2734    "IPv4 over 1394 (RFC 2734)"
#define SPEC_NAME_RFC_3146    "IPv6 over 1394 (RFC 3146)"

static const struct spec_identifier spec_iana_ipv4 = {
    OUI_ICANN_IANA,
    SPEC_VERSION_RFC_2734,
};

static const struct spec_identifier spec_iana_ipv6 = {
    OUI_ICANN_IANA,
    SPEC_VERSION_RFC_3146,
};

#define OUI_INCITS           0x00609e
#define SPEC_VERSION_SBP     0x010483
#define SPEC_VERSION_SBP_AVC 0x0105bb
#define SPEC_NAME_SBP        "SBP-2"
#define SPEC_NAME_SBP_AVC    "AV/C over SBP-3"

static const struct spec_identifier spec_incits_sbp = {
    OUI_INCITS,
    SPEC_VERSION_SBP,
};

static const struct spec_identifier spec_incits_sbp_avc = {
    OUI_INCITS,
    SPEC_VERSION_SBP_AVC,
};

#define OUI_1394TA                     0x00a02d
#define SPEC_VERSION_AVC               0x010001
#define SPEC_VERSION_CAL               0x010002
#define SPEC_VERSION_EHS               0x010004
#define SPEC_VERSION_HAVI              0x010008
#define SPEC_VERSION_VENDOR_UNIQUE     0x014000
#define SPEC_VERSION_VENDOR_UNIQUE_AVC 0x014001
#define SPEC_VERSION_IIDC_104          0x000100
#define SPEC_VERSION_IIDC_120          0x000101
#define SPEC_VERSION_IIDC_130          0x000102
#define SPEC_VERSION_IIDC2             0x000110
#define SPEC_VERSION_DPP_111           0x0a6be2
#define SPEC_VERSION_IICP              0x4b661f
#define SPEC_NAME_AVC                  "AV/C"
#define SPEC_NAME_CAL                  "CAL"
#define SPEC_NAME_EHS                  "EHS"
#define SPEC_NAME_HAVI                 "HAVi"
#define SPEC_NAME_VENDOR_UNIQUE        "Vendor Unique"
#define SPEC_NAME_VENDOR_UNIQUE_AVC    "Vendor Unique and AV/C"
#define SPEC_NAME_IIDC_104             "IIDC 1.04"
#define SPEC_NAME_IIDC_120             "IIDC 1.20"
#define SPEC_NAME_IIDC_130             "IIDC 1.30"
#define SPEC_NAME_IIDC2                "IIDC2"
#define SPEC_NAME_DPP_111              "DPP 1.0"
#define SPEC_NAME_IICP                 "IICP 1.0"

static const struct spec_identifier spec_1394ta_avc = {
    OUI_1394TA,
    SPEC_VERSION_AVC,
};

static const struct spec_identifier spec_1394ta_cal = {
    OUI_1394TA,
    SPEC_VERSION_CAL,
};

static const struct spec_identifier spec_1394ta_ehs = {
    OUI_1394TA,
    SPEC_VERSION_EHS,
};

static const struct spec_identifier spec_1394ta_havi = {
    OUI_1394TA,
    SPEC_VERSION_HAVI,
};

static const struct spec_identifier spec_1394ta_vendor_unique = {
    OUI_1394TA,
    SPEC_VERSION_VENDOR_UNIQUE,
};

static const struct spec_identifier spec_1394ta_vendor_unique_avc = {
    OUI_1394TA,
    SPEC_VERSION_VENDOR_UNIQUE_AVC,
};

static const struct spec_identifier spec_1394ta_iidc_104 = {
    OUI_1394TA,
    SPEC_VERSION_IIDC_104,
};

static const struct spec_identifier spec_1394ta_iidc_120 = {
    OUI_1394TA,
    SPEC_VERSION_IIDC_120,
};

static const struct spec_identifier spec_1394ta_iidc_130 = {
    OUI_1394TA,
    SPEC_VERSION_IIDC_130,
};

static const struct spec_identifier spec_1394ta_iidc2 = {
    OUI_1394TA,
    SPEC_VERSION_IIDC2,
};

static const struct spec_identifier spec_1394ta_dpp_111 = {
    OUI_1394TA,
    SPEC_VERSION_DPP_111,
};

static const struct spec_identifier spec_1394ta_iicp = {
    OUI_1394TA,
    SPEC_VERSION_IICP,
};

#define OUI_ALESIS                0x000595
#define SPEC_VERSION_ALESIS_AUDIO 0x000001
#define SPEC_NAME_ALESIS_AUDIO    "audio"

static const struct spec_identifier spec_alesis_audio = {
    OUI_ALESIS,
    SPEC_VERSION_ALESIS_AUDIO,
};

#define OUI_APPLE                   0x000a27
#define SPEC_VERSION_ISIGHT_AUDIO   0x000010
#define SPEC_VERSION_ISIGHT_FACTORY 0x000011
#define SPEC_VERSION_ISIGHT_IRIS    0x000012
#define SPEC_NAME_ISIGHT_AUDIO      "iSight audio unit"
#define SPEC_NAME_ISIGHT_FACTORY    "iSight factory unit"
#define SPEC_NAME_ISIGHT_IRIS       "iSight iris unit"

static const struct spec_identifier spec_apple_isight_audio = {
    OUI_APPLE,
    SPEC_VERSION_ISIGHT_AUDIO,
};

static const struct spec_identifier spec_apple_isight_factory = {
    OUI_APPLE,
    SPEC_VERSION_ISIGHT_FACTORY,
};

static const struct spec_identifier spec_apple_isight_iris = {
    OUI_APPLE,
    SPEC_VERSION_ISIGHT_IRIS,
};

#define OUI_LACIE              0x00d04b
#define SPEC_VERSION_LACIE_HID 0x484944
#define SPEC_NAME_LACIE_HID    "HID"

static const struct spec_identifier spec_lacie_hid = {
    OUI_LACIE,
    SPEC_VERSION_LACIE_HID,
};

///////////////////////////////////////////////
// Directory entries specific to CSR directory.
///////////////////////////////////////////////

#define CSR_DESCRIPTOR_NAME       "descriptor"
#define CSR_BUS_DEP_INFO_NAME     "bus dependent info"
#define CSR_VENDOR_INFO_NAME      "vendor"
#define CSR_HARDWARE_VERSION_NAME "hardware version"
#define CSR_MODULE_INFO_NAME      "module"
#define CSR_NODE_CAPS_NAME        "node capabilities"
#define CSR_EUI_64_NAME           "eui-64"
#define CSR_UNIT_NAME             "unit"
#define CSR_SPECIFIER_ID_NAME     "specifier id"
#define CSR_VERSION_NAME          "version"
#define CSR_DEP_INFO_NAME         "dependent info"
#define CSR_UNIT_LOCATION_NAME    "unit location"
#define CSR_MODEL_NAME            "model"
#define CSR_INSTANCE_NAME         "instance"
#define CSR_KEYWORD_NAME          "keyword"
#define CSR_FEATURE_NAME          "feature"
#define CSR_MODIFIABLE_DESC_NAME  "modifiable descriptor"
#define CSR_DIRECTORY_ID_NAME     "directory id"

static size_t format_csr_textual_descriptor_leaf_content(char **buf, size_t length, size_t offset,
                                                         const uint32_t *quadlet,
                                                         size_t quadlet_count,
                                                         const char *spec_name)
{
    uint8_t width;
    uint16_t character_set;
    uint16_t language;
    size_t consumed;
    int i, j;

    if (quadlet_count < 2)
        return 0;

    width = quadlet[0] >> 28;
    character_set = (quadlet[0] & 0x0fff0000) >> 16;
    language = (quadlet[0] & 0x0000ffff) >> 0;

    consumed = format_line_prefix(buf[0], length, offset, quadlet[0], true);
    if (character_set == 0) {
        snprintf(buf[0] + consumed, length - consumed, "minimal ASCII");
    } else {
        snprintf(buf[0] + consumed, length - consumed, "width %d, character_set %d, language %d",
                 width, character_set, language);
    }

    for (i = 1; i < quadlet_count; ++i) {
        consumed = format_line_prefix(buf[i], length, offset + i * 4, quadlet[i], true);

        if (quadlet[i] > 0) {
            consumed += snprintf(buf[i] + consumed, length - consumed, "\"");

            for (j = 0; j < 4; ++j) {
                size_t shift = 24 - j * 8;
                uint8_t letter = (quadlet[i] >> shift) & 0xff;
                if (letter != '\0')
                    consumed += snprintf(buf[i] + consumed, length - consumed, "%c", letter);
            }

            snprintf(buf[i] + consumed, length - consumed, "\"");
        }
    }

    return i;
}

static size_t format_csr_icon_descriptor_leaf_content(char **buf, size_t length, size_t offset,
                                                      const uint32_t *quadlet, size_t quadlet_count,
                                                      const char *spec_name)
{
    int i;

    for (i = 0; i < quadlet_count; ++i)
        format_line_prefix(buf[i], length, offset + i * 4, quadlet[i], false);

    return i;
}

static size_t format_csr_unspecified_descriptor_leaf_content(char **buf, size_t length,
                                                             size_t offset, const uint32_t *quadlet,
                                                             size_t quadlet_count,
                                                             const char *spec_name)
{
    int i;

    for (i = 0; i < quadlet_count; ++i)
        format_line_prefix(buf[i], length, offset + i * 4, quadlet[i], false);

    return i;
}

#define CSR_DESC_TYPE_MASK    0xff000000
#define CSR_DESC_TYPE_SHIFT   24
#define CSR_SPEC_MASK         0x00ffffff
#define CSR_SPEC_SHIFT        0

#define CSR_DESC_TYPE_TEXTUAL 0x00
#define CSR_DESC_TYPE_ICON    0x01

static size_t format_csr_descriptor_leaf_content(char **buf, size_t length, size_t offset,
                                                 const uint32_t *quadlet, size_t quadlet_count,
                                                 const char *spec_name)
{
    size_t (*format)(char **buf, size_t length, size_t offset, const uint32_t *quadlet,
                     size_t quadlet_count, const char *spec_name);
    uint8_t desc_type;
    uint32_t spec_id;
    char desc_type_name[64];
    size_t consumed;
    size_t lines;

    if (quadlet_count < 1)
        return 0;

    desc_type = (quadlet[0] & CSR_DESC_TYPE_MASK) >> CSR_DESC_TYPE_SHIFT;
    spec_id = (quadlet[0] & CSR_SPEC_MASK) & CSR_SPEC_SHIFT;

    switch (desc_type) {
    case CSR_DESC_TYPE_TEXTUAL:
        snprintf(desc_type_name, sizeof(desc_type_name), "textual descriptor");
        format = format_csr_textual_descriptor_leaf_content;
        break;
    case CSR_DESC_TYPE_ICON:
        snprintf(desc_type_name, sizeof(desc_type_name), "icon descriptor");
        format = format_csr_icon_descriptor_leaf_content;
        break;
    default:
        snprintf(desc_type_name, sizeof(desc_type_name), "descriptor_type %02x, specifier_ID %x",
                 desc_type, spec_id);
        format = format_csr_unspecified_descriptor_leaf_content;
        break;
    }

    lines = 0;

    consumed = format_line_prefix(buf[lines], length, offset, quadlet[0], true);
    snprintf(buf[lines] + consumed, length - consumed, "%s", desc_type_name);
    ++lines;

    offset += 4;
    ++quadlet;
    quadlet_count -= 1;

    lines += format(buf + lines, length, offset, quadlet, quadlet_count, spec_name);

    return lines;
}

static size_t format_csr_keyword_leaf_content(char **buf, size_t length, size_t offset,
                                              const uint32_t *quadlet, size_t quadlet_count,
                                              const char *spec_name)
{
    int i;

    for (i = 0; i < quadlet_count; ++i) {
        size_t consumed;
        int j;

        consumed = format_line_prefix(buf[i], length, offset + 4 * i, quadlet[i], true);
        if (quadlet[i] > 0) {
            consumed += snprintf(buf[i] + consumed, length - consumed, "\"");

            for (j = 0; j < 4; ++j) {
                size_t shift = 24 - j * 8;
                uint8_t letter = (quadlet[i] >> shift) & 0xff;

                if (letter != '\0')
                    consumed += snprintf(buf[i] + consumed, length - consumed, "%c", letter);
                else if (i < quadlet_count - 1)
                    consumed += snprintf(buf[i] + consumed, length - consumed, "\" \"");
                else
                    break;
            }

            snprintf(buf[i] + consumed, length - consumed, "\"");
        }
    }

    return i;
}

static size_t format_csr_unit_location_leaf_content(char **buf, size_t length, size_t offset,
                                                    const uint32_t *quadlet, size_t quadlet_count,
                                                    const char *spec_name)
{
    uint64_t base_address;
    uint64_t upper_bound;
    size_t consumed;

    if (quadlet_count < 4)
        return 0;

    base_address = (((uint64_t)quadlet[0]) << 32) | quadlet[1];
    upper_bound = (((uint64_t)quadlet[2]) << 32) | quadlet[3];

    consumed = format_line_prefix(buf[0], length, offset, quadlet[0], true);
    snprintf(buf[0] + consumed, length - consumed, "base_address %016lx", base_address);

    format_line_prefix(buf[1], length, offset + 4, quadlet[1], false);

    consumed = format_line_prefix(buf[2], length, offset + 8, quadlet[2], true);
    snprintf(buf[2] + consumed, length - consumed, "upper_bound %016lx", upper_bound);

    format_line_prefix(buf[3], length, offset + 12, quadlet[3], false);

    return 4;
}

static size_t format_csr_eui64_leaf_content(char **buf, size_t length, size_t offset,
                                            const uint32_t *quadlet, size_t quadlet_count,
                                            const char *spec_name)
{
    uint32_t company_id;
    uint64_t device_id;
    uint64_t eui64;
    size_t consumed;

    if (quadlet_count < 2)
        return 0;

    company_id = (quadlet[0] & 0xffffff00) >> 8;
    device_id = ((((uint64_t)quadlet[0]) & 0x000000ff) << 32) | quadlet[1];
    eui64 = (((uint64_t)quadlet[0]) << 32) | quadlet[1];

    consumed = format_line_prefix(buf[0], length, offset, quadlet[0], true);
    snprintf(buf[0] + consumed, length - consumed, "company_id %06x     | ", company_id);

    consumed = format_line_prefix(buf[1], length, offset + 4, quadlet[1], true);
    snprintf(buf[1] + consumed, length - consumed, "device_id %010lx  | EUI-64 %016lx", device_id,
             eui64);

    return 2;
}

static size_t format_unspecified_leaf_content(char **buf, size_t length, size_t offset,
                                              const uint32_t *quadlet, size_t quadlet_count,
                                              const char *spec_name)
{
    int i;

    for (i = 0; i < quadlet_count; ++i)
        format_line_prefix(buf[i], length, offset + i * 4, quadlet[i], false);

    return i;
}

static const struct key_formatter csr_key_formatters[] = {
    {
        KEY_TYPE_LEAF,
        KEY_ID_CSR_DESCRIPTOR,
        CSR_DESCRIPTOR_NAME,
        .format_content.leaf = format_csr_descriptor_leaf_content,
    },
    {
        KEY_TYPE_DIRECTORY,
        KEY_ID_CSR_DESCRIPTOR,
        CSR_DESCRIPTOR_NAME,
        .format_content.directory = format_directory_entries,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_CSR_BUS_DEP_INFO,
        CSR_BUS_DEP_INFO_NAME,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_CSR_BUS_DEP_INFO,
        CSR_BUS_DEP_INFO_NAME,
        .format_content.leaf = format_unspecified_leaf_content,
    },
    {
        KEY_TYPE_DIRECTORY,
        KEY_ID_CSR_BUS_DEP_INFO,
        CSR_BUS_DEP_INFO_NAME,
        .format_content.directory = format_directory_entries,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_CSR_VENDOR_INFO,
        CSR_VENDOR_INFO_NAME,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_CSR_VENDOR_INFO,
        CSR_VENDOR_INFO_NAME,
        .format_content.leaf = format_unspecified_leaf_content,
    },
    {
        KEY_TYPE_DIRECTORY,
        KEY_ID_CSR_VENDOR_INFO,
        CSR_VENDOR_INFO_NAME,
        .format_content.directory = format_directory_entries,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_CSR_HARDWARE_VERSION,
        CSR_HARDWARE_VERSION_NAME,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_CSR_MODULE_INFO,
        CSR_MODULE_INFO_NAME,
        .format_content.leaf = format_csr_eui64_leaf_content,
    },
    {
        KEY_TYPE_DIRECTORY,
        KEY_ID_CSR_MODULE_INFO,
        CSR_MODULE_INFO_NAME,
        .format_content.directory = format_directory_entries,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_CSR_EUI_64,
        CSR_EUI_64_NAME,
        .format_content.leaf = format_csr_eui64_leaf_content,
    },
    {
        KEY_TYPE_DIRECTORY,
        KEY_ID_CSR_UNIT,
        CSR_UNIT_NAME,
        .format_content.directory = format_directory_entries,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_CSR_SPECIFIER_ID,
        CSR_SPECIFIER_ID_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_CSR_VERSION,
        CSR_VERSION_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_CSR_DEP_INFO,
        CSR_DEP_INFO_NAME,
    },
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_CSR_DEP_INFO,
        CSR_DEP_INFO_NAME,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_CSR_DEP_INFO,
        CSR_DEP_INFO_NAME,
        .format_content.leaf = format_unspecified_leaf_content,
    },
    {
        KEY_TYPE_DIRECTORY,
        KEY_ID_CSR_DEP_INFO,
        CSR_DEP_INFO_NAME,
        .format_content.directory = format_directory_entries,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_CSR_UNIT_LOCATION,
        CSR_UNIT_LOCATION_NAME,
        .format_content.leaf = format_csr_unit_location_leaf_content,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_CSR_MODEL,
        CSR_MODEL_NAME,
    },
    {
        KEY_TYPE_DIRECTORY,
        KEY_ID_CSR_INSTANCE,
        CSR_INSTANCE_NAME,
        .format_content.directory = format_directory_entries,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_CSR_KEYWORD,
        CSR_KEYWORD_NAME,
        .format_content.leaf = format_csr_keyword_leaf_content,
    },
    {
        KEY_TYPE_DIRECTORY,
        KEY_ID_CSR_FEATURE,
        CSR_FEATURE_NAME,
        .format_content.directory = format_directory_entries,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_CSR_DIRECTORY_ID,
        CSR_DIRECTORY_ID_NAME,
    },
};

////////////////////////////////////////////////
// Directory entries specific to IEEE 1394 bus.
////////////////////////////////////////////////

static size_t format_ieee1394_bus_node_capabilities_immediate_value(char *buf, size_t length,
                                                                    uint32_t value)
{
    return snprintf(buf, length, "per IEEE 1394");
}

static const struct key_formatter ieee1394_bus_key_formatters[] = {
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_CSR_NODE_CAPS,
        CSR_NODE_CAPS_NAME,
        .format_content.immediate = format_ieee1394_bus_node_capabilities_immediate_value,
    },
};

//////////////////////////////////////
// Directory entries specific to SBP.
//////////////////////////////////////

#define KEY_ID_SBP2_UNIT_UNIQUE_ID        0x0d // For leaf.
#define KEY_ID_SBP2_LOGICAL_UNIT_NUMBER   0x14 // For immediate.
#define KEY_ID_SBP2_MANAGEMENT_AGENT      0x14 // For CSR offset.
#define KEY_ID_SBP2_LOGICAL_UNIT          0x14 // For directory.
#define KEY_ID_SBP3_REVISION              0x21 // For immediate.
#define KEY_ID_SBP3_PLUG_CONTROL_REGISTER 0x32 // For immediate.
#define KEY_ID_SBP2_COMMAND_SET_SPEC_ID   0x38 // For immediate.
#define KEY_ID_SBP2_COMMAND_SET           0x39 // For immediate.
#define KEY_ID_SBP2_UNIT_CHARACTERISTIC   0x3a // For immediate.
#define KEY_ID_SBP2_COMMAND_SET_REVISION  0x3b // For immediate.
#define KEY_ID_SBP2_FIRMWARE_REVISION     0x3c // For immediate.
#define KEY_ID_SBP2_RECONNECT_TIMEOUT     0x3d // For immediate.
#define KEY_ID_SBP3_FAST_START            0x3e // For immediate.

#define SBP2_UNIT_UNIQUE_ID_NAME          "unit unique id"
#define SBP2_LOGICAL_UNIT_NUMBER_NAME     "logical unit number"
#define SBP2_MANAGEMENT_AGENT_NAME        "management agent CSR"
#define SBP2_LOGICAL_UNIT_NAME            "logical unit"
#define SBP3_REVISION_NAME                "revision"
#define SBP3_PLUG_CONTROL_REGISTER_NAME   "plug control register"
#define SBP2_COMMAND_SET_SPEC_ID_NAME     "command set spec id"
#define SBP2_COMMAND_SET_NAME             "command set"
#define SBP2_UNIT_CHARACTERISTIC_NAME     "unit char."
#define SBP2_COMMAND_SET_REVISION_NAME    "command set revision"
#define SBP2_FIRMWARE_REVISION_NAME       "firmware revision"
#define SBP2_RECONNECT_TIMEOUT_NAME       "reconnect timeout"
#define SBP3_FAST_START_NAME              "fast start"

static size_t format_sbp_logical_unit_number_immediate_value(char *buf, size_t length,
                                                             uint32_t value)
{
    static const char *const device_types[] = {
        [0x00] = "Disk",    [0x01] = "Tape",      [0x02] = "Printer",  [0x03] = "Processor",
        [0x04] = "WORM",    [0x05] = "CD/DVD",    [0x06] = "Scanner",  [0x07] = "MOD",
        [0x08] = "Changer", [0x09] = "Comm",      [0x0a] = "Prepress", [0x0b] = "Prepress",
        [0x0c] = "RAID",    [0x0d] = "Enclosure", [0x0e] = "RBC",      [0x0f] = "OCRW",
        [0x10] = "Bridge",  [0x11] = "OSD",       [0x12] = "ADC-2",
    };
    bool extended = (value & 0x800000) >> 23;
    unsigned int ordered = (value & 0x400000) >> 22;
    bool isoc = (value & 0x200000) >> 21;
    unsigned int device_type = (value & 0x1f) >> 16;
    unsigned int logical_unit = value & 0x00ffff;
    size_t consumed = 0;

    if (extended)
        consumed += snprintf(buf + consumed, length - consumed, " extended_status 1,");

    consumed += snprintf(buf + consumed, length - consumed, " ordered %d,", ordered);

    if (isoc)
        consumed += snprintf(buf + consumed, length - consumed, " isoch 1,");

    if (device_type < CONST_ARRAY_SIZE(device_types)) {
        consumed +=
            snprintf(buf + consumed, length - consumed, "type %s,", device_types[device_type]);
    } else if (logical_unit == 0x1e) {
        consumed += snprintf(buf + consumed, length - consumed, "type w.k.LUN,");
    } else if (logical_unit == 0x1f) {
        consumed += snprintf(buf + consumed, length - consumed, "type unknown,");
    } else {
        consumed += snprintf(buf + consumed, length - consumed, "type %02x?,", device_type);
    }

    return consumed;
}

static size_t format_sbp3_revision_immediate_value(char *buf, size_t length, uint32_t value)
{
    size_t consumed = snprintf(buf, length, "%d", value);

    switch (value) {
    case 0:
        consumed += snprintf(buf + consumed, length - consumed, " = SBP-2");
        break;
    case 1:
        consumed += snprintf(buf + consumed, length - consumed, " = SBP-3");
        break;
    default:
        break;
    }

    return consumed;
}

static size_t format_sbp3_plug_control_register_immediate_value(char *buf, size_t length,
                                                                uint32_t value)
{
    bool is_output = (value & 0x20) >> 5;
    unsigned int plug_index = value & 0x1f;

    return snprintf(buf, length, "plug control register: %sPCR, plug_index %d",
                    is_output ? "o" : "i", plug_index);
}

static size_t format_sbp_command_set_immediate_value(char *buf, size_t length, uint32_t value)
{
    if (value == 0x0104d8)
        return snprintf(buf, length, "SCSI Primary Commands 2 and related standards");
    else if (value == 0x010001)
        return snprintf(buf, length, "AV/C");
    else
        return 0;
}

static size_t format_sbp_unit_characteristic_immediate_value(char *buf, size_t length,
                                                             uint32_t value)
{
    bool distributed_data = (value & 0x010000) >> 16; // Extended by SBP-3.
    float mgt_orb_timeout_sec = 0.5 * ((value & 0x00ff00) >> 8);
    unsigned int orb_size = value & 0x0000ff;
    size_t consumed = 0;

    if (distributed_data)
        consumed += snprintf(buf + consumed, length - consumed, "distrib. data 1, ");

    consumed += snprintf(buf + consumed, length - consumed,
                         "mgt_ORB_timeout %gs, ORB_size %d quadlets", mgt_orb_timeout_sec,
                         orb_size);

    return consumed;
}

static size_t format_sbp_firmware_revision_immediate_value(char *buf, size_t length, uint32_t value)
{
    return snprintf(buf, length, "%06x", value);
}

static size_t format_sbp_reconnect_timeout_immediate_value(char *buf, size_t length, uint32_t value)
{
    unsigned int max_reconnect_hold = 1 + (value & 0x00ffff);

    return snprintf(buf, length, "reconnect timeout: max_reconnect_hold %ds", max_reconnect_hold);
}

static size_t format_sbp3_fast_start_immediate_value(char *buf, size_t length, uint32_t value)
{
    unsigned int max_payload = (value & 0x00ff00) >> 8;
    unsigned int fast_start_offset = value & 0x0000ff;
    size_t consumed = 0;

    if (max_payload > 0) {
        unsigned int max_payload_bytes = max_payload << 2;

        consumed += snprintf(buf + consumed, length - consumed, " max_payload %d bytes,",
                             max_payload_bytes);
    } else {
        consumed += snprintf(buf + consumed, length - consumed, " max_payload per max_rec,");
    }

    consumed += snprintf(buf + consumed, length - consumed, " offset %d", fast_start_offset);

    return consumed;
}

static const struct key_formatter incits_sbp_key_formatters[] = {
    {
        KEY_TYPE_LEAF,
        KEY_ID_SBP2_UNIT_UNIQUE_ID,
        SBP2_UNIT_UNIQUE_ID_NAME,
        .format_content.leaf = format_csr_eui64_leaf_content,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_SBP2_LOGICAL_UNIT_NUMBER,
        SBP2_LOGICAL_UNIT_NUMBER_NAME,
        .format_content.immediate = format_sbp_logical_unit_number_immediate_value,
    },
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_SBP2_MANAGEMENT_AGENT,
        SBP2_MANAGEMENT_AGENT_NAME,
    },
    {
        KEY_TYPE_DIRECTORY,
        KEY_ID_SBP2_LOGICAL_UNIT,
        SBP2_LOGICAL_UNIT_NAME,
        .format_content.directory = format_directory_entries,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_SBP3_REVISION,
        SBP3_REVISION_NAME,
        .format_content.immediate = format_sbp3_revision_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_SBP3_PLUG_CONTROL_REGISTER,
        SBP3_PLUG_CONTROL_REGISTER_NAME,
        .format_content.immediate = format_sbp3_plug_control_register_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_SBP2_COMMAND_SET_SPEC_ID,
        SBP2_COMMAND_SET_SPEC_ID_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_SBP2_COMMAND_SET,
        SBP2_COMMAND_SET_NAME,
        .format_content.immediate = format_sbp_command_set_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_SBP2_UNIT_CHARACTERISTIC,
        SBP2_UNIT_CHARACTERISTIC_NAME,
        .format_content.immediate = format_sbp_unit_characteristic_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_SBP2_COMMAND_SET_REVISION,
        SBP2_COMMAND_SET_REVISION_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_SBP2_FIRMWARE_REVISION,
        SBP2_FIRMWARE_REVISION_NAME,
        .format_content.immediate = format_sbp_firmware_revision_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_SBP2_RECONNECT_TIMEOUT,
        SBP2_RECONNECT_TIMEOUT_NAME,
        .format_content.immediate = format_sbp_reconnect_timeout_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_SBP3_FAST_START,
        SBP3_FAST_START_NAME,
        .format_content.immediate = format_sbp3_fast_start_immediate_value,
    },
};

///////////////////////////////////////
// Directory entries specific to IIDC.
///////////////////////////////////////

#define KEY_ID_IIDC_CMD_REG_BASE             0x00 // For immediate.
#define KEY_ID_IIDC_VENDOR_NAME              0x01 // For leaf.
#define KEY_ID_IIDC_MODEL_NAME               0x02 // For leaf.

#define IIDC_CMD_REG_BASE_NAME               "command_regs_base"
#define IIDC_VENDOR_NAME                     "vendor name"
#define IIDC_MODEL_NAME                      "model name"

#define KEY_ID_IIDC_131_UNIT_SUB_SW_VERSION  0x38 // For immediate.
#define KEY_ID_IIDC_131_RESERVED_0           0x39 // For immediate.
#define KEY_ID_IIDC_131_RESERVED_1           0x3a // For immediate.
#define KEY_ID_IIDC_131_RESERVED_2           0x3b // For immediate.
#define KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_0 0x3c // For immediate.
#define KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_1 0x3d // For immediate.
#define KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_2 0x3e // For immediate.
#define KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_3 0x3f // For immediate.

#define IIDC_131_UNIT_SUB_SW_VERSION_NAME    "unit sub sw version"
#define IIDC_131_RESERVED_NAME               "(reserved)"
#define IIDC_131_VENDOR_UNIQUE_INFO_0_NAME   "vendor_unique_info_0"
#define IIDC_131_VENDOR_UNIQUE_INFO_1_NAME   "vendor_unique_info_1"
#define IIDC_131_VENDOR_UNIQUE_INFO_2_NAME   "vendor_unique_info_2"
#define IIDC_131_VENDOR_UNIQUE_INFO_3_NAME   "vendor_unique_info_3"

#define IIDC2_CMD_REG_BASE_NAME              "IIDC2Entry"

static size_t format_iidc_131_unit_sub_sw_version_immediate_value(char *buf, size_t length,
                                                                  uint32_t value)
{
    return snprintf(buf, length, "v1.3%d", value >> 4);
}

static size_t format_iidc2_100_unit_sub_sw_version_immediate_value(char *buf, size_t length,
                                                                   uint32_t value)
{
    unsigned int major = value >> 16;
    unsigned int minor = (value >> 8) & 0xff;
    unsigned int micro = value & 0xff;

    return snprintf(buf, length, "v%d.%d.%d", major, minor, micro);
}

static size_t format_iidc_104_leaf_content(char **buf, size_t length, size_t offset,
                                           const uint32_t *quadlet, size_t quadlet_count,
                                           const char *spec_name)
{
    int i;

    for (i = 0; i < 2; ++i)
        format_line_prefix(buf[i], length, offset + i * 4, quadlet[i], false);

    for (; i < quadlet_count; ++i) {
        size_t consumed;
        int j;

        consumed = format_line_prefix(buf[i], length, offset + i * 4, quadlet[i], true);
        if (quadlet[i] > 0) {
            consumed += snprintf(buf[i] + consumed, length - consumed, "\"");

            for (j = 0; j < 4; ++j) {
                size_t shift = 24 - j * 8;
                uint8_t letter = (quadlet[i] >> shift) & 0xff;
                if (letter != '\0')
                    consumed += snprintf(buf[i] + consumed, length - consumed, "%c", letter);
            }

            snprintf(buf[i] + consumed, length - consumed, "\"");
        }
    }

    return i;
}

static const struct key_formatter ta1394_iidc_104_key_formatters[] = {
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_IIDC_CMD_REG_BASE,
        IIDC_CMD_REG_BASE_NAME,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_IIDC_VENDOR_NAME,
        IIDC_VENDOR_NAME,
        .format_content.leaf = format_iidc_104_leaf_content,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_IIDC_MODEL_NAME,
        IIDC_MODEL_NAME,
        .format_content.leaf = format_iidc_104_leaf_content,
    },
};

static const struct key_formatter ta1394_iidc_131_key_formatters[] = {
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_IIDC_CMD_REG_BASE,
        IIDC_CMD_REG_BASE_NAME,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_IIDC_VENDOR_NAME,
        IIDC_VENDOR_NAME,
        .format_content.leaf = format_iidc_104_leaf_content,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_IIDC_MODEL_NAME,
        IIDC_MODEL_NAME,
        .format_content.leaf = format_iidc_104_leaf_content,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_UNIT_SUB_SW_VERSION,
        IIDC_131_UNIT_SUB_SW_VERSION_NAME,
        .format_content.immediate = format_iidc_131_unit_sub_sw_version_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_RESERVED_0,
        IIDC_131_RESERVED_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_RESERVED_1,
        IIDC_131_RESERVED_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_RESERVED_2,
        IIDC_131_RESERVED_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_0,
        IIDC_131_VENDOR_UNIQUE_INFO_0_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_1,
        IIDC_131_VENDOR_UNIQUE_INFO_1_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_2,
        IIDC_131_VENDOR_UNIQUE_INFO_2_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_3,
        IIDC_131_VENDOR_UNIQUE_INFO_3_NAME,
    },
};

static const struct key_formatter ta1394_iidc2_100_key_formatters[] = {
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_IIDC_CMD_REG_BASE,
        IIDC2_CMD_REG_BASE_NAME,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_IIDC_VENDOR_NAME,
        IIDC_VENDOR_NAME,
        .format_content.leaf = format_iidc_104_leaf_content,
    },
    {
        KEY_TYPE_LEAF,
        KEY_ID_IIDC_MODEL_NAME,
        IIDC_MODEL_NAME,
        .format_content.leaf = format_iidc_104_leaf_content,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_UNIT_SUB_SW_VERSION,
        IIDC_131_UNIT_SUB_SW_VERSION_NAME,
        .format_content.immediate = format_iidc2_100_unit_sub_sw_version_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_RESERVED_0,
        IIDC_131_RESERVED_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_RESERVED_1,
        IIDC_131_RESERVED_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_RESERVED_2,
        IIDC_131_RESERVED_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_0,
        IIDC_131_VENDOR_UNIQUE_INFO_0_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_1,
        IIDC_131_VENDOR_UNIQUE_INFO_1_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_2,
        IIDC_131_VENDOR_UNIQUE_INFO_2_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IIDC_131_VENDOR_UNIQUE_INFO_3,
        IIDC_131_VENDOR_UNIQUE_INFO_3_NAME,
    },
};

//////////////////////////////////////
// Directory entries specific to DPP.
//////////////////////////////////////

#define KEY_ID_DPP_111_COMMAND_SET_DIRECTORY      0x14 // Just for directory.
#define KEY_ID_DPP_111_COMMAND_SET_SPEC_ID        0x38 // Just for immediate.
#define KEY_ID_DPP_111_COMMAND_SET                0x39 // Just for immediate.
#define KEY_ID_DPP_111_COMMAND_SET_DETAILS        0x3a // Just for immediate.
#define KEY_ID_DPP_111_CONNECTION_REGISTER        0x3b // Just for CSR offset.
#define KEY_ID_DPP_111_WRITE_TRANSACTION_INTERVAL 0x3c // Just for immediate.
#define KEY_ID_DPP_111_UNIT_SW_DETAILS            0x3d // Just for immediate.

#define DPP_111_COMMAND_SET_DIRECTORY_NAME        "command set directory"
#define DPP_111_COMMAND_SET_SPEC_ID_NAME          "command set spec id"
#define DPP_111_COMMAND_SET_NAME                  "command set"
#define DPP_111_COMMAND_SET_DETAILS_NAME          "command set details"
#define DPP_111_CONNECTION_REGISTER_NAME          "connection CSR"
#define DPP_111_WRITE_TRANSACTION_INTERVAL_NAME   "write transaction interval"
#define DPP_111_UNIT_SW_DETAILS_NAME              "unit sw details"

static size_t format_dpp_111_command_set_immediate_value(char *buf, size_t length, uint32_t value)
{
    switch (value) {
    case 0xb081f2:
        return snprintf(buf, length, "DPC");
    case 0x020000:
        return snprintf(buf, length, "FTC");
    default:
        return 0;
    }
}

static size_t format_dpp_111_write_transaction_interval_immediate_value(char *buf, size_t length,
                                                                        uint32_t value)
{
    return snprintf(buf, length, "%dms", value);
}

static size_t format_dpp_111_unit_sw_details_immediate_value(char *buf, size_t length,
                                                             uint32_t value)
{
    unsigned int major = (value & 0x00f00000) >> 20;
    unsigned int minor = (value & 0x000f0000) >> 16;
    unsigned int micro = (value & 0x0000f000) >> 12;
    bool sdu_write_order = value & 1;

    return snprintf(buf, length, "v%d.%d.%d, sdu_write_order %d", major, minor, micro,
                    sdu_write_order);
}

static const struct key_formatter ta1394_dpp_111_key_formatters[] = {
    {
        KEY_TYPE_DIRECTORY,
        KEY_ID_DPP_111_COMMAND_SET_DIRECTORY,
        DPP_111_COMMAND_SET_DIRECTORY_NAME,
        .format_content.directory = format_directory_entries,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_DPP_111_COMMAND_SET_SPEC_ID,
        DPP_111_COMMAND_SET_SPEC_ID_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_DPP_111_COMMAND_SET,
        DPP_111_COMMAND_SET_NAME,
        .format_content.immediate = format_dpp_111_command_set_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_DPP_111_COMMAND_SET_DETAILS,
        DPP_111_COMMAND_SET_DETAILS_NAME,
    },
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_DPP_111_CONNECTION_REGISTER,
        DPP_111_CONNECTION_REGISTER_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_DPP_111_WRITE_TRANSACTION_INTERVAL,
        DPP_111_WRITE_TRANSACTION_INTERVAL_NAME,
        .format_content.immediate = format_dpp_111_write_transaction_interval_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_DPP_111_UNIT_SW_DETAILS,
        DPP_111_UNIT_SW_DETAILS_NAME,
        .format_content.immediate = format_dpp_111_unit_sw_details_immediate_value,
    },
};

///////////////////////////////////////
// Directory entries specific to IICP.
///////////////////////////////////////

#define KEY_ID_IICP_DETAILS                     0x38 // For immediate.
#define KEY_ID_IICP_COMMAND_SET_SPEC_ID         0x39 // For immediate.
#define KEY_ID_IICP_COMMAND_SET                 0x3a // For immediate.
#define KEY_ID_IICP_COMMAND_SET_DETAILS         0x3b // For immediate.
#define KEY_ID_IICP_CONNECTION_REG_OFFSET       0x3c // For CSR offset.
#define KEY_ID_IICP_CAPABILITIES                0x3d // For immediate.
#define KEY_ID_IICP_INTERRUPT_ENABLE_REG_OFFSET 0x3e // For CSR offset.
#define KEY_ID_IICP_INTERRUPT_HANDR_REG_OFFSET  0x3f // For CSR offset.

#define IICP_DETAILS_NAME                       "details"
#define IICP_COMMAND_SET_SPEC_ID_NAME           "command set spec id"
#define IICP_COMMAND_SET_NAME                   "command set"
#define IICP_COMMAND_SET_DETAILS_NAME           "command set details"
#define IICP_CONNECTION_REG_OFFSET_NAME         "connection CSR"
#define IICP_CAPABILITIES_NAME                  "capabilities"
#define IICP_INTERRUPT_ENABLE_REG_OFFSET_NAME   "interrupt_enable CSR"
#define IICP_INTERRUPT_HANDR_REG_OFFSET_NAME    "interrupt_handlr CSR"

static size_t format_iicp_details_immediate_value(char *buf, size_t length, uint32_t value)
{
    unsigned int major =
        (((value & 0xf00000) >> 20) & 0xf) * 10 + (((value & 0x0f0000) >> 16) & 0xf);
    unsigned int minor =
        (((value & 0x00f000) >> 12) & 0xf) * 10 + (((value & 0x000f00) >> 8) & 0xf);

    return snprintf(buf, length, "v%d.%d", major, minor);
}

static size_t format_iicp_command_set_immediate_value(char *buf, size_t length, uint32_t value)
{
    switch (value) {
    case 0x4b661f:
        return snprintf(buf, length, "IICP only");
    case 0xc27f10:
        return snprintf(buf, length, "IICP488");
    default:
        return 0;
    }
}

static size_t format_iicp_command_set_details_immediate_value(char *buf, size_t length,
                                                              uint32_t value)
{
    unsigned int major =
        (((value & 0xf00000) >> 20) & 0xf) * 10 + (((value & 0x0f0000) >> 16) & 0xf);
    unsigned int minor =
        (((value & 0x00f000) >> 12) & 0xf) * 10 + (((value & 0x000f00) >> 8) & 0xf);

    return snprintf(buf, length, "v%d.%d", major, minor);
}

static size_t format_iicp_capabilities_immediate_value(char *buf, size_t length, uint32_t value)
{
    unsigned int reserved_high_proto = (value & 0xff0000) >> 16;
    unsigned int reserved_iicp = (value & 0x00ffc0) >> 6;
    unsigned int ccli = (value & 0x000020) >> 5;
    unsigned int cmgr = (value & 0x000010) >> 4;
    unsigned int max_int_length_exponent = (value & 0x00000f);
    size_t consumed = 0;

    consumed += snprintf(buf, length, "hi proto %d, IICP %d, ccli %d, cmgr %d", reserved_high_proto,
                         reserved_iicp, ccli, cmgr);

    if (max_int_length_exponent > 0) {
        unsigned int max_int_bytes = 2 << max_int_length_exponent;

        consumed +=
            snprintf(buf + consumed, length - consumed, "  maxIntLength %d bytes", max_int_bytes);
    } else {
        consumed += snprintf(buf + consumed, length - consumed, "  maxIntLength -");
    }

    return consumed;
}

static const struct key_formatter ta1394_iicp_key_formatters[] = {
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IICP_DETAILS,
        IICP_DETAILS_NAME,
        .format_content.immediate = format_iicp_details_immediate_value,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IICP_COMMAND_SET_SPEC_ID,
        IICP_COMMAND_SET_SPEC_ID_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IICP_COMMAND_SET,
        IICP_COMMAND_SET_NAME,
        .format_content.immediate = format_iicp_command_set_immediate_value,
    },
    { KEY_TYPE_IMMEDIATE, KEY_ID_IICP_COMMAND_SET_DETAILS, IICP_COMMAND_SET_DETAILS_NAME,
      .format_content.immediate = format_iicp_command_set_details_immediate_value },
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_IICP_CONNECTION_REG_OFFSET,
        IICP_CONNECTION_REG_OFFSET_NAME,
    },
    {
        KEY_TYPE_IMMEDIATE,
        KEY_ID_IICP_CAPABILITIES,
        IICP_CAPABILITIES_NAME,
        .format_content.immediate = format_iicp_capabilities_immediate_value,
    },
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_IICP_INTERRUPT_ENABLE_REG_OFFSET,
        IICP_INTERRUPT_ENABLE_REG_OFFSET_NAME,
    },
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_IICP_INTERRUPT_HANDR_REG_OFFSET,
        IICP_INTERRUPT_HANDR_REG_OFFSET_NAME,
    }
};

#define KEY_ID_APPLE_ISIGHT_AUDIO_REG 0x00 // For CSR offset.

#define APPLE_ISIGHT_AUDIO_REG_NAME   "register file"

static const struct key_formatter apple_isight_audio_key_formatters[] = {
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_APPLE_ISIGHT_AUDIO_REG,
        APPLE_ISIGHT_AUDIO_REG_NAME,
    },
};

#define KEY_ID_APPLE_ISIGHT_IRIS_REG 0x00 // For CSR offset.

#define APPLE_ISIGHT_IRIS_REG_NAME   "Iris Status Address register"

static const struct key_formatter apple_isight_iris_key_formatters[] = {
    {
        KEY_TYPE_CSR_OFFSET,
        KEY_ID_APPLE_ISIGHT_IRIS_REG,
        APPLE_ISIGHT_IRIS_REG_NAME,
    },
};

static size_t format_unspecified_immediate_value(char *buf, size_t length, uint32_t value)
{
    return snprintf(buf, length, "(immediate value)");
}

static const struct key_formatter *find_formatter(const struct key_formatter *formatters,
                                                  size_t formatter_count, uint32_t key_type,
                                                  uint32_t key_id)
{
    int i;

    for (i = 0; i < formatter_count; ++i) {
        const struct key_formatter *formatter = formatters + i;
        if (formatter->key_type == key_type && formatter->key_id == key_id)
            return formatter;
    }

    return NULL;
}

static void detect_key_formatter(const struct key_formatter **formatter, const char **spec_name,
                                 const struct spec_identifier *identifier, uint32_t key_type,
                                 uint32_t key_id)
{
    static const struct {
        const char *spec_name;
        const struct spec_identifier *identifier;
        const struct key_formatter *formatters;
        size_t formatter_count;
    } *spec_entry, spec_entries[] = {
        {
            SPEC_NAME_RFC_2734,
            &spec_iana_ipv4,
            NULL,
            0,
        },
        {
            SPEC_NAME_RFC_3146,
            &spec_iana_ipv6,
            NULL,
            0,
        },
        // NOTE: both SBP-2 and -3 use the same identifiers.
        {
            SPEC_NAME_SBP,
            &spec_incits_sbp,
            incits_sbp_key_formatters,
            CONST_ARRAY_SIZE(incits_sbp_key_formatters),
        },
        {
            SPEC_NAME_SBP_AVC,
            &spec_incits_sbp_avc,
            incits_sbp_key_formatters,
            CONST_ARRAY_SIZE(incits_sbp_key_formatters),
        },
        {
            SPEC_NAME_AVC,
            &spec_1394ta_avc,
            NULL,
            0,
        },
        {
            SPEC_NAME_CAL,
            &spec_1394ta_cal,
            NULL,
            0,
        },
        {
            SPEC_NAME_EHS,
            &spec_1394ta_ehs,
            NULL,
            0,
        },
        {
            SPEC_NAME_HAVI,
            &spec_1394ta_havi,
            NULL,
            0,
        },
        {
            SPEC_NAME_VENDOR_UNIQUE,
            &spec_1394ta_vendor_unique,
            NULL,
            0,
        },
        {
            SPEC_NAME_VENDOR_UNIQUE_AVC,
            &spec_1394ta_vendor_unique_avc,
            NULL,
            0,
        },
        {
            SPEC_NAME_IIDC_104,
            &spec_1394ta_iidc_104,
            ta1394_iidc_104_key_formatters,
            CONST_ARRAY_SIZE(ta1394_iidc_104_key_formatters),
        },
        {
            SPEC_NAME_IIDC_120,
            &spec_1394ta_iidc_120,
            ta1394_iidc_104_key_formatters,
            CONST_ARRAY_SIZE(ta1394_iidc_104_key_formatters),
        },
        {
            SPEC_NAME_IIDC_130,
            &spec_1394ta_iidc_130,
            ta1394_iidc_131_key_formatters,
            CONST_ARRAY_SIZE(ta1394_iidc_131_key_formatters),
        },
        {
            SPEC_NAME_IIDC2,
            &spec_1394ta_iidc2,
            ta1394_iidc2_100_key_formatters,
            CONST_ARRAY_SIZE(ta1394_iidc2_100_key_formatters),
        },
        {
            SPEC_NAME_DPP_111,
            &spec_1394ta_dpp_111,
            ta1394_dpp_111_key_formatters,
            CONST_ARRAY_SIZE(ta1394_dpp_111_key_formatters),
        },
        {
            SPEC_NAME_IICP,
            &spec_1394ta_iicp,
            ta1394_iicp_key_formatters,
            CONST_ARRAY_SIZE(ta1394_iicp_key_formatters),
        },
        {
            SPEC_NAME_ALESIS_AUDIO,
            &spec_alesis_audio,
            NULL,
            0,
        },
        {
            SPEC_NAME_ISIGHT_AUDIO,
            &spec_apple_isight_audio,
            apple_isight_audio_key_formatters,
            CONST_ARRAY_SIZE(apple_isight_audio_key_formatters),
        },
        {
            SPEC_NAME_ISIGHT_FACTORY,
            &spec_apple_isight_factory,
            NULL,
            0,
        },
        {
            SPEC_NAME_ISIGHT_IRIS,
            &spec_apple_isight_iris,
            apple_isight_iris_key_formatters,
            CONST_ARRAY_SIZE(apple_isight_iris_key_formatters),
        },
        {
            SPEC_NAME_LACIE_HID,
            &spec_lacie_hid,
            NULL,
            0,
        },
    };
    static const struct key_formatter default_formatters[] = {
        [KEY_TYPE_IMMEDIATE] =
            {
                KEY_TYPE_IMMEDIATE,
                INVALID_KEY_ID,
                UNSPECIFIED_ENTRY_NAME,
                .format_content.immediate = format_unspecified_immediate_value,
            },
        [KEY_TYPE_CSR_OFFSET] =
            {
                KEY_TYPE_CSR_OFFSET,
                INVALID_KEY_ID,
                UNSPECIFIED_ENTRY_NAME,
            },
        [KEY_TYPE_LEAF] =
            {
                KEY_TYPE_LEAF,
                INVALID_KEY_ID,
                UNSPECIFIED_ENTRY_NAME,
                .format_content.leaf = format_unspecified_leaf_content,
            },
        [KEY_TYPE_DIRECTORY] =
            {
                KEY_TYPE_DIRECTORY,
                INVALID_KEY_ID,
                UNSPECIFIED_ENTRY_NAME,
                .format_content.directory = format_directory_entries,
            },
    };
    int i;

    spec_entry = NULL;
    for (i = 0; i < CONST_ARRAY_SIZE(spec_entries); ++i) {
        if (!memcmp(spec_entries[i].identifier, identifier, sizeof(*identifier))) {
            spec_entry = spec_entries + i;
            break;
        }
    }

    if (spec_entry != NULL) {
        *formatter =
            find_formatter(spec_entry->formatters, spec_entry->formatter_count, key_type, key_id);
        if (*formatter != NULL) {
            *spec_name = spec_entry->spec_name;
            return;
        }
    }

    *formatter = find_formatter(ieee1394_bus_key_formatters,
                                CONST_ARRAY_SIZE(ieee1394_bus_key_formatters), key_type, key_id);
    if (*formatter != NULL)
        return;

    *formatter =
        find_formatter(csr_key_formatters, CONST_ARRAY_SIZE(csr_key_formatters), key_type, key_id);
    if (*formatter != NULL)
        return;

    *formatter = &default_formatters[key_type];
}
