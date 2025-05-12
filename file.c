// nantuFS_fixer
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define BLOCK_SIZE 4096
#define TOTAL_BLOCKS 64
#define INODE_SIZE 256
#define INODE_COUNT 80
#define MAGIC 0xD34D
#define INODE_TABLE_BLOCKS 5

struct superblock {
    uint16_t magic;
    uint32_t block_size;
    uint32_t total_blocks;
    uint32_t inode_bitmap_blk;
    uint32_t data_bitmap_blk;
    uint32_t inode_table_blk;
    uint32_t first_data_blk;
    uint32_t inode_size;
    uint32_t inode_count;
    char reserved[4058];
};

struct inode {
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t size;
    uint32_t atime;
    uint32_t ctime;
    uint32_t mtime;
    uint32_t dtime;
    uint32_t links_count;
    uint32_t blocks;
    uint32_t direct;
    uint32_t indirect;
    uint32_t double_indirect;
    uint32_t triple_indirect;
    char reserved[156];
};

FILE *img;
uint8_t inode_bitmap[BLOCK_SIZE];
uint8_t data_bitmap[BLOCK_SIZE];
struct inode inodes[INODE_COUNT];
bool block_referenced[TOTAL_BLOCKS] = { false };
bool modified = false;
bool fix_superblock = false;
bool fix_inode_bitmap = false;
bool fix_data_bitmap = false;

void read_block(int blkno, void *buf) {
    fseek(img, blkno * BLOCK_SIZE, SEEK_SET);
    fread(buf, 1, BLOCK_SIZE, img);
}

void write_block(int blkno, void *buf) {
    fseek(img, blkno * BLOCK_SIZE, SEEK_SET);
    fwrite(buf, 1, BLOCK_SIZE, img);
}
// sudipta
bool check_superblock(struct superblock *sb) {
    bool valid = true;
    if (sb->magic != MAGIC) {
        printf("[ERROR] Invalid magic number: 0x%X\n", sb->magic);
        fix_superblock = true;
        valid = false;
    }
    if (sb->block_size != BLOCK_SIZE) {
        printf("[ERROR] Incorrect block size: %d\n", sb->block_size);
        fix_superblock = true;
        valid = false;
    }
    if (sb->total_blocks != TOTAL_BLOCKS) {
        printf("[ERROR] Incorrect total blocks: %d\n", sb->total_blocks);
        fix_superblock = true;
        valid = false;
    }
    if (sb->inode_bitmap_blk != 1 || sb->data_bitmap_blk != 2) {
        printf("[ERROR] Incorrect bitmap block numbers\n");
        fix_superblock = true;
        valid = false;
    }
    if (sb->inode_table_blk != 3 || sb->first_data_blk != 8) {
        printf("[ERROR] Incorrect inode table or data block start\n");
        fix_superblock = true;
        valid = false;
    }
    if (sb->inode_size != INODE_SIZE || sb->inode_count > INODE_COUNT) {
        printf("[ERROR] Invalid inode size or count\n");
        fix_superblock = true;
        valid = false;
    }
    return valid;
}
//sudipta
void fix_superblock_fields(struct superblock *sb) {
    sb->magic = MAGIC;
    sb->block_size = BLOCK_SIZE;
    sb->total_blocks = TOTAL_BLOCKS;
    sb->inode_bitmap_blk = 1;
    sb->data_bitmap_blk = 2;
    sb->inode_table_blk = 3;
    sb->first_data_blk = 8;
    sb->inode_size = INODE_SIZE;
    sb->inode_count = INODE_COUNT;
    modified = true;
    printf("[FIX] Superblock fields corrected\n");
}
//sudipta
void load_fs_metadata(const struct superblock *sb) {
    read_block(sb->inode_bitmap_blk, inode_bitmap);
    read_block(sb->data_bitmap_blk, data_bitmap);
    for (int i = 0; i < INODE_TABLE_BLOCKS; i++) {
        read_block(sb->inode_table_blk + i, ((uint8_t*)inodes) + i * BLOCK_SIZE);
    }
}
//swanan
void check_inode_bitmap(const struct superblock *sb) {
    for (int i = 0; i < sb->inode_count; i++) {
        bool bitmap_set = (inode_bitmap[i / 8] >> (i % 8)) & 1;
        struct inode *node = &inodes[i];
        bool valid_inode = (node->links_count > 0 && node->dtime == 0);

        if (bitmap_set && !valid_inode) {
            printf("[ERROR] Inode %d marked used but is invalid.\n", i);
            fix_inode_bitmap = true;
        }
        else if (!bitmap_set && valid_inode) {
            printf("[ERROR] Inode %d valid but not marked used.\n", i);
            fix_inode_bitmap = true;
        }
    }
}
//swanan
void fix_inode_bitmap_func(const struct superblock *sb) {
    for (int i = 0; i < sb->inode_count; i++) {
        struct inode *node = &inodes[i];
        bool valid_inode = (node->links_count > 0 && node->dtime == 0);
        if (valid_inode)
            inode_bitmap[i / 8] |= (1 << (i % 8));
        else
            inode_bitmap[i / 8] &= ~(1 << (i % 8));
    }
    modified = true;
    printf("[FIX] Inode bitmap corrected\n");
}
//swanan
void check_and_mark_block(uint32_t blkno, int inode_index) {
    if (blkno < 8 || blkno >= TOTAL_BLOCKS) {
        printf("[ERROR] Inode %d references invalid block %d.\n", inode_index, blkno);
        return;
    }
    if (block_referenced[blkno]) {
        printf("[ERROR] Block %d referenced by multiple inodes.\n", blkno);
    }
    block_referenced[blkno] = true;
}
//sudipta
void check_data_bitmap(const struct superblock *sb) {
    for (int i = 0; i < sb->inode_count; i++) {
        if (!((inode_bitmap[i / 8] >> (i % 8)) & 1)) continue;
        struct inode *node = &inodes[i];
        if (node->direct != 0) {
            check_and_mark_block(node->direct, i);
        }
    }

    for (int blk = sb->first_data_blk; blk < TOTAL_BLOCKS; blk++) {
        bool bitmap_set = (data_bitmap[blk / 8] >> (blk % 8)) & 1;
        bool actually_used = block_referenced[blk];

        if (actually_used && !bitmap_set) {
            printf("[ERROR] Block %d used but not marked in bitmap.\n", blk);
            fix_data_bitmap = true;
        } else if (!actually_used && bitmap_set) {
            printf("[ERROR] Block %d marked in bitmap but not used.\n", blk);
            fix_data_bitmap = true;
        }
    }
}
//sudipta
void fix_data_bitmap_func(const struct superblock *sb) {
    for (int blk = sb->first_data_blk; blk < TOTAL_BLOCKS; blk++) {
        if (block_referenced[blk])
            data_bitmap[blk / 8] |= (1 << (blk % 8));
        else
            data_bitmap[blk / 8] &= ~(1 << (blk % 8));
    }
    modified = true;
    printf("[FIX] Data bitmap corrected\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <vsfs.img>\n", argv[0]);
        return 1;
    }

    img = fopen(argv[1], "r+b");
    if (!img) {
        perror("[ERROR] Failed to open file");
        return 1;
    }

    struct superblock sb;
    read_block(0, &sb);

    printf("\n[INFO] Checking Superblock...\n");
    check_superblock(&sb);

    load_fs_metadata(&sb);

    printf("\n[INFO] Checking Inode Bitmap...\n");
    check_inode_bitmap(&sb);

    printf("\n[INFO] Checking Data Bitmap...\n");
    check_data_bitmap(&sb);

    if (fix_superblock || fix_inode_bitmap || fix_data_bitmap) {
        printf("\n[INFO] Applying fixes...\n");
        if (fix_superblock) fix_superblock_fields(&sb);
        if (fix_inode_bitmap) fix_inode_bitmap_func(&sb);
        if (fix_data_bitmap) fix_data_bitmap_func(&sb);

        write_block(0, &sb);
        write_block(sb.inode_bitmap_blk, inode_bitmap);
        write_block(sb.data_bitmap_blk, data_bitmap);
        for (int i = 0; i < INODE_TABLE_BLOCKS; i++) {
            write_block(sb.inode_table_blk + i, ((uint8_t*)inodes) + i * BLOCK_SIZE);
        }
        printf("[INFO] File system corrections written.\n");
    } else {
        printf("\n[INFO] No fixes needed. File system is consistent.\n");
    }

    fclose(img);
    return 0;
}
