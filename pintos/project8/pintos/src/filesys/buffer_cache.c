#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/buffer_cache.h"


struct buffer_head buffer_cache[BC_ENTRY_NB]; //buffer_head�� �迭
int clock_hand; //clock_algoritm�� ���� clock


//block_cache �б�.
bool bc_read(block_sector_t sector_idx, void* buffer, off_t bytes_read,
		int chunk_size, int sector_ofs) {

	struct buffer_head* b = bc_lookup(sector_idx);

	//���� �ش缽�Ͱ� ���ۿ����� �������� �ʾҴٸ�, bc_select_victim�� ����
	//���ο� buffer_entry�� �Ҵ�ް�, �� entry�� ��ũ�κ��� data�� �о��.
	if ((int) b == SECTOR_ERROR) {

		b = bc_select_victim();
		if ((int) b == SECTOR_ERROR) { //execption handling.
			printf("bc_select_victim ERROR\n");
			return false;
		}
		//��ũ�κ��� �ڷḦ �а� bc_entry used�� clock�� �ֽ�ȭ���ش�.
		lock_acquire(&b->lock);
		block_read(fs_device, sector_idx, b->data); // b->data �´°�?
		b->used = true;
		b->sector = sector_idx;
		lock_release(&b->lock);
	}

	//buffer�� buffer_cache�� ������ �����Ѵ�.
	lock_acquire(&b->lock);
	memcpy(buffer + bytes_read, b->data + sector_ofs, chunk_size);
	b->clock = true;
	lock_release(&b->lock);

	return true;

}

//block_cache ����
bool bc_write(block_sector_t sector_idx, void* buffer, off_t bytes_written,
		int chunk_size, int sector_ofs) {

	struct buffer_head* b = bc_lookup(sector_idx);

	//���� �ش缽�Ͱ� ���ۿ����� �������� �ʾҴٸ�, bc_select_victim�� ����
	//���ο� buffer_entry�� �Ҵ�ް�, �� entry�� ��ũ�κ��� data�� �о��.
	if ((int) b == SECTOR_ERROR) {
		b = bc_select_victim();
		if ((int) b == SECTOR_ERROR) {
			printf("bc_select_victim ERROR\n");
			return false;
		}
		//��ũ�κ��� �ڷḦ �а� bc_entry used�� clock�� �ֽ�ȭ���ش�
		lock_acquire(&b->lock);
		block_read(fs_device, sector_idx, b->data); // b->data �´°�?
		b->used = true;
		b->sector = sector_idx;
		lock_release(&b->lock);
	}

	//buffer�� ���� buffer_cache�� ������ �����Ѵ�.
	lock_acquire(&b->lock);
	memcpy(b->data + sector_ofs, buffer + bytes_written, chunk_size);
	b->clock = true;
	b->dirty = true;
	lock_release(&b->lock);
	return true;
}


//buffer_cache ����ϱ� ���� �ʱ�ȭ�۾�
void bc_init(void) {

	clock_hand = -1;
	int i;
	//�� entry�� ��ȸ�ϸ� bc_head �ڷᱸ�� �ʱ�ȭ.
	for (i = 0; i < BC_ENTRY_NB; ++i) {
		//�� entry ���� block_sector_size ��ŭ �����Ҵ�.
		buffer_cache[i].data = (uint8_t *) malloc(BLOCK_SECTOR_SIZE);
		buffer_cache[i].dirty = false;
		buffer_cache[i].used = false;
		buffer_cache[i].clock = false;
		buffer_cache[i].sector = SECTOR_ERROR;
		lock_init(&buffer_cache[i].lock);
	}
}



// ��밡���� buffer_head�ڷᱸ���� ��ȯ�ϴ� �Լ�.
struct buffer_head* bc_select_victim(void) {

	// ������ �ʴ� entry�� �ִ��� �˻��� ������ ��ȯ.
	int i;
	for (i = 0; i < BC_ENTRY_NB; ++i) {
		if (buffer_cache[i].used == false) {
			return &buffer_cache[i];
		}
	}
	//��� bc_entry�� ������̶�� lru_clock�� �̿��� victim ���� �� �ش� entry ��ȯ
	while (1) {
		//clock_hand ���� 1�� �÷��ְ� 64�� �Ѿ�� �ٽ� 0����
		++clock_hand;
		if (clock_hand == BC_ENTRY_NB)
			clock_hand = 0;
		lock_acquire(&buffer_cache[clock_hand].lock);
		//�ش� entry�� clock������ false���
		if (buffer_cache[clock_hand].clock == false) {
			//entry�� ������ flush ���ְ� sector ���� sector_error������ ����.
			if (buffer_cache[clock_hand].dirty) {
				bc_flush_entry(&buffer_cache[clock_hand]);
			}
			buffer_cache[clock_hand].sector = SECTOR_ERROR;
			lock_release(&buffer_cache[clock_hand].lock);
			//����� entry ��ȯ
			return &buffer_cache[clock_hand];
		}
		// �ƴϸ�clock���� 0���� ������.
		else
			buffer_cache[clock_hand].clock = false;
		lock_release(&buffer_cache[clock_hand].lock);
	}
}

// buffer_cache�� �ش� sector�� �ִ��� �˻��ϰ� entry�� ��ȯ�ϴ� �Լ�.
struct buffer_head* bc_lookup(block_sector_t sector) {

	int i;
	//��ȸ�ϸ� ���� �� ã���� entry �ּҹ�ȯ
	for (i = 0; i < BC_ENTRY_NB; ++i) {
		if (buffer_cache[i].sector == sector)
			return &buffer_cache[i];
	}
	return SECTOR_ERROR;
}

// buffer_cahce entry�� ������ ��ũ�� �����ְ� entry �ڷᱸ���� ����.
void bc_flush_entry(struct buffer_head *p_flush_entry) {

	block_write(fs_device, p_flush_entry->sector, p_flush_entry->data);
	p_flush_entry->dirty = false;
	p_flush_entry->used = false;
	p_flush_entry->clock = false;

}

// buffer_cahce�� ��� entry�� ���Ͽ� bc_flush_entry�� ����,
void bc_flush_all_entries(void) {

	int i;
	// ��ȸ�ϸ� bc_flush_entry�Լ� ȣ��
	for (i = 0; i < BC_ENTRY_NB; ++i) {
		if (buffer_cache[i].dirty) {
			lock_acquire(&buffer_cache[clock_hand].lock);
			bc_flush_entry(&buffer_cache[i]);
			lock_release(&buffer_cache[clock_hand].lock);
		}
	}
}

// buffer_cache������ �����ϴ� �Լ�.
void bc_term(void) {

	//bc_flush_all_entries ȣ�� �� �����Ҵ�� ���� ��� �ʱ�ȭ.
	bc_flush_all_entries();
	int i;
	for (i = 0; i < BC_ENTRY_NB; ++i) {
		free(buffer_cache[i].data);
	}
}
