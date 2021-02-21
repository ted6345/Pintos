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


struct buffer_head buffer_cache[BC_ENTRY_NB]; //buffer_head의 배열
int clock_hand; //clock_algoritm을 위한 clock


//block_cache 읽기.
bool bc_read(block_sector_t sector_idx, void* buffer, off_t bytes_read,
		int chunk_size, int sector_ofs) {

	struct buffer_head* b = bc_lookup(sector_idx);

	//만약 해당섹터가 버퍼영역에 존재하지 않았다면, bc_select_victim을 통해
	//새로운 buffer_entry를 할당받고, 그 entry에 디스크로부터 data를 읽어옴.
	if ((int) b == SECTOR_ERROR) {

		b = bc_select_victim();
		if ((int) b == SECTOR_ERROR) { //execption handling.
			printf("bc_select_victim ERROR\n");
			return false;
		}
		//디스크로부터 자료를 읽고 bc_entry used와 clock을 최신화해준다.
		lock_acquire(&b->lock);
		block_read(fs_device, sector_idx, b->data); // b->data 맞는가?
		b->used = true;
		b->sector = sector_idx;
		lock_release(&b->lock);
	}

	//buffer에 buffer_cache의 정보를 복사한다.
	lock_acquire(&b->lock);
	memcpy(buffer + bytes_read, b->data + sector_ofs, chunk_size);
	b->clock = true;
	lock_release(&b->lock);

	return true;

}

//block_cache 쓰기
bool bc_write(block_sector_t sector_idx, void* buffer, off_t bytes_written,
		int chunk_size, int sector_ofs) {

	struct buffer_head* b = bc_lookup(sector_idx);

	//만약 해당섹터가 버퍼영역에 존재하지 않았다면, bc_select_victim을 통해
	//새로운 buffer_entry를 할당받고, 그 entry에 디스크로부터 data를 읽어옴.
	if ((int) b == SECTOR_ERROR) {
		b = bc_select_victim();
		if ((int) b == SECTOR_ERROR) {
			printf("bc_select_victim ERROR\n");
			return false;
		}
		//디스크로부터 자료를 읽고 bc_entry used와 clock을 최신화해준다
		lock_acquire(&b->lock);
		block_read(fs_device, sector_idx, b->data); // b->data 맞는가?
		b->used = true;
		b->sector = sector_idx;
		lock_release(&b->lock);
	}

	//buffer로 부터 buffer_cache에 정보를 복사한다.
	lock_acquire(&b->lock);
	memcpy(b->data + sector_ofs, buffer + bytes_written, chunk_size);
	b->clock = true;
	b->dirty = true;
	lock_release(&b->lock);
	return true;
}


//buffer_cache 사용하기 위한 초기화작업
void bc_init(void) {

	clock_hand = -1;
	int i;
	//각 entry를 순회하며 bc_head 자료구조 초기화.
	for (i = 0; i < BC_ENTRY_NB; ++i) {
		//각 entry 마다 block_sector_size 만큼 동적할당.
		buffer_cache[i].data = (uint8_t *) malloc(BLOCK_SECTOR_SIZE);
		buffer_cache[i].dirty = false;
		buffer_cache[i].used = false;
		buffer_cache[i].clock = false;
		buffer_cache[i].sector = SECTOR_ERROR;
		lock_init(&buffer_cache[i].lock);
	}
}



// 사용가능한 buffer_head자료구조를 반환하는 함수.
struct buffer_head* bc_select_victim(void) {

	// 사용되지 않는 entry가 있는지 검색후 있으면 반환.
	int i;
	for (i = 0; i < BC_ENTRY_NB; ++i) {
		if (buffer_cache[i].used == false) {
			return &buffer_cache[i];
		}
	}
	//모든 bc_entry가 사용중이라면 lru_clock을 이용한 victim 선정 및 해당 entry 반환
	while (1) {
		//clock_hand 값을 1씩 늘려주고 64를 넘어가면 다시 0으로
		++clock_hand;
		if (clock_hand == BC_ENTRY_NB)
			clock_hand = 0;
		lock_acquire(&buffer_cache[clock_hand].lock);
		//해당 entry의 clock변수가 false라면
		if (buffer_cache[clock_hand].clock == false) {
			//entry의 내용을 flush 해주고 sector 값은 sector_error값으로 변경.
			if (buffer_cache[clock_hand].dirty) {
				bc_flush_entry(&buffer_cache[clock_hand]);
			}
			buffer_cache[clock_hand].sector = SECTOR_ERROR;
			lock_release(&buffer_cache[clock_hand].lock);
			//비워준 entry 반환
			return &buffer_cache[clock_hand];
		}
		// 아니면clock값을 0으로 고쳐줌.
		else
			buffer_cache[clock_hand].clock = false;
		lock_release(&buffer_cache[clock_hand].lock);
	}
}

// buffer_cache에 해당 sector가 있는지 검사하고 entry를 반환하는 함수.
struct buffer_head* bc_lookup(block_sector_t sector) {

	int i;
	//순회하며 같은 값 찾으면 entry 주소반환
	for (i = 0; i < BC_ENTRY_NB; ++i) {
		if (buffer_cache[i].sector == sector)
			return &buffer_cache[i];
	}
	return SECTOR_ERROR;
}

// buffer_cahce entry의 정보를 디스크에 내려주고 entry 자료구조값 변경.
void bc_flush_entry(struct buffer_head *p_flush_entry) {

	block_write(fs_device, p_flush_entry->sector, p_flush_entry->data);
	p_flush_entry->dirty = false;
	p_flush_entry->used = false;
	p_flush_entry->clock = false;

}

// buffer_cahce의 모든 entry에 대하여 bc_flush_entry를 해줌,
void bc_flush_all_entries(void) {

	int i;
	// 순회하며 bc_flush_entry함수 호출
	for (i = 0; i < BC_ENTRY_NB; ++i) {
		if (buffer_cache[i].dirty) {
			lock_acquire(&buffer_cache[clock_hand].lock);
			bc_flush_entry(&buffer_cache[i]);
			lock_release(&buffer_cache[clock_hand].lock);
		}
	}
}

// buffer_cache영역을 정리하는 함수.
void bc_term(void) {

	//bc_flush_all_entries 호출 후 동적할당된 영역 모두 초기화.
	bc_flush_all_entries();
	int i;
	for (i = 0; i < BC_ENTRY_NB; ++i) {
		free(buffer_cache[i].data);
	}
}
