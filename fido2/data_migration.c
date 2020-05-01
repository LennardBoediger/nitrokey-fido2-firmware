// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include "data_migration.h"
#include "log.h"
#include "device.h"
#include "crypto.h"
#include "flash.h"
#include "memory_layout.h"

typedef uint8_t * address;
typedef uint8_t page_num;

bool RK_record_empty(CTAP_residentKey_vFF* rec){
  return *((uint32_t*)rec) == 0xFFFFFFFF;
}

typedef struct RK_page {
  union{
    struct{
      CTAP_residentKey_v1 buf_1[5];
      uint8_t _padding[2];
      uint8_t version;
    };
    uint8_t page_raw[PAGE_SIZE];
  };
} RK_page;

static_assert(sizeof(RK_page) <= FLASH_PAGE_SIZE, "RK PAGE bigger than one page");

void migrate_RK_page_from_FF_to_01(page_num page){
  CTAP_residentKey_vFF buf_ff[5];
  CTAP_residentKey_v1 buf_1[5];
  static_assert(sizeof(buf_ff) <= FLASH_PAGE_SIZE, "array buf ff bigger than one page");
  static_assert(sizeof(buf_1) <= FLASH_PAGE_SIZE, "array buf 1 bigger than one page");

  uint8_t rpId_str[] = "Unknown   ";

  // load data into buffer
  memmove((address)buf_ff, (address)flash_addr(page), sizeof(buf_ff));

  // process data
  for (int i = 0; i < 5; ++i) {
    if (RK_record_empty(&buf_ff[i])) {
      //skip processing empty record
      continue;
    }
    memmove((address)&buf_1[i].id, (address)&buf_ff[i].id, sizeof(buf_ff[i].id));
    memmove((address)&buf_1[i].user, (address)&buf_ff[i].user, sizeof(buf_ff[i].user));
    memmove((address)&buf_1[i].rpId, rpId_str, sizeof(rpId_str));
    buf_1[i].rpIdSize = sizeof(rpId_str);
  }

  //set version on page 1
  if (page == 0) {
    *(uint8_t*)(&buf_1) = 0x01;
  }

  // clear page addr
  flash_erase_page(page);
  // move data to page
  flash_write(flash_addr(page), (address)buf_1, sizeof(buf_1));
}

void migrate_RK_from_FF_to_01(){
  if (*(uint8_t*)flash_addr(RK_START_PAGE) == 0x01) {
    return;
  }
  for (int i = 0; i < RK_NUM_PAGES; ++i) {
    migrate_RK_page_from_FF_to_01(RK_START_PAGE+i);
  }
}

// TODO bail if cannot restore the data, instead of triggering assert
// TODO move from macro to function/assert for better readability?
#define check(x) assert(state_prev_0xff->x == state_tmp_ptr->x);
#define check_buf(x) assert(memcmp(state_prev_0xff->x, state_tmp_ptr->x, sizeof(state_tmp_ptr->x)) == 0);

bool migrate_from_FF_to_01(AuthenticatorState_0xFF* state_prev_0xff, AuthenticatorState_0x01* state_tmp_ptr){
    // Calculate PIN hash, and replace PIN raw storage with it; add version to structure
    // other ingredients do not change
    if (state_tmp_ptr->data_version != 0xFF)
        return false;

    static_assert(sizeof(AuthenticatorState_0xFF) <= sizeof(AuthenticatorState_0x01), "New state structure is smaller, than current one, which is not handled");

    if (ctap_generate_rng(state_tmp_ptr->PIN_SALT, sizeof(state_tmp_ptr->PIN_SALT)) != 1) {
        printf2(TAG_ERR, "Error, rng failed\n");
        return false;
    }
    if (state_prev_0xff->is_pin_set){
        crypto_sha256_init();
        crypto_sha256_update(state_prev_0xff->pin_code, state_prev_0xff->pin_code_length);
        uint8_t intermediateHash[32];
        crypto_sha256_final(intermediateHash);

        crypto_sha256_init();
        crypto_sha256_update(intermediateHash, 16);
        memset(intermediateHash, 0, sizeof(intermediateHash));
        crypto_sha256_update(state_tmp_ptr->PIN_SALT, sizeof(state_tmp_ptr->PIN_SALT));
        crypto_sha256_final(state_tmp_ptr->PIN_CODE_HASH);
    }

    assert(state_tmp_ptr->_reserved == state_prev_0xff->pin_code_length);
    state_tmp_ptr->_reserved = 0xFF;
    state_tmp_ptr->data_version = 1;

    check(is_initialized);
    check(is_pin_set);
    check(remaining_tries);
    check(rk_stored);
    check_buf(key_lens);
    check_buf(key_space);
    assert(state_tmp_ptr->data_version != 0xFF);

    return true;
}

void save_migrated_state(AuthenticatorState *state_tmp_ptr) {
    memmove(&STATE, state_tmp_ptr, sizeof(AuthenticatorState));
    authenticator_write_state(state_tmp_ptr);
}

void do_migration_if_required(AuthenticatorState* state_current){
    // Currently handles only state structures with the same size, or bigger
    // FIXME rework to raw buffers with fixed size to allow state structure size decrease
    if(!state_current->is_initialized)
        return;

    AuthenticatorState state_tmp;
    AuthenticatorState state_previous;
    authenticator_read_state(&state_previous);
    authenticator_read_state(&state_tmp);
    if(state_current->data_version == 0xFF){
        printf2(TAG_ERR, "Running migration\n");
        bool success = migrate_from_FF_to_01((AuthenticatorState_0xFF *) &state_previous, &state_tmp);
        if (!success){
            printf2(TAG_ERR, "Failed migration from 0xFF to 1\n");
            // FIXME discuss migration failure behavior
            goto return_cleanup;
        }
        dump_hex1(TAG_ERR, (void*)&state_tmp, sizeof(state_tmp));
        dump_hex1(TAG_ERR, (void*)&state_previous, sizeof(state_previous));
        save_migrated_state(&state_tmp);
    }

    assert(state_current->data_version == STATE_VERSION);

    return_cleanup:
    memset(&state_tmp, 0, sizeof(AuthenticatorState));
    memset(&state_previous, 0, sizeof(AuthenticatorState));
}
