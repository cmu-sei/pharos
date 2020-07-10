// Copyright 2020 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdlib.h>
#include <stdint.h>
#include "test.hpp"

#define SUCCESS 1
#define PIPE_CB1_A 3
#define PIPE_CB2_B 6
#define PIPE_RECV PIPE_CB2_B
#define OP_ADD 0
#define OP_SUB 1
#define OP_MUL 2
#define OP_DIV 3
#define OP_ACK 4
#define OP_MOD 61
#define NUM_OPS 256
#define ERRNO_KEY_EXCHANGE 9

typedef int (*funcptr_t)(u_int32_t, int*, u_int8_t);

int cgc_op_add(u_int32_t, int*, u_int8_t) {
  return SUCCESS;
}
int cgc_op_sub(u_int32_t, int*, u_int8_t) {
  return SUCCESS;
}
int cgc_op_mul(u_int32_t, int*, u_int8_t) {
  return SUCCESS;
}
int cgc_op_div(u_int32_t, int*, u_int8_t) {
  return SUCCESS;
}

int cgc_op_mod(u_int32_t x, int* y, u_int8_t nmb);

funcptr_t operations[NUM_OPS] = {
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 8
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 16
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 24
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 32
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 40
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 48
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 56
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_mod, cgc_op_mul, cgc_op_div, // 64
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 72
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 80
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 88
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 96
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 104
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 112
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 120
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 128

  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 8
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 16
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 24
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 32
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 40
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 48
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 56
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 64
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 72
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 80
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 88
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 96
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 104
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 112
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 120
  cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, cgc_op_add, cgc_op_sub, cgc_op_mul, cgc_op_div, // 128
};

typedef struct __attribute__((packed)) msg {
  u_int32_t dst; // 4B
  u_int32_t x; // 8B
  funcptr_t y; // 12B
  u_int8_t op; // 13B
  u_int8_t nmb; // 14B
  u_int8_t pad[2]; // 16B
  u_int64_t result; // 24B
} msg;

u_int32_t cgc_enckey[4] = { 0, 0, 0, 0 };
u_int32_t cgc_auth_token = { 0 };

int cgc_receive(int, char*, size_t bytes_left, size_t *rx_bytes_local) {
  *rx_bytes_local = bytes_left;
  return SUCCESS;
}

// An unholy alliance of Paul's CQE function and Nick's CFE function.
int cgc_recv_bytes(int fd, char *buf, unsigned int size) {

  int ret = SUCCESS;
  size_t bytes_left = size;
  size_t rx_bytes_local = 0;

  while (bytes_left) {

    rx_bytes_local = 0;

    if (SUCCESS != (ret = cgc_receive(fd, buf+(size-bytes_left), bytes_left, &rx_bytes_local))) {
      goto bail;
    }
    rx_bytes_local = 1;

    bytes_left -= rx_bytes_local;
  }

bail:
  return ret;
}

// An authenticated function used to reconfigure the operations
// (and provide type 1 PoV).
int cgc_op_mod(u_int32_t x, int* iy, u_int8_t nmb) {

    funcptr_t y = (funcptr_t)iy;

    int ret = SUCCESS;


    // We only honor requests that contain a valid auth_token.
    if (x != cgc_auth_token) {
        goto bail;
    } else {
    }

    // Okay we're authenticated.
    // y = the new function pointer
    // op = OP_MOD
    // nmb = the op index we're going to modify
    if (y == operations[OP_ADD] ||
        y == operations[OP_SUB] ||
        y == operations[OP_MUL] ||
        y == operations[OP_DIV]) {
        operations[nmb] = (funcptr_t)y;
    } else {
        path_goal();
        if (y == operations[OP_ADD]) {
          path_nongoal();
        }
    }

bail:

    return ret;
}



int cgc_negotiate(void) {

    int ret = SUCCESS;
    u_int32_t enckey_idx = 0;

    if (SUCCESS != (ret = cgc_recv_bytes(PIPE_RECV, (char *)&enckey_idx, sizeof(enckey_idx)))) {
        goto bail;
    }

bail:
    return ret;
}



int main() {
    path_start();

    int ret = SUCCESS;
    msg req;
    // This by itself (practically the only thing in the function) found goal in 258 seconds.
    int rand_value = INT_RAND;

    // Do initial setup things.
    if (SUCCESS != (ret = cgc_negotiate())) {
        ret = ERRNO_KEY_EXCHANGE;
        goto bail;
    }

    // On 64-bit builds, we get the following warning:
    // warning: cast to pointer from integer of different size [-Wint-to-pointer-cast]
    req.y = (funcptr_t)((intptr_t)rand_value);
    req.x = cgc_auth_token;
    req.nmb = CHAR_RAND;
    cgc_op_mod(req.x, (int*)req.y, req.nmb);
    goto bail;

bail:
    return ret;
}

