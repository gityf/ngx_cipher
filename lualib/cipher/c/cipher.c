#include <lua.h>
#include <lauxlib.h>
#include <string.h>

#include "md5.h"
#include "sha1.h"
#include "sha224.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"
#include "hmac.h"
#include "crc16.h"
#include "crc32.h"
#include "crc64.h"

static int l_md5(lua_State *L) {
  unsigned char out[MD5_DIGEST_SIZE] = {0};
  char hex_buf[MD5_DIGEST_SIZE*2+1] = {0};

  const char *in = luaL_checkstring(L, 1);
  luaL_Buffer buf;
  luaL_buffinit(L, &buf);

  MD5Calc(in, strlen(in), out);
  tohex(out, hex_buf, MD5_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, MD5_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_sha1(lua_State *L) {
  unsigned char out[SHA1_DIGEST_SIZE] = {0};
  char hex_buf[SHA1_DIGEST_SIZE*2+1] = {0};

  const char *in = luaL_checkstring(L, 1);
  luaL_Buffer buf;
  luaL_buffinit(L, &buf);

  SHA1Calc(in, strlen(in), out);
  tohex(out, hex_buf, SHA1_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, SHA1_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_sha224(lua_State *L) {
  unsigned char out[SHA224_DIGEST_SIZE] = {0};
  char hex_buf[SHA224_DIGEST_SIZE*2+1] = {0};

  const char *in = luaL_checkstring(L, 1);
  luaL_Buffer buf;
  luaL_buffinit(L, &buf);

  SHA224_Simple(in, strlen(in), out);
  tohex(out, hex_buf, SHA224_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, SHA224_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_sha256(lua_State *L) {
  unsigned char out[SHA256_DIGEST_SIZE] = {0};
  char hex_buf[SHA256_DIGEST_SIZE*2+1] = {0};

  const char *in = luaL_checkstring(L, 1);
  luaL_Buffer buf;
  luaL_buffinit(L, &buf);

  SHA256_Simple(in, strlen(in), out);
  tohex(out, hex_buf, SHA256_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, SHA256_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_sha384(lua_State *L) {
  unsigned char out[SHA384_DIGEST_SIZE] = {0};
  char hex_buf[SHA384_DIGEST_SIZE*2+1] = {0};

  const char *in = luaL_checkstring(L, 1);
  luaL_Buffer buf;
  luaL_buffinit(L, &buf);

  SHA384_Simple(in, strlen(in), out);
  tohex(out, hex_buf, SHA384_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, SHA384_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_sha512(lua_State *L) {
  unsigned char out[SHA512_DIGEST_SIZE] = {0};
  char hex_buf[SHA512_DIGEST_SIZE*2+1] = {0};

  const char *in = luaL_checkstring(L, 1);
  luaL_Buffer buf;
  luaL_buffinit(L, &buf);

  SHA512_Simple(in, strlen(in), out);
  tohex(out, hex_buf, SHA512_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, SHA512_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

/**
 * hmac
**/
static int l_hmac_md5(lua_State *L) {
  unsigned char out[MD5_DIGEST_SIZE] = {0};
  char hex_buf[MD5_DIGEST_SIZE*2+1] = {0};

  luaL_Buffer buf;
  luaL_buffinit(L, &buf);
  const char *in = luaL_checkstring(L, 1);
  const char *key = luaL_checkstring(L, 2);

  hmac_md5(key, strlen(key), in, strlen(in), out);
  tohex(out, hex_buf, MD5_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, MD5_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_hmac_sha1(lua_State *L) {
  unsigned char out[SHA1_DIGEST_SIZE] = {0};
  char hex_buf[SHA1_DIGEST_SIZE*2+1] = {0};

  luaL_Buffer buf;
  luaL_buffinit(L, &buf);
  const char *in = luaL_checkstring(L, 1);
  const char *key = luaL_checkstring(L, 2);

  hmac_sha1(key, strlen(key), in, strlen(in), out);
  tohex(out, hex_buf, SHA1_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, SHA1_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_hmac_sha224(lua_State *L) {
  unsigned char out[SHA224_DIGEST_SIZE] = {0};
  char hex_buf[SHA224_DIGEST_SIZE*2+1] = {0};

  luaL_Buffer buf;
  luaL_buffinit(L, &buf);
  const char *in = luaL_checkstring(L, 1);
  const char *key = luaL_checkstring(L, 2);

  hmac_sha224(key, strlen(key), in, strlen(in), out);
  tohex(out, hex_buf, SHA224_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, SHA224_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_hmac_sha256(lua_State *L) {
  unsigned char out[SHA256_DIGEST_SIZE] = {0};
  char hex_buf[SHA256_DIGEST_SIZE*2+1] = {0};

  luaL_Buffer buf;
  luaL_buffinit(L, &buf);
  const char *in = luaL_checkstring(L, 1);
  const char *key = luaL_checkstring(L, 2);

  hmac_sha256(key, strlen(key), in, strlen(in), out);
  tohex(out, hex_buf, SHA256_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, SHA256_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_hmac_sha384(lua_State *L) {
  unsigned char out[SHA384_DIGEST_SIZE] = {0};
  char hex_buf[SHA384_DIGEST_SIZE*2+1] = {0};

  luaL_Buffer buf;
  luaL_buffinit(L, &buf);
  const char *in = luaL_checkstring(L, 1);
  const char *key = luaL_checkstring(L, 2);

  hmac_sha384(key, strlen(key), in, strlen(in), out);
  tohex(out, hex_buf, SHA384_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, SHA384_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_hmac_sha512(lua_State *L) {
  unsigned char out[SHA512_DIGEST_SIZE] = {0};
  char hex_buf[SHA512_DIGEST_SIZE*2+1] = {0};

  luaL_Buffer buf;
  luaL_buffinit(L, &buf);
  const char *in = luaL_checkstring(L, 1);
  const char *key = luaL_checkstring(L, 2);

  hmac_sha512(key, strlen(key), in, strlen(in), out);
  tohex(out, hex_buf, SHA512_DIGEST_SIZE);

  luaL_addlstring(&buf, (void*)&hex_buf, SHA512_DIGEST_SIZE*2);
  luaL_pushresult(&buf);
  return 1;
}

static int l_crc16(lua_State *L) {
  const char *in = luaL_checkstring(L, 1);

  uint16_t out = crc16(in, strlen(in));

  lua_pushnumber(L, out);
  return 1;
}

static int l_crc32(lua_State *L) {
  const char *in = luaL_checkstring(L, 1);

  uint32_t out = crc32(in, strlen(in));
  lua_pushnumber(L, out);
  return 1;
}

// Creates a new longnumber and pushes it onto the statck
static uint64_t * lualongnumber_pushlong(lua_State *L, int64_t *val) {
  uint64_t *data = (uint64_t *)lua_newuserdata(L, sizeof(uint64_t)); // longnum
  luaL_getmetatable(L, "_ngx_long_numner");                          // longnum, mt
  lua_setmetatable(L, -2);                                            // longnum
  if (val) {
    *data = *val;
  }
  return data;
}

static int l_crc64(lua_State *L) {
  const char *in = luaL_checkstring(L, 1);

  uint64_t out = crc64(in, strlen(in));

  lualongnumber_pushlong(L, out);
  return 1;
}

static const struct luaL_Reg lua_cipher[] = {
  {"md5",    l_md5},
  {"sha1",   l_sha1},
  {"sha224", l_sha224},
  {"sha256", l_sha256},
  {"sha384", l_sha384},
  {"sha512", l_sha512},

  {"hmac_md5",    l_hmac_md5},
  {"hmac_sha1",   l_hmac_sha1},
  {"hmac_sha224", l_hmac_sha224},
  {"hmac_sha256", l_hmac_sha256},
  {"hmac_sha384", l_hmac_sha384},
  {"hmac_sha512", l_hmac_sha512},/*
  {"PKCS5_PBKDF2_HMAC",  l_PKCS5_PBKDF2_HMAC},
  {"PKCS5_PBKDF2_HMAC2", l_PKCS5_PBKDF2_HMAC2},
  {"PKCS5_PBKDF2_HMAC5", l_PKCS5_PBKDF2_HMAC5},*/

  //{"rc4", l_rc4},
  {"crc16", l_crc16},
  {"crc32", l_crc32},
  {"crc64", l_crc64},
  {NULL, NULL}
};

int luaopen_cipher(lua_State *L) {
  luaL_register(L, "cipher", lua_cipher);
  return 1;
}