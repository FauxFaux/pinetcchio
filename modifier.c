#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "app.h"

struct modifier {
    lua_State *lua;
};

static int l_send_packet(lua_State *lua) {
    enum direction direction = lua_toboolean(lua, 1) ? DIR_IN : DIR_OUT;
    unsigned int fd = lua_tounsigned(lua,
            lua_upvalueindex(DIR_IN == direction ? 1 : 2));
    const char *buf = lua_touserdata(lua, 2);
    assert(buf);
    size_t len = *(uint16_t*)buf;
    do_a_send((int)fd, buf + sizeof(uint16_t), len);
    return 0;
}

static int l_set_byte(lua_State *lua) {
    char *buf = lua_touserdata(lua, 1);
    assert(buf);
    uint32_t offset = lua_tounsigned(lua, 2);
    uint32_t value = lua_tounsigned(lua, 3);

    size_t len = *(uint16_t*)buf;
    if (offset > len) {
        return luaL_error(lua, "offset %u beyond length of frame (%u)", offset, len);
    }

    if (value > 0xff) {
        return luaL_error(lua, "%u is too big for a byte", value);
    }

    buf[sizeof(uint16_t) + offset] = value;

    return 0;
}

static int l_get_len(lua_State *lua) {
    char *buf = lua_touserdata(lua, 1);
    assert(buf);
    uint32_t len = *(uint16_t*)buf;
    lua_pushunsigned(lua, len);
    return 1;
}

struct modifier *modifier_alloc(int in_fd, int out_fd) {
    struct modifier *ret = malloc(sizeof(struct modifier));
    assert(ret);

    ret->lua = luaL_newstate();
    luaL_openlibs(ret->lua);

    lua_pushunsigned(ret->lua, in_fd);
    lua_pushunsigned(ret->lua, out_fd);
    lua_pushcclosure(ret->lua, &l_send_packet, 2);
    lua_setglobal(ret->lua, "send_packet");

    lua_pushcfunction(ret->lua, &l_set_byte);
    lua_setglobal(ret->lua, "set_byte");

    lua_pushcfunction(ret->lua, &l_get_len);
    lua_setglobal(ret->lua, "get_len");

    if (luaL_dofile(ret->lua, "modifier.lua")) {
        printf("problem loading script: %s", lua_tostring(ret->lua, -1));
        lua_pop(ret->lua, 1);
        return NULL;
    }
    assert(ret->lua);
    return ret;
}

void modifier_free(struct modifier *modifier) {
    if (NULL == modifier) {
        return;
    }
    lua_close(modifier->lua);
    free(modifier);
}

void packet_seen(
        struct modifier *const modifier,
        enum direction direction,
        char *buf,
        ssize_t len) {
    lua_State *const lua = modifier->lua;
    lua_getglobal(lua, "packet_seen");

    lua_pushboolean(lua, direction);
    lua_pushlightuserdata(lua, buf);

    if (lua_pcall(lua, 2, 0, 0)) {
        int ip_header_length = (*buf & 0x0f) * 4;
        const char *tcp = buf + ip_header_length;
        printf("error: %s: %4ld %2d (%5d -> %5d): %s\n",
                DIR_IN == direction ? "<-" : "->",
                len,
                *(buf+9),                     // ip protocol
                ntohs(*(uint16_t*)tcp),       // src port
                ntohs(*(((uint16_t*)tcp)+4)), // dest port
                lua_tostring(lua, -1)
                );
        lua_pop(lua, 1);
    }
}

