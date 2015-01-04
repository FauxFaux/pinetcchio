#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "app.h"

struct modifier {
    lua_State *lua;
};

static int l_send_packet(lua_State *lua) {
    enum direction direction = lua_toboolean(lua, 1) ? DIR_IN : DIR_OUT;
    unsigned int fd = lua_tounsigned(lua,
            lua_upvalueindex(DIR_IN == direction ? 1 : 2));
    size_t len = 0;
    const char *buf = lua_tolstring(lua, 2, &len);
    assert(buf);
    do_a_send((int)fd, buf, len);
    return 0;
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
    lua_getglobal(lua, "modify");

    lua_pushboolean(lua, direction);
    // TODO: annoying copy
    lua_pushlstring(lua, buf, (size_t)len);

    if (lua_pcall(lua, 2, 0, 0)) {
        int ip_header_length = (*buf & 0x0f) * 4;
        const char *tcp = buf + ip_header_length;
        printf("error: %s: %4ld %2d (%5d -> %5d): %s\n",
                DIR_IN == direction ? "<-" : "->",
                len,
                *(buf+9),                     // ip protocol
                ntohs(*(uint16_t*)tcp),       // src port
                ntohs(*(((uint16_t*)tcp)+4)),  // dest port
                lua_tostring(lua, -1)
                );
        lua_pop(lua, 1);
    }
}

