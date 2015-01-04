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

struct modifier *modifier_alloc() {
    struct modifier *ret = malloc(sizeof(struct modifier));
    assert(ret);

    ret->lua = luaL_newstate();
    luaL_openlibs(ret->lua);
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
        const char *prefix,
        char *buf,
        ssize_t len) {
    lua_State *const lua = modifier->lua;
    lua_getglobal(lua, "modify");

    // TODO: annoying copy
    lua_pushlstring(lua, buf, (size_t)len);

    if (lua_pcall(lua, 1, 0, 0)) {
        int ip_header_length = (*buf & 0x0f) * 4;
        const char *tcp = buf + ip_header_length;
        printf("error: %s: %4ld %2d (%5d -> %5d): %s\n", prefix, len,
                *(buf+9),                     // ip protocol
                ntohs(*(uint16_t*)tcp),       // src port
                ntohs(*(((uint16_t*)tcp)+4)),  // dest port
                lua_tostring(lua, -1)
                );
        lua_pop(lua, 1);
    }
}

