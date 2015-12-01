cmake_minimum_required(VERSION 3.3)
project(pinetcchio)

find_package(Lua)

include_directories(SYSTEM
        /usr/include/libnl3
        )

if (LUA_FOUND)
    include_directories(
            ${LUA_INCLUDE_DIR}
    )

    add_executable(teleport
            teleport.c
            modifier.c
            tcpip.c
            tun.c
            rope.c)

    target_link_libraries(teleport
            nl-3
            nl-route-3
            lua5.2
            )
endif (LUA_FOUND)

add_executable(pocksify
        pocksify.c
        tun.c
        )

target_link_libraries(pocksify
        nl-3
        nl-route-3
        )

add_executable(tests
        tests.c
        tcpip.c
        )

add_executable(test_rope
        test_rope.c
        rope.c
        )

target_link_libraries(tests
        tap
        )

target_link_libraries(test_rope
        tap
        )


enable_testing()
add_test(COMMAND ./tests)
add_test(COMMAND ./test_rope)
