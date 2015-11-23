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
            app.h
            teleport.c
            modifier.c
            tcpip.c
            tun.c tun.h
            )

    target_link_libraries(teleport
            nl-3
            nl-route-3
            lua5.2
            )
endif (LUA_FOUND)

add_executable(pocksify
        app.h
        pocksify.c
        tun.c tun.h
        )

target_link_libraries(pocksify
        nl-3
        nl-route-3
        )

add_executable(tests
        tests.c
        tcpip.c
        )

target_link_libraries(tests
        tap
        )

enable_testing()
add_test(COMMAND ./tests)
