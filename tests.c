#include <tap.h>
#include "app.h"

#include "t/tcpip.c"

int main() {
    plan(1);

    test_tcpip();

    done_testing();
}
