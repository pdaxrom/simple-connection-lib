#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "../src/base64.h"
#include "../src/getrandom.h"
#include "../src/logging.h"

static void test_base64_encode_decode(void **state) {
    (void) state;
    const char *input = "Hello World";
    size_t out_len;
    unsigned char *encoded = simple_connection_base64_encode((const unsigned char *)input, strlen(input), &out_len);
    assert_non_null(encoded);
    unsigned char *decoded = simple_connection_base64_decode(encoded, out_len, &out_len);
    assert_non_null(decoded);
    assert_string_equal((char *)decoded, input);
    free(encoded);
    free(decoded);
}

static void test_get_random(void **state) {
    (void) state;
    unsigned char buf[16];
    int ret = simple_connection_get_random(buf, sizeof(buf), 0);
    assert_int_equal(ret, sizeof(buf));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_base64_encode_decode),
        cmocka_unit_test(test_get_random),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
