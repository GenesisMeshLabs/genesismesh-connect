/* Run on an Apple host: validates SDK ABI and output bounds, not iPhone DNS. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

int n0_read_ios_dns(char *, size_t);

int main(void) {
    struct { unsigned char before; char data[1]; unsigned char after; } tiny = {0xA5, {0}, 0x5A};
    assert(n0_read_ios_dns(NULL, 16) == -1);
    assert(n0_read_ios_dns(tiny.data, 0) == -1);
    assert(n0_read_ios_dns(tiny.data, sizeof(tiny.data)) == -1);
    assert(tiny.before == 0xA5 && tiny.after == 0x5A);
    for (int i = 0; i < 32; ++i) {
        struct { unsigned char before; char data[16384]; unsigned char after; } output;
        memset(&output, 0, sizeof(output));
        output.before = 0xA5;
        output.after = 0x5A;
        int length = n0_read_ios_dns(output.data, sizeof(output.data));
        assert(length > 0 && (size_t)length < sizeof(output.data));
        assert(output.data[length] == '\0');
        assert(output.before == 0xA5 && output.after == 0x5A);
        assert(strncmp(output.data, "server ", 7) == 0);
        assert(strstr(output.data, "\nndots ") != NULL);
    }
    puts("Apple host libresolv: configuration and buffer bounds passed; no DNS queries sent");
    return 0;
}
