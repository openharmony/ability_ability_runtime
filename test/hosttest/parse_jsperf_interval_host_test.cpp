#include "parse_jsperf_interval.h"
#include <cassert>
#include <climits>
#include <cstdio>
#include <stdexcept>
#include <string>

static void ExpectOk(const char *s, int32_t want)
{
    int32_t out = 999;
    assert(ParseJsperfInterval(s, out));
    assert(out == want);
}

static void ExpectFail(const char *s)
{
    int32_t out = 42;
    assert(!ParseJsperfInterval(s, out));
}

static bool StoiThrows(const std::string &s)
{
    try {
        (void)std::stoi(s);
        return false;
    } catch (const std::out_of_range &) {
        return true;
    } catch (const std::invalid_argument &) {
        return true;
    }
}

int main()
{
    ExpectOk("0", 0);
    ExpectOk("1", 1);
    ExpectOk("42", 42);
    ExpectOk("2147483647", INT32_MAX);
    ExpectFail("");
    ExpectFail("-1");
    ExpectFail("12a");
    ExpectFail("a12");
    ExpectFail(" 1");
    ExpectFail("1 ");
    ExpectFail("2147483648");
    ExpectFail("9999999999");

    /* leftover: regex ^\s*(\d+).* then bare stoi on overflow */
    const std::string overflow(20, '9');
    assert(StoiThrows(overflow));
    ExpectFail(overflow.c_str());

    std::puts("parse_jsperf_interval_host_test OK");
    return 0;
}
