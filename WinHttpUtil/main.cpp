#include "WinHttpUtil.h"

#include <clocale>

const char post_data[] = R"({
    "foo": "bar",
    "hoge": "fuga",
    "users": ["lance", "ck19"]
})";

const wchar_t header[] = LR"(Content-Type: application/json
accept: application/json)";

int main() {
    using namespace std;

    cout << "Current locale is: " << setlocale(LC_ALL, "Chinese-simplified") << endl;

    const auto& resp = http_client.post(L"https://httpbin.org/post", post_data, header);

    if (resp.status_code == 200) {
        cout << resp.text << endl;
    } else {
        cout << resp.status_code << "\nerror: " << resp.error << endl;
    }

    getchar();
    return 0;
}