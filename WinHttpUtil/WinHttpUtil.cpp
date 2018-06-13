#include "winhttputil.h"
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <format>

constexpr const wchar_t DEFAULT_USER_AGENT[] = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.50";

/// HttpResponse

HttpResponse::HttpResponse() : text(""), header(L""), error(""),
status_code(0), content_length(0),
_header_record({ }) { }


void HttpResponse::reset() {
    text = "";
    header = L"";
    status_code = 0;
    error = "";
    _header_record.clear();
    content_length = 0;
}


HeaderRecord& HttpResponse::header_record() {
    if (!_header_record.empty()) {
        return _header_record;
    }

    bool return_carriage_reached = false;
    bool colon_reached = false;
    bool colon_just_reached = false;
    std::wstring key;
    std::wstring value;
    for (size_t i = 0; i < header.size(); ++i) {
        const wchar_t ch = header.at(i);
        if (ch == L':') {
            colon_reached = true;
            colon_just_reached = true;
            continue;
        } else if (ch == L'\r') {
            return_carriage_reached = true;
        } else if (ch == L'\n' && !return_carriage_reached) {
            return_carriage_reached = true;
        } else if (ch == L'\n' && return_carriage_reached) {
            return_carriage_reached = false;
            continue;
        }

        if (return_carriage_reached) {
            if (!key.empty() && !value.empty()) {
                _header_record[key] = value;
            }

            key.clear();
            value.clear();
            colon_reached = false;
            if (ch == L'\n') {
                return_carriage_reached = false;
            }

            continue;
        }

        if (colon_reached == false) {
            key += ch;
        } else {
            if (colon_just_reached) {
                colon_just_reached = false;
                if (ch == L' ') {
                    continue;
                }
            }
            value += ch;
        }
    }

    if (!key.empty() && !value.empty()) {
        _header_record[key] = value;
    }

    return _header_record;
}


wstring HttpResponse::cookies() {
    wstring result = L"Cookie: ";

    auto header_copy = header;
    wregex pattern(L"Set-Cookie: (.*)");
    std::pmr::wsmatch match;

    while (std::regex_search(header_copy, match, pattern)) {
        result += match[1];
        result += L"; ";
        header_copy = match.suffix();
    }

    return result;
}

/// HttpClient


HttpClient::HttpClient(bool_t use_proxy) noexcept : _use_proxy(use_proxy), _proxy_host(L""), _proxy_username(L""), _proxy_password(L""),
_user_agent(DEFAULT_USER_AGENT), _check_valid_ssl(FALSE), _last_error_code(0),
_resolve_timeout(0), _connect_timeout(60000), _send_timeout(30000), _receive_timeout(30000) { }


HttpClient::~HttpClient() noexcept { }


void HttpClient::set_proxy(const wstring& proxy_host, const wstring& proxy_username, const wstring& proxy_password) {
    _proxy_host = proxy_host;
    _proxy_username = proxy_username;
    _proxy_password = proxy_password;
}


void HttpClient::set_use_proxy(bool_t use_proxy) {
    _use_proxy = use_proxy;
}


void HttpClient::set_user_agent(const wstring& user_agent) {
    _user_agent = user_agent;
}


int HttpClient::last_error() {
    return _last_error_code;
}


HttpResponse HttpClient::request(const wstring& method, const wstring& url, const string& body, const wstring& extra_header) {
    HttpResponse response;

    HINTERNET session_handle = nullptr;
    HINTERNET connect_handle = nullptr;
    HINTERNET request_handle = nullptr;

    // 检查 url
    if (url == L"") {
        _last_error_code = ERROR_PATH_NOT_FOUND;
        return response;
    }

    if (method == L"") {
        _last_error_code = ERROR_INVALID_PARAMETER;
        return response;
    }

    session_handle = WinHttpOpen(_user_agent.c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (session_handle == nullptr) {
        _last_error_code = GetLastError();
        return response;
    }

    WinHttpSetTimeouts(session_handle, _resolve_timeout, _connect_timeout, _send_timeout, _receive_timeout);

    array<wchar_t, MAX_PATH> host_name_buf {0};
    array<wchar_t, MAX_PATH * 8> url_path_buf {0};

    URL_COMPONENTS url_comp;

    memset(&url_comp, 0, sizeof(url_comp));
    url_comp.dwStructSize = sizeof(url_comp);
    url_comp.lpszHostName = host_name_buf.data();
    url_comp.dwHostNameLength = host_name_buf.max_size();
    url_comp.lpszUrlPath = url_path_buf.data();
    url_comp.dwUrlPathLength = url_path_buf.max_size();
    url_comp.dwSchemeLength = 1; // None zero

    try {
        if (!WinHttpCrackUrl(url.c_str(), url.length(), 0, &url_comp)) {
            throw std::runtime_error("WinHttpCrackUrl Failed!");
        }

        connect_handle = WinHttpConnect(session_handle, host_name_buf.data(), url_comp.nPort, 0);

        if (!connect_handle) {
            throw std::runtime_error("WinHttpConnect Failed!");
        }

        const dword_t open_request_flag = (url_comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        request_handle = WinHttpOpenRequest(connect_handle,
            method.c_str(),
            url_comp.lpszUrlPath,
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            open_request_flag);

        if (!request_handle) {
            throw std::runtime_error("WinHttpOpenRequest Failed!");
        }

        // If HTTPS, then client is very susceptable to invalid certificates
        // Easiest to accept anything for now
        if (!_check_valid_ssl && url_comp.nScheme == INTERNET_SCHEME_HTTPS) {
            constexpr dword_t options = SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;

            WinHttpSetOption(request_handle,
                WINHTTP_OPTION_SECURITY_FLAGS,
                const_cast<dword_t*>(&options),
                sizeof(dword_t));
        }

        // Not allow redirect
        constexpr dword_t options = WINHTTP_DISABLE_REDIRECTS;
        WinHttpSetOption(request_handle,
            WINHTTP_OPTION_DISABLE_FEATURE,
            const_cast<dword_t*>(&options),
            sizeof(dword_t));

        wstring header;
        if (body.length() > 0) {
            header = std::format(L"Content-Length: {}\r\n", body.length());
        }
        if (extra_header == L"" || extra_header.find(L"Content-Type: application/json") == -1) {
            header += L"Content-Type: application/x-www-form-urlencoded\r\n";
        }
        header += std::format(L"Referer: {}\r\n", url);
        header += extra_header + L"\r\n";

        if (!WinHttpAddRequestHeaders(request_handle, header.c_str(), header.length(), WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON)) {
            _last_error_code = GetLastError();
        }

        WINHTTP_PROXY_INFO proxy_info;
        if (_use_proxy) {
            memset(&proxy_info, 0, sizeof(proxy_info));
            proxy_info.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
            proxy_info.lpszProxy = const_cast<wchar_t*>(_proxy_host.c_str());
            if (!WinHttpSetOption(request_handle, WINHTTP_OPTION_PROXY, &proxy_info, sizeof(proxy_info))) {
                _last_error_code = GetLastError();
            }
            if (_proxy_username != L"") {
                if (!WinHttpSetOption(request_handle, WINHTTP_OPTION_PROXY_USERNAME, const_cast<wchar_t*>(_proxy_username.c_str()), _proxy_username.length())) {
                    _last_error_code = GetLastError();
                }
                if (_proxy_password != L"") {
                    if (!WinHttpSetOption(request_handle, WINHTTP_OPTION_PROXY_PASSWORD, const_cast<wchar_t*>(_proxy_password.c_str()), _proxy_password.length())) {
                        _last_error_code = GetLastError();
                    }
                }
            }
        }

        bool_t send_succeed = WinHttpSendRequest(request_handle,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            NULL);

        if (!send_succeed) {
            // Query the proxy information from IE setting and set the proxy if any.
            WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxy_config;
            memset(&proxy_config, 0, sizeof(proxy_config));
            if (WinHttpGetIEProxyConfigForCurrentUser(&proxy_config)) {
                if (proxy_config.lpszAutoConfigUrl != nullptr) {
                    WINHTTP_AUTOPROXY_OPTIONS auto_proxy_options = {
                        .dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT | WINHTTP_AUTOPROXY_CONFIG_URL,
                        .dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP,
                        .lpszAutoConfigUrl = proxy_config.lpszAutoConfigUrl,
                        .lpvReserved = nullptr,
                        .dwReserved = 0,
                        .fAutoLogonIfChallenged = TRUE,
                    };

                    memset(&proxy_info, 0, sizeof(proxy_info));

                    if (WinHttpGetProxyForUrl(session_handle, url.c_str(), &auto_proxy_options, &proxy_info)) {
                        if (WinHttpSetOption(request_handle, WINHTTP_OPTION_PROXY, &proxy_info, sizeof(proxy_info))) {
                            if (WinHttpSendRequest(request_handle,
                                WINHTTP_NO_ADDITIONAL_HEADERS,
                                0,
                                WINHTTP_NO_REQUEST_DATA,
                                0,
                                0,
                                NULL)) {
                                send_succeed = TRUE;
                            }
                        }
                        if (proxy_info.lpszProxy != nullptr) {
                            GlobalFree(proxy_info.lpszProxy);
                        }
                        if (proxy_info.lpszProxyBypass != nullptr) {
                            GlobalFree(proxy_info.lpszProxyBypass);
                        }
                    } else {
                        _last_error_code = GetLastError();
                    }
                } else if (proxy_config.lpszProxy != nullptr) {
                    memset(&proxy_info, 0, sizeof(proxy_info));
                    proxy_info.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                    proxy_info.lpszProxy = proxy_config.lpszProxy;

                    if (proxy_config.lpszProxyBypass != nullptr) {
                        proxy_info.lpszProxyBypass = proxy_config.lpszProxyBypass;
                    }

                    if (!WinHttpSetOption(request_handle, WINHTTP_OPTION_PROXY, &proxy_info, sizeof(proxy_info))) {
                        _last_error_code = GetLastError();
                    }
                }
                if (proxy_config.lpszAutoConfigUrl != nullptr) {
                    GlobalFree(proxy_config.lpszAutoConfigUrl);
                }
                if (proxy_config.lpszProxy != nullptr) {
                    GlobalFree(proxy_config.lpszProxy);
                }
                if (proxy_config.lpszProxyBypass != nullptr) {
                    GlobalFree(proxy_config.lpszProxyBypass);
                }
            } else {
                _last_error_code = GetLastError();
            }
        }
        if (!send_succeed) {
            throw std::runtime_error("WinHttpSendRequest Failed!");
        }

        dword_t written_size = 0;
        if (body.length() > 0 && !WinHttpWriteData(request_handle,
            body.c_str(),
            body.length(),
            &written_size)) {

            _last_error_code = GetLastError();
        }
        if (!WinHttpReceiveResponse(request_handle, nullptr)) {
            throw std::runtime_error("WinHttpReceiveResponse Failed!");
        }

        // Get http status code
        dword_t remaining_read_size = 0;
        bool_t succeed = WinHttpQueryHeaders(request_handle,
            WINHTTP_QUERY_STATUS_CODE,
            WINHTTP_HEADER_NAME_BY_INDEX,
            nullptr,
            &remaining_read_size,
            WINHTTP_NO_HEADER_INDEX);

        if (succeed || (!succeed && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))) {
            remaining_read_size = sizeof(response.status_code);
            WinHttpQueryHeaders(request_handle,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &response.status_code,
                &remaining_read_size,
                WINHTTP_NO_HEADER_INDEX);
        }

        // Get response header
        remaining_read_size = 0;
        succeed = WinHttpQueryHeaders(request_handle,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            WINHTTP_HEADER_NAME_BY_INDEX,
            NULL,
            &remaining_read_size,
            WINHTTP_NO_HEADER_INDEX);

        if (succeed || (!succeed && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))) {
            // Allocate memory for the buffer.
            response.header.resize(remaining_read_size + 1);

            // Now, use WinHttpQueryHeaders to retrieve the header.
            succeed = WinHttpQueryHeaders(request_handle,
                WINHTTP_QUERY_RAW_HEADERS_CRLF,
                WINHTTP_HEADER_NAME_BY_INDEX,
                response.header.data(),
                &remaining_read_size,
                WINHTTP_NO_HEADER_INDEX);
        }

        do {
            remaining_read_size = 0;
            if (WinHttpQueryDataAvailable(request_handle, &remaining_read_size)) {
                vector<char> read_buf(remaining_read_size + 1, 0);

                dword_t read_size = 0;
                if (WinHttpReadData(request_handle,
                    read_buf.data(),
                    remaining_read_size,
                    &read_size)) {
                    response.text += read_buf.data();
                    response.content_length += read_size;
                }
            }
        } while (remaining_read_size > 0);

    } catch (std::exception const& error) {
        response.error = error.what();
    }
    if (request_handle) {
        WinHttpCloseHandle(request_handle);
    }
    if (connect_handle) {
        WinHttpCloseHandle(connect_handle);
    }
    if (session_handle) {
        WinHttpCloseHandle(session_handle);
    }
    return response;
}


HttpResponse HttpClient::get(const wstring& url, const wstring& extra_header) {
    return request(L"GET", url, "", extra_header);
}


HttpResponse HttpClient::post(const wstring& url, const string& body, const wstring& extra_header) {
    return request(L"POST", url, body, extra_header);
}



HttpResponse HttpClient::put(const wstring& url, const string& body, const wstring& extra_header) {
    return request(L"PUT", url, body, extra_header);
}


HttpResponse HttpClient::patch(const wstring& url, const string& body, const wstring& extra_header) {
    return request(L"PATCH", url, body, extra_header);
}


HttpResponse HttpClient::delete_(const wstring& url, const string& body, const wstring& extra_header) {
    return request(L"DELETE", url, body, extra_header);
}

HttpClient http_client;
