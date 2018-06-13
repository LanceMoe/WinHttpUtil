#ifndef WIN_HTTP_H
#define WIN_HTTP_H

#include <windows.h>

#include <array>
#include <bit>
#include <format>
#include <iostream>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

using std::array;
using std::regex;
using std::string;
using std::unordered_map;
using std::vector;
using std::wregex;
using std::wstring;

#include <cstdbool>
#include <cstdint>
#include <cstdlib>

using bool_t = int;
using word_t = unsigned long;
using dword_t = unsigned long;
using qword_t = unsigned long long;
using HeaderRecord = unordered_map<wstring, wstring>;

struct HttpResponse {
    /// <summary>
    /// HttpResponse constructor
    /// </summary>
    HttpResponse();

    /// <summary>
    /// Reset HTTP response
    /// </summary>
    void reset();

    /// <summary>
    /// Get header record(dict)
    /// </summary>
    /// <returns>HeaderRecord& header_record</returns>
    HeaderRecord& header_record();

    /// <summary>
    /// Get cookies from header (From Set-cookie)
    /// </summary>
    /// <returns>wstring cookies</returns>
    wstring cookies();

    string text;
    wstring header;
    DWORD status_code;
    DWORD content_length;
    string error;

private:
    HeaderRecord _header_record;
};

class HttpClient {
public:
    /// <summary>
    /// HttpClient constructor
    /// </summary>
    /// <param name="use_proxy"></param>
    HttpClient(bool_t use_proxy = FALSE) noexcept;

    /// <summary>
    /// HttpClient deconstructor
    /// </summary>
    ~HttpClient() noexcept;

    /// <summary>
    /// Set proxy
    /// </summary>
    /// <param name="proxy_host"></param>
    /// <param name="proxy_username"></param>
    /// <param name="proxy_password"></param>
    void set_proxy(const wstring& proxy_host, const wstring& proxy_username, const wstring& proxy_password);

    /// <summary>
    /// Whether to use proxy settings
    /// </summary>
    /// <param name="use_proxy"></param>
    void set_use_proxy(bool_t use_proxy);

    /// <summary>
    /// Set User-agent
    /// </summary>
    /// <param name="user_agent"></param>
    void set_user_agent(const wstring& user_agent);

    /// <summary>
    /// Get last error code
    /// </summary>
    /// <returns>dword_t last_error_code</returns>
    int last_error();

    /// <summary>
    /// Send HTTP request
    /// </summary>
    /// <param name="method">HTTP method(verb): GET, POST, PUT, PATCH, DELETE</param>
    /// <param name="url">HTTP url path</param>
    /// <param name="body">Request body</param>
    /// <param name="extra_header">Request header</param>
    /// <returns>HttpResponse response</returns>
    HttpResponse request(const wstring& method, const wstring& url, const string& body = "", const wstring& extra_header = L"");

    /// <summary>
    /// Send HTTP GET request
    /// </summary>
    /// <param name="url">HTTP url path</param>
    /// <param name="extra_header">Request header</param>
    /// <returns>HttpResponse response</returns>
    HttpResponse get(const wstring& url, const wstring& extra_header = L"");

    /// <summary>
    /// Send HTTP POST request
    /// </summary>
    /// <param name="url">HTTP url path</param>
    /// <param name="body">Request body</param>
    /// <param name="extra_header">Request header</param>
    /// <returns>HttpResponse response</returns>
    HttpResponse post(const wstring& url, const string& body, const wstring& extra_header = L"");

    /// <summary>
    /// Send HTTP PUT request
    /// </summary>
    /// <param name="url">HTTP url path</param>
    /// <param name="body">Request body</param>
    /// <param name="extra_header">Request header</param>
    /// <returns>HttpResponse response</returns>
    HttpResponse put(const wstring& url, const string& body, const wstring& extra_header = L"");

    /// <summary>
    /// Send HTTP PATCH request
    /// </summary>
    /// <param name="url">HTTP url path</param>
    /// <param name="body">Request body</param>
    /// <param name="extra_header">Request header</param>
    /// <returns>HttpResponse response</returns>
    HttpResponse patch(const wstring& url, const string& body, const wstring& extra_header = L"");

    /// <summary>
    /// Send HTTP DELETE request
    /// </summary>
    /// <param name="url">HTTP url path</param>
    /// <param name="body">Request body</param>
    /// <param name="extra_header">Request header</param>
    /// <returns>HttpResponse response</returns>
    HttpResponse delete_(const wstring& url, const string& body, const wstring& extra_header = L"");

private:
    bool_t _use_proxy;
    wstring _proxy_host;
    wstring _proxy_username;
    wstring _proxy_password;

    wstring _user_agent;
    dword_t _last_error_code;
    bool_t _check_valid_ssl;

    dword_t _resolve_timeout;
    dword_t _connect_timeout;
    dword_t _send_timeout;
    dword_t _receive_timeout;
};

/// <summary>
/// HttpClient instance with default config
/// </summary>
extern HttpClient http_client;

#endif