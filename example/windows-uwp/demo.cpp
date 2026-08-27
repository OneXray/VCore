#include "vcore.h"

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

class BridgeLock {
public:
  BridgeLock()
      : handle_(
            CreateMutexW(nullptr, FALSE, L"Local\\VCore.UwpDemo.Bridge.v1")) {
    if (handle_ == nullptr) {
      throw std::runtime_error("cannot create bridge lock");
    }
    const DWORD result = WaitForSingleObject(handle_, 30'000);
    if (result != WAIT_OBJECT_0 && result != WAIT_ABANDONED) {
      CloseHandle(handle_);
      handle_ = nullptr;
      throw std::runtime_error("another bridge command is still running");
    }
  }

  ~BridgeLock() {
    if (handle_ != nullptr) {
      ReleaseMutex(handle_);
      CloseHandle(handle_);
    }
  }

  BridgeLock(const BridgeLock &) = delete;
  BridgeLock &operator=(const BridgeLock &) = delete;

private:
  HANDLE handle_;
};

std::string read_config(const wchar_t *path) {
  std::ifstream input(std::filesystem::path(path), std::ios::binary);
  if (!input) {
    throw std::runtime_error("cannot open config file");
  }
  std::string config(std::istreambuf_iterator<char>(input), {});
  if (config.starts_with("\xEF\xBB\xBF")) {
    config.erase(0, 3);
  }
  return config;
}

std::string json_string(std::string_view value) {
  static constexpr char hex[] = "0123456789abcdef";
  std::string result;
  result.reserve(value.size() + 2);
  result.push_back('"');
  for (const unsigned char byte : value) {
    switch (byte) {
    case '"':
      result += "\\\"";
      break;
    case '\\':
      result += "\\\\";
      break;
    case '\b':
      result += "\\b";
      break;
    case '\f':
      result += "\\f";
      break;
    case '\n':
      result += "\\n";
      break;
    case '\r':
      result += "\\r";
      break;
    case '\t':
      result += "\\t";
      break;
    default:
      if (byte < 0x20) {
        result += "\\u00";
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0f]);
      } else {
        result.push_back(static_cast<char>(byte));
      }
    }
  }
  result.push_back('"');
  return result;
}

std::string request(int argc, wchar_t **argv) {
  if (argc == 2 && std::wstring_view(argv[1]) == L"environment") {
    return R"({"bridgeVersion":2,"method":"getEnvironment","payload":{}})";
  }
  if (argc == 2 && std::wstring_view(argv[1]) == L"status") {
    return R"({"bridgeVersion":2,"method":"getVpnStatus","payload":{}})";
  }
  if (argc == 2 && std::wstring_view(argv[1]) == L"stop") {
    return R"({"bridgeVersion":2,"method":"stopVpn","payload":{}})";
  }
  if (argc == 3 && std::wstring_view(argv[1]) == L"start") {
    return std::string(
               R"({"bridgeVersion":2,"method":"startVpn","payload":{"configYaml":)") +
           json_string(read_config(argv[2])) +
           R"(,"networkSettings":{"ipv4Address":"192.168.3.1","ipv6Address":"fd00::2","dnsIpv4Address":"223.5.5.5","dnsIpv6Address":"2400:3200::1"}}})";
  }
  throw std::runtime_error(
      "usage: vcore-uwp-demo.exe environment|status|stop|start <config.yaml>");
}

} // namespace

int wmain(int argc, wchar_t **argv) {
  SetConsoleOutputCP(CP_UTF8);
  try {
    const std::string input = request(argc, argv);
    const BridgeLock lock;
    char *raw = VCoreWindowsVpnInvoke(input.c_str());
    if (raw == nullptr) {
      std::cerr << "VCore returned no response\n";
      return 1;
    }
    const std::string response(raw);
    VCoreFree(raw);
    std::cout << response << '\n';
    return response.find("\"success\":true") == std::string::npos ? 1 : 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
}
