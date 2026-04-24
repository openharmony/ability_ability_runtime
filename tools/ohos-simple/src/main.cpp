// Copyright (c) 2025 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <iostream>
#include <string>
#include <cstdlib>

// Constants for magic numbers
namespace {
    constexpr int MESSAGE_PREFIX_LEN = 10;
    constexpr int COUNT_PREFIX_LEN = 8;
    constexpr int MAX_COUNT = 10;
    constexpr int MIN_COUNT = 1;
}

void EmitResult(const std::string& status, const std::string& message, int repeatCount)
{
    std::cout << "{\"event\": \"result\", \"data\": {"
              << "\"status\": \"" << status << "\", "
              << "\"message\": \"" << message << "\", "
              << "\"repeat_count\": " << repeatCount
              << "}}" << std::endl;
}

void ShowHelp()
{
    std::cout << "Usage: ohos-simple [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --message=<msg>  Set message to display (default: 'Hello from ohos-simple')" << std::endl;
    std::cout << "  --count=<num>    Number of repetitions (1-10, default: 1)" << std::endl;
    std::cout << "  --verbose        Enable verbose output" << std::endl;
    std::cout << "  --help, -h       Show this help message" << std::endl;
}

bool ParseArguments(int argc, char* argv[], std::string& message, int& count, bool& verbose)
{
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg.find("--message=") == 0) {
            message = arg.substr(MESSAGE_PREFIX_LEN);
        } else if (arg.find("--count=") == 0) {
            count = std::atoi(arg.substr(COUNT_PREFIX_LEN).c_str());
            if (count < MIN_COUNT) {
                count = MIN_COUNT;
            }
            if (count > MAX_COUNT) {
                count = MAX_COUNT;
            }
        } else if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            ShowHelp();
            return false;
        }
    }
    return true;
}

std::string ExecuteTask(const std::string& message, int count, bool verbose)
{
    std::string result;
    for (int i = 0; i < count; ++i) {
        if (i > 0) {
            result += " ";
        }
        result += message;
    }

    return result;
}

int main(int argc, char* argv[])
{
    std::string message = "Hello from ohos-simple";
    int count = 1;
    bool verbose = false;

    if (!ParseArguments(argc, argv, message, count, verbose)) {
        return 0;
    }

    if (message.empty()) {
        return 1;
    }

    std::string result = ExecuteTask(message, count, verbose);

    EmitResult("success", result, count);

    return 0;
}
