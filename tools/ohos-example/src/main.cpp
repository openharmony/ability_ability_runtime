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
#include <vector>
#include <sstream>
#include <cstring>
#include <ctime>

// Constants for magic numbers
namespace {
    constexpr int PROGRESS_MAX = 100;
    constexpr int MIN_ARGC = 2;
}

void EmitProgress(int percentage, const std::string& status)
{
    std::cout << "{\"type\": \"progress\", "
              << "\"percentage\": " << percentage << ", "
              << "\"status\": \"" << status << "\""
              << "}" << std::endl;
}

void EmitRunResult(const std::string& result)
{
    std::cout << "{\"type\": \"result\", "
              << "\"status\": \"success\", "
              << "\"data\": {"
              << "\"result\": \"" << result << "\""
              << "}}"
              << "}" << std::endl;
}

void EmitVersionResult(const std::string& version, const std::string& buildTime)
{
    std::cout << "{\"type\": \"result\", "
              << "\"status\": \"success\", "
              << "\"data\": {"
              << "\"version\": \"" << version << "\", "
              << "\"build_time\": \"" << buildTime << "\""
              << "}}"
              << "}" << std::endl;
}

void EmitError(const std::string& errCode, const std::string& errMsg, const std::string& suggestion)
{
    std::cout << "{\"type\": \"result\", "
              << "\"status\": \"failed\", "
              << "\"errCode\": \"" << errCode << "\", "
              << "\"errMsg\": \"" << errMsg << "\", "
              << "\"suggestion\": \"" << suggestion << "\""
              << "}" << std::endl;
}

int RunCommand(const std::vector<std::string>& args)
{
    EmitProgress(0, "starting");

    std::string result = "执行完成";
    for (size_t i = 0; i < args.size(); i++) {
        if (i > 0 || !result.empty()) {
            result += " ";
        }
        result += args[i];

        int progress = static_cast<int>((i + 1) * PROGRESS_MAX / (args.size() + 1));
        EmitProgress(progress, "running");
    }

    EmitProgress(PROGRESS_MAX, "completed");
    EmitRunResult(result);

    return 0;
}

int VersionCommand()
{
    std::string version = "1.0.0";

    const char* buildTime = "2026-04-04 00:00:00";

    EmitVersionResult(version, buildTime);

    return 0;
}

void ShowHelp()
{
    std::cout << "Usage: ohos-example <subcommand> [args]" << std::endl;
    std::cout << "Subcommands:" << std::endl;
    std::cout << "  run [args...]     Run the tool with arguments" << std::endl;
    std::cout << "  version          Show version information" << std::endl;
    std::cout << "  help             Show this help message" << std::endl;
}

int main(int argc, char* argv[])
{
    if (argc < MIN_ARGC) {
        ShowHelp();
        return 1;
    }

    std::string subcommand = argv[1];

    if (subcommand == "run") {
        std::vector<std::string> args;
        for (int i = 2; i < argc; ++i) {
            args.push_back(argv[i]);
        }
        return RunCommand(args);
    } else if (subcommand == "version") {
        return VersionCommand();
    } else if (subcommand == "help" || subcommand == "--help" || subcommand == "-h") {
        ShowHelp();
        return 0;
    } else {
        ShowHelp();
        return 1;
    }

    return 0;
}
