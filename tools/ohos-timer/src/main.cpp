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
#include <chrono>
#include <thread>
#include <cstdlib>
#include <cerrno>
#include <climits>

// Constants for magic numbers
namespace {
    constexpr int PROGRESS_PERCENTAGE_MAX = 100;
    constexpr int DEFAULT_INTERVAL = 1;
    constexpr int MIN_DURATION = 1;
    constexpr int MIN_INTERVAL = 1;
    constexpr int DURATION_PREFIX_LEN = 11;
    constexpr int INTERVAL_PREFIX_LEN = 11;
    constexpr int HELP_ARGC = 2;
    constexpr int ARG_PARSE_START_INDEX = 1;
}

struct TimerConfig {
    int duration = 0;
    int interval = DEFAULT_INTERVAL;
    bool showProgress = false;
    bool verbose = false;
};

void EmitProgress(int percentage, const std::string& status)
{
    std::cout << "{\"type\": \"progress\", "
              << "\"percentage\": " << percentage << ", "
              << "\"status\": \"" << status << "\""
              << "}" << std::endl;
}

void EmitResult(const std::string& status, int duration, int actualDuration)
{
    std::cout << "{\"type\": \"result\", "
              << "\"status\": \"" << status << "\", "
              << "\"data\": {"
              << "\"status\": \"" << status << "\", "
              << "\"duration\": " << duration << ", "
              << "\"actual_duration\": " << actualDuration
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

void ShowHelp()
{
    std::cout << "Usage: ohos-timer [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --duration=<sec>  Duration in seconds (required, minimum 1)" << std::endl;
    std::cout << "  --interval=<sec>  Progress update interval in seconds (optional, default 1)" << std::endl;
    std::cout << "  --progress        Enable progress events" << std::endl;
    std::cout << "  --verbose         Enable verbose output" << std::endl;
    std::cout << "  --help, -h        Show this help message" << std::endl;
}

bool ParseArguments(int argc, char* argv[], TimerConfig& config)
{
    for (int i = ARG_PARSE_START_INDEX; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg.find("--duration=") == 0) {
            std::string value = arg.substr(DURATION_PREFIX_LEN);
            char* end = nullptr;
            errno = 0;
            long val = std::strtol(value.c_str(), &end, 10);
            if (errno != 0 || end == value.c_str() || *end != '\0' || val < 0 || val > INT_MAX) {
                return false;
            }
            config.duration = static_cast<int>(val);
        } else if (arg.find("--interval=") == 0) {
            std::string value = arg.substr(INTERVAL_PREFIX_LEN);
            char* end = nullptr;
            errno = 0;
            long val = std::strtol(value.c_str(), &end, 10);
            if (errno != 0 || end == value.c_str() || *end != '\0' || val < 0 || val > INT_MAX) {
                return false;
            }
            config.interval = static_cast<int>(val);
        } else if (arg == "--progress") {
            config.showProgress = true;
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            ShowHelp();
            return false;
        }
    }
    return true;
}

bool ValidateArguments(const TimerConfig& config)
{
    if (config.duration < MIN_DURATION) {
        return false;
    }

    if (config.interval < MIN_INTERVAL) {
        return false;
    }

    if (config.interval > config.duration) {
        return false;
    }

    return true;
}

void UpdateProgress(int elapsed, int duration, int& lastPercentage)
{
    if (duration == 0) {
        return;
    }

    int percentage = static_cast<int>(
        (elapsed * PROGRESS_PERCENTAGE_MAX) / duration
    );

    if (percentage > lastPercentage && percentage > 0) {
        EmitProgress(percentage, "running");
        lastPercentage = percentage;
    }
}

int ExecuteTimer(const TimerConfig& config)
{
    auto startTime = std::chrono::steady_clock::now();
    int lastPercentage = -1;
    int elapsed = 0;

    if (config.showProgress) {
        EmitProgress(0, "starting");
    }

    while (elapsed < config.duration) {
        if (config.showProgress) {
            UpdateProgress(elapsed, config.duration, lastPercentage);
        }

        std::this_thread::sleep_for(std::chrono::seconds(config.interval));

        elapsed = static_cast<int>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - startTime
            ).count()
        );
    }

    if (config.showProgress) {
        EmitProgress(PROGRESS_PERCENTAGE_MAX, "completed");
    }
    EmitResult("success", config.duration, elapsed);

    return 0;
}

int main(int argc, char* argv[])
{
    TimerConfig config;

    if (argc < HELP_ARGC) {
        ShowHelp();
        return 1;
    }

    if (!ParseArguments(argc, argv, config)) {
        return 1;
    }

    if (config.duration == 0) {
        ShowHelp();
        return 1;
    }

    if (!ValidateArguments(config)) {
        return 1;
    }

    return ExecuteTimer(config);
}
