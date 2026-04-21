/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_ABILITY_RUNTIME_TOOL_INFO_H
#define OHOS_ABILITY_RUNTIME_TOOL_INFO_H

#include "tool_summary.h"

#include <iremote_broker.h>
#include <iremote_object.h>
#include <map>
#include <memory>
#include <parcel.h>
#include <string>
#include <vector>

namespace OHOS {
namespace CliTool {
/**
 * @brief Raw data type for IDL serialization
 */
class ToolsRawData : public Parcelable {
public:
    std::vector<uint32_t> data;

    ToolsRawData() = default;
    ~ToolsRawData() = default;

    bool Marshalling(Parcel &parcel) const override
    {
        if (!parcel.WriteUInt32Vector(data)) {
            return false;
        }
        return true;
    }

    static ToolsRawData *Unmarshalling(Parcel &parcel)
    {
        ToolsRawData *rawdata = new (std::nothrow) ToolsRawData();
        if (rawdata && !parcel.ReadUInt32Vector(&rawdata->data)) {
            delete rawdata;
            return nullptr;
        }
        return rawdata;
    }
};

/**
 * @brief Tool information structure (full version)
 */
class ToolInfo : public Parcelable {
public:
    std::string name;
    std::string version;
    std::string description;
    std::string executablePath;
    std::vector<std::string> permissions;
    std::string inputSchema;       // JSON string
    std::string outputSchema;      // JSON string
    std::string argMapping;        // JSON string
    std::string eventSchemas;      // JSON string (map of event type to schema)
    int32_t timeout = 0;
    std::vector<std::string> eventTypes;
    int64_t registeredTime = 0;
    bool enabled = true;
    bool hasSubcommands = false;
    std::string subcommands;       // JSON string (map of subcommand name to SubCommandInfo)

    ToolInfo() = default;
    ~ToolInfo() = default;

    bool Marshalling(Parcel &parcel) const override;
    static ToolInfo *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Tool execution options
 */
class ExecOptions : public Parcelable {
public:
    bool background = false;       // true: async, false: sync with yieldMs timeout
    int32_t yieldMs = 30000;       // foreground wait timeout (only when background=false)
    int32_t timeout = 0;           // total execution timeout (0 = use tool default)
    std::map<std::string, std::string> env;
    std::string workingDir;

    ExecOptions() = default;
    ~ExecOptions() = default;

    bool Marshalling(Parcel &parcel) const override;
    static ExecOptions *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Tool execution result
 */
class ExecResult : public Parcelable {
public:
    int32_t exitCode = 0;
    std::string outputText;
    std::string errorText;
    int32_t signalNumber = 0;
    bool timedOut = false;
    int64_t executionTime = 0;

    ExecResult() = default;
    ~ExecResult() = default;

    bool Marshalling(Parcel &parcel) const override;
    static ExecResult *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Session information
 */
class SessionInfo : public Parcelable {
public:
    std::string sessionId;
    std::string toolName;
    std::string status;            // "running", "completed", "failed"
    int64_t startTime = 0;
    int64_t endTime = 0;
    std::shared_ptr<ExecResult> result;  // optional, only when status="completed"

    SessionInfo() = default;
    ~SessionInfo() = default;

    bool Marshalling(Parcel &parcel) const override;
    static SessionInfo *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Tool event (for async mode)
 */
class ToolEvent : public Parcelable {
public:
    std::string type;              // "stdout", "stderr", "exit", "error"
    std::string eventData;
    int32_t exitCode = 0;
    int64_t timestamp = 0;

    ToolEvent() = default;
    ~ToolEvent() = default;

    bool Marshalling(Parcel &parcel) const override;
    static ToolEvent *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Session status (for query)
 */
class SessionStatus : public Parcelable {
public:
    std::string sessionId;
    std::string toolName;
    std::string status;            // "running", "completed", "failed"
    int64_t startTime = 0;
    int64_t endTime = 0;
    std::shared_ptr<ExecResult> result;  // optional, only when status="completed"

    SessionStatus() = default;
    ~SessionStatus() = default;

    bool Marshalling(Parcel &parcel) const override;
    static SessionStatus *Unmarshalling(Parcel &parcel);
};
} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_TOOL_INFO_H
