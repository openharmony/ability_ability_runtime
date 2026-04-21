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

#include "tool_info.h"

namespace OHOS {
namespace CliTool {

// ToolInfo implementation
bool ToolInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(name) &&
           parcel.WriteString(version) &&
           parcel.WriteString(description) &&
           parcel.WriteString(executablePath) &&
           parcel.WriteStringVector(permissions) &&
           parcel.WriteString(inputSchema) &&
           parcel.WriteString(outputSchema) &&
           parcel.WriteString(argMapping) &&
           parcel.WriteString(eventSchemas) &&
           parcel.WriteInt32(timeout) &&
           parcel.WriteStringVector(eventTypes) &&
           parcel.WriteInt64(registeredTime) &&
           parcel.WriteBool(enabled) &&
           parcel.WriteBool(hasSubcommands) &&
           parcel.WriteString(subcommands);
}

ToolInfo *ToolInfo::Unmarshalling(Parcel &parcel)
{
    auto *tool = new (std::nothrow) ToolInfo();
    if (tool == nullptr) {
        return nullptr;
    }

    if (!parcel.ReadString(tool->name) ||
        !parcel.ReadString(tool->version) ||
        !parcel.ReadString(tool->description) ||
        !parcel.ReadString(tool->executablePath) ||
        !parcel.ReadStringVector(&tool->permissions) ||
        !parcel.ReadString(tool->inputSchema) ||
        !parcel.ReadString(tool->outputSchema) ||
        !parcel.ReadString(tool->argMapping) ||
        !parcel.ReadString(tool->eventSchemas) ||
        !parcel.ReadInt32(tool->timeout) ||
        !parcel.ReadStringVector(&tool->eventTypes) ||
        !parcel.ReadInt64(tool->registeredTime) ||
        !parcel.ReadBool(tool->enabled) ||
        !parcel.ReadBool(tool->hasSubcommands) ||
        !parcel.ReadString(tool->subcommands)) {
        delete tool;
        return nullptr;
    }

    return tool;
}

// ExecOptions implementation
bool ExecOptions::Marshalling(Parcel &parcel) const
{
    return parcel.WriteBool(background) &&
           parcel.WriteInt32(yieldMs) &&
           parcel.WriteInt32(timeout) &&
           parcel.WriteString(workingDir);
}

ExecOptions *ExecOptions::Unmarshalling(Parcel &parcel)
{
    auto *options = new (std::nothrow) ExecOptions();
    if (options == nullptr) {
        return nullptr;
    }

    if (!parcel.ReadBool(options->background) ||
        !parcel.ReadInt32(options->yieldMs) ||
        !parcel.ReadInt32(options->timeout) ||
        !parcel.ReadString(options->workingDir)) {
        delete options;
        return nullptr;
    }

    return options;
}

// ExecResult implementation
bool ExecResult::Marshalling(Parcel &parcel) const
{
    return parcel.WriteInt32(exitCode) &&
           parcel.WriteString(outputText) &&
           parcel.WriteString(errorText) &&
           parcel.WriteInt32(signalNumber) &&
           parcel.WriteBool(timedOut) &&
           parcel.WriteInt64(executionTime);
}

ExecResult *ExecResult::Unmarshalling(Parcel &parcel)
{
    auto *result = new (std::nothrow) ExecResult();
    if (result == nullptr) {
        return nullptr;
    }

    if (!parcel.ReadInt32(result->exitCode) ||
        !parcel.ReadString(result->outputText) ||
        !parcel.ReadString(result->errorText) ||
        !parcel.ReadInt32(result->signalNumber) ||
        !parcel.ReadBool(result->timedOut) ||
        !parcel.ReadInt64(result->executionTime)) {
        delete result;
        return nullptr;
    }

    return result;
}

// SessionInfo implementation
bool SessionInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(sessionId) &&
           parcel.WriteString(toolName) &&
           parcel.WriteString(status) &&
           parcel.WriteInt64(startTime) &&
           parcel.WriteInt64(endTime) &&
           parcel.WriteBool(result != nullptr) &&
           (result == nullptr || parcel.WriteParcelable(result.get()));
}

SessionInfo *SessionInfo::Unmarshalling(Parcel &parcel)
{
    auto *session = new (std::nothrow) SessionInfo();
    if (session == nullptr) {
        return nullptr;
    }

    bool hasResult = false;
    if (!parcel.ReadString(session->sessionId) ||
        !parcel.ReadString(session->toolName) ||
        !parcel.ReadString(session->status) ||
        !parcel.ReadInt64(session->startTime) ||
        !parcel.ReadInt64(session->endTime) ||
        !parcel.ReadBool(hasResult)) {
        delete session;
        return nullptr;
    }

    if (hasResult) {
        session->result.reset(ExecResult::Unmarshalling(parcel));
        if (session->result == nullptr) {
            delete session;
            return nullptr;
        }
    }

    return session;
}

// ToolEvent implementation
bool ToolEvent::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(type) &&
           parcel.WriteString(eventData) &&
           parcel.WriteInt32(exitCode) &&
           parcel.WriteInt64(timestamp);
}

ToolEvent *ToolEvent::Unmarshalling(Parcel &parcel)
{
    auto *event = new (std::nothrow) ToolEvent();
    if (event == nullptr) {
        return nullptr;
    }

    if (!parcel.ReadString(event->type) ||
        !parcel.ReadString(event->eventData) ||
        !parcel.ReadInt32(event->exitCode) ||
        !parcel.ReadInt64(event->timestamp)) {
        delete event;
        return nullptr;
    }

    return event;
}

// SessionStatus implementation
bool SessionStatus::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(sessionId) &&
           parcel.WriteString(toolName) &&
           parcel.WriteString(status) &&
           parcel.WriteInt64(startTime) &&
           parcel.WriteInt64(endTime) &&
           parcel.WriteBool(result != nullptr) &&
           (result == nullptr || parcel.WriteParcelable(result.get()));
}

SessionStatus *SessionStatus::Unmarshalling(Parcel &parcel)
{
    auto *status = new (std::nothrow) SessionStatus();
    if (status == nullptr) {
        return nullptr;
    }

    bool hasResult = false;
    if (!parcel.ReadString(status->sessionId) ||
        !parcel.ReadString(status->toolName) ||
        !parcel.ReadString(status->status) ||
        !parcel.ReadInt64(status->startTime) ||
        !parcel.ReadInt64(status->endTime) ||
        !parcel.ReadBool(hasResult)) {
        delete status;
        return nullptr;
    }

    if (hasResult) {
        status->result.reset(ExecResult::Unmarshalling(parcel));
        if (status->result == nullptr) {
            delete status;
            return nullptr;
        }
    }

    return status;
}
} // namespace CliTool
} // namespace OHOS
