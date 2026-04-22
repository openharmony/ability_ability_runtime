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

#include "exec_options.h"

namespace OHOS {
namespace CliTool {
bool ExecOptions::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(background)) {
        return false;
    }
    if (!parcel.WriteInt32(yieldMs)) {
        return false;
    }
    if (!parcel.WriteInt32(timeout)) {
        return false;
    }
    if (!parcel.WriteUint32(static_cast<uint32_t>(env.size()))) {
        return false;
    }
    for (const auto &[key, value] : env) {
        if (!parcel.WriteString(key)) {
            return false;
        }
        if (!parcel.WriteString(value)) {
            return false;
        }
    }
    if (!parcel.WriteString(workingDir)) {
        return false;
    }
    return true;
}

ExecOptions *ExecOptions::Unmarshalling(Parcel &parcel)
{
    auto *options = new (std::nothrow) ExecOptions();
    if (options && !parcel.ReadBool(options->background)) {
        delete options;
        return nullptr;
    }
    if (!parcel.ReadInt32(options->yieldMs)) {
        delete options;
        return nullptr;
    }
    if (!parcel.ReadInt32(options->timeout)) {
        delete options;
        return nullptr;
    }
    uint32_t envSize = 0;
    if (!parcel.ReadUint32(envSize)) {
        delete options;
        return nullptr;
    }
    for (uint32_t i = 0; i < envSize; i++) {
        std::string key;
        std::string value;
        if (!parcel.ReadString(key)) {
            delete options;
            return nullptr;
        }
        if (!parcel.ReadString(value)) {
            delete options;
            return nullptr;
        }
        options->env[key] = value;
    }
    if (!parcel.ReadString(options->workingDir)) {
        delete options;
        return nullptr;
    }
    return options;
}
} // namespace CliTool
} // namespace OHOS