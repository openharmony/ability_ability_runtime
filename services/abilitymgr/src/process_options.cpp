/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "process_options.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
const int NUMBER_ZERO = 0;
const int NUMBER_ONE = 1;
const int NUMBER_TWO = 2;
const int NUMBER_THREE = 3;

bool ProcessOptions::ReadFromParcel(Parcel &parcel)
{
    processMode = static_cast<ProcessMode>(parcel.ReadInt32());
    startupVisibility = static_cast<StartupVisibility>(parcel.ReadInt32());
    processName = parcel.ReadString();
    isRestartKeepAlive = parcel.ReadBool();
    isStartFromNDK = parcel.ReadBool();
    return true;
}

ProcessOptions *ProcessOptions::Unmarshalling(Parcel &parcel)
{
    ProcessOptions *option = new (std::nothrow) ProcessOptions();
    if (option == nullptr) {
        return nullptr;
    }

    if (!option->ReadFromParcel(parcel)) {
        delete option;
        option = nullptr;
    }

    return option;
}

bool ProcessOptions::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(processMode))) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ProcessMode write failed");
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(startupVisibility))) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "StartupVisibility write failed");
        return false;
    }
    if (!parcel.WriteString(processName)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ProcessName write failed");
        return false;
    }
    if (!parcel.WriteBool(isRestartKeepAlive)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "isRestartKeepAlive write failed");
        return false;
    }
    if (!parcel.WriteBool(isStartFromNDK)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "isStartFromNDK write failed");
        return false;
    }
    return true;
}

ProcessMode ProcessOptions::ConvertInt32ToProcessMode(int32_t value)
{
    if (value <= static_cast<int32_t>(ProcessMode::UNSPECIFIED) ||
        value >= static_cast<int32_t>(ProcessMode::END)) {
        return ProcessMode::UNSPECIFIED;
    }
    return static_cast<ProcessMode>(value);
}

ProcessMode ProcessOptions::ConvertStsToProcessMode(int32_t index)
{
    if (index < NUMBER_ZERO || index > NUMBER_TWO) {
        return ProcessMode::UNSPECIFIED;
    }
    return static_cast<ProcessMode>(index + NUMBER_ONE);
}
int32_t ProcessOptions::ConvertProcessModeToSts(const ProcessMode mode)
{
    int32_t value = static_cast<int32_t>(mode);
    if (value >= NUMBER_ONE && value <= NUMBER_THREE) {
        return value - NUMBER_ONE;
    }
    return static_cast<int32_t>(ProcessMode::NEW_PROCESS_ATTACH_TO_PARENT);
}

StartupVisibility ProcessOptions::ConvertInt32ToStartupVisibility(int32_t value)
{
    if (value <= static_cast<int32_t>(StartupVisibility::UNSPECIFIED) ||
        value >= static_cast<int32_t>(StartupVisibility::END)) {
        return StartupVisibility::UNSPECIFIED;
    }
    return static_cast<StartupVisibility>(value);
}

StartupVisibility ConvertStsToStartupVisibility(int32_t index)
{
    if (index < NUMBER_ZERO || index > NUMBER_ONE) {
        return StartupVisibility::UNSPECIFIED;
    }
    return static_cast<StartupVisibility>(index);
}
int32_t ConvertStartupVisibilityToSts(const StartupVisibility value)
{
    if (value == StartupVisibility::STARTUP_HIDE) {
        return NUMBER_ZERO;
    } else if (value == StartupVisibility::STARTUP_SHOW) {
        return NUMBER_ONE;
    }
    return NUMBER_ZERO;
}

bool ProcessOptions::IsNewProcessMode(ProcessMode value)
{
    return (value == ProcessMode::NEW_PROCESS_ATTACH_TO_PARENT) ||
        (value == ProcessMode::NEW_PROCESS_ATTACH_TO_STATUS_BAR_ITEM);
}

bool ProcessOptions::IsAttachToStatusBarMode(ProcessMode value)
{
    return (value == ProcessMode::NEW_PROCESS_ATTACH_TO_STATUS_BAR_ITEM) ||
        (value == ProcessMode::ATTACH_TO_STATUS_BAR_ITEM);
}

bool ProcessOptions::IsValidProcessMode(ProcessMode value)
{
    return (value > ProcessMode::UNSPECIFIED) && (value < ProcessMode::END);
}

bool ProcessOptions::IsNoAttachmentMode(ProcessMode value)
{
    return (value == ProcessMode::NO_ATTACHMENT);
}

bool ProcessOptions::IsAttachToStatusBarItemMode(ProcessMode value)
{
    return (value == ProcessMode::ATTACH_TO_STATUS_BAR_ITEM);
}

bool ProcessOptions::IsNewHiddenProcessMode(ProcessMode value)
{
    return (value == ProcessMode::NEW_HIDDEN_PROCESS);
}
}  // namespace AAFwk
}  // namespace OHOS
