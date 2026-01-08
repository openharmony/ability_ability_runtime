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

#include "kioskmanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "interceptor/kiosk_interceptor.h"
#include "kiosk_manager.h"
#undef private

#include "ability_auto_startup_data_manager.h"
#include "ability_fuzz_util.h"
#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
constexpr size_t ARRAY_MAX_LENGTH = 10;
}

sptr<Token> GetFuzzAbilityToken()
{
    sptr<Token> token = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.fuzzTest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::DATA;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (abilityRecord) {
        token = abilityRecord->GetToken();
    }
    return token;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto& kioskManager = KioskManager::GetInstance();
    AppInfo info;
    AbilityFuzzUtil::GetRandomKeepAliveAppInfo(fdp, info);
    std::vector<std::string> appList;
    appList = AbilityFuzzUtil::GenerateStringArray(fdp);
    sptr<IRemoteObject> token = GetFuzzAbilityToken();
    bool flag = fdp.ConsumeBool();
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    std::vector<DialogAppInfo> dialogAppInfos;
    DialogAppInfo dialogAppInfo;
    dialogAppInfo.abilityIconId = fdp.ConsumeIntegral<int32_t>();
    dialogAppInfo.abilityLabelId = fdp.ConsumeIntegral<int32_t>();
    dialogAppInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    dialogAppInfo.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    dialogAppInfo.visible = fdp.ConsumeBool();
    dialogAppInfo.isAppLink = fdp.ConsumeBool();
    dialogAppInfos.emplace_back(dialogAppInfo);
    KioskStatus kioskStatus;
    std::vector<AbilityInfo> abilityInfos;
    AbilityInfo abilityInfo;
    size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, ARRAY_MAX_LENGTH);
    for (size_t i = 0; i < arraySize; ++i) {
        AbilityFuzzUtil::GetRandomAbilityInfo(fdp, abilityInfo);
        abilityInfos.emplace_back(abilityInfo);
    }

    kioskManager.OnAppStop(info);
    kioskManager.UpdateKioskApplicationList(appList);
    kioskManager.EnterKioskMode(token);
    kioskManager.ExitKioskMode(token, flag);
    kioskManager.ExitKioskModeInner(bundleName, token, flag);
    kioskManager.GetKioskStatus(kioskStatus);
    kioskManager.FilterDialogAppInfos(dialogAppInfos);
    kioskManager.FilterDialogAppInfos(dialogAppInfos);
    kioskManager.FilterAbilityInfos(abilityInfos);
    kioskManager.IsInKioskMode();
    kioskManager.IsInWhiteList(bundleName);
    kioskManager.IsInKioskModeInner();
    kioskManager.IsKioskBundleUid(uid);
    kioskManager.NotifyKioskModeChanged(flag);
    kioskManager.IsInWhiteListInner(bundleName);
    kioskManager.GetEnterKioskModeCallback();
    kioskManager.GetExitKioskModeCallback();
    kioskManager.AddKioskInterceptor();
    kioskManager.RemoveKioskInterceptor();
    kioskManager.CheckCallerIsForeground(token);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}