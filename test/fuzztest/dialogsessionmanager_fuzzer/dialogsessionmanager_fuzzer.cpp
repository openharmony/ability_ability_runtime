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

#include "dialogsessionmanager_fuzzer.h"
#include <cstddef>
#include <cstdint>
#define private public
#include "dialog_session_manager.h"
#undef private
#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr int INPUT_ZERO = 0;
constexpr int INPUT_ONE = 1;
constexpr int INPUT_TWO = 2;
constexpr int INPUT_THREE = 3;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t OFFSET_ZERO = 24;
constexpr size_t OFFSET_ONE = 16;
constexpr size_t OFFSET_TWO = 8;
constexpr uint8_t ENABLE = 2;
} // namespace

uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[INPUT_ZERO] << OFFSET_ZERO) | (ptr[INPUT_ONE] << OFFSET_ONE) | (ptr[INPUT_TWO] << OFFSET_TWO) |
        ptr[INPUT_THREE];
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

bool DoSomethingInterestingWithMyAPI(const char *data, size_t size)
{
    std::string bundleName(data, size);
    std::string dialogSessionId(data, size);
    std::string replaceWant(data, size);
    bool isSelector = *data % ENABLE;
    AAFwk::WantParams wantParams;
    int32_t int32Param = static_cast<int32_t>(GetU32Data(data));
    AbilityRequest abilityRequest;
    std::vector<DialogAppInfo> dialogAppInfos;
    std::vector<DialogAbilityInfo> targetAbilityInfos;
    sptr<IRemoteObject> callerToken = GetFuzzAbilityToken();
    Parcel wantParcel;
    Want want;
    auto dialogSessionInfo = std::make_shared<DialogSessionInfo>();
    if (dialogSessionInfo == nullptr) {
        return false;
    }
    std::shared_ptr<DialogCallerInfo> dialogCallerInfo = std::make_shared<DialogCallerInfo>();
    if (dialogCallerInfo == nullptr) {
        return false;
    }
    std::shared_ptr<DialogSessionManager> dialogSessionManager = std::make_shared<DialogSessionManager>();
    if (dialogSessionManager == nullptr) {
        return false;
    }
    dialogSessionManager->GenerateDialogSessionId();
    dialogSessionManager->SetStartupSessionInfo(dialogSessionId, abilityRequest);
    DialogAbilityInfo callerAbilityInfo;
    dialogSessionManager->GenerateCallerAbilityInfo(abilityRequest, callerAbilityInfo);
    dialogSessionManager->GenerateSelectorTargetAbilityInfos(dialogAppInfos, targetAbilityInfos);
    SelectorType type = SelectorType::WITHOUT_SELECTOR;
    dialogSessionManager->GenerateDialogSessionRecordCommon(abilityRequest, int32Param, wantParams,
        dialogAppInfos, type, isSelector);
    type = SelectorType::IMPLICIT_START_SELECTOR;
    dialogSessionManager->GenerateDialogSessionRecordCommon(abilityRequest, int32Param, wantParams,
        dialogAppInfos, type, isSelector);
    type = SelectorType::APP_CLONE_SELECTOR;
    dialogSessionManager->GenerateDialogSessionRecordCommon(abilityRequest, int32Param, wantParams,
        dialogAppInfos, type, isSelector);
    type = SelectorType::INTERCEPTOR_SELECTOR;
    dialogSessionManager->GenerateDialogSessionRecordCommon(abilityRequest, int32Param, wantParams,
        dialogAppInfos, type, isSelector);
    dialogSessionManager->GenerateDialogCallerInfo(abilityRequest, int32Param, dialogCallerInfo, type, isSelector);
    dialogSessionManager->NotifySCBToRecoveryAfterInterception(dialogSessionId, abilityRequest);
    dialogSessionManager->CreateJumpModalDialog(abilityRequest, int32Param, want);
    dialogSessionManager->CreateImplicitSelectorModalDialog(abilityRequest, want, int32Param, dialogAppInfos);
    dialogSessionManager->CreateCloneSelectorModalDialog(abilityRequest, want, int32Param, dialogAppInfos,
        replaceWant);
    dialogSessionManager->CreateModalDialogCommon(want, callerToken, dialogSessionId);
    dialogSessionManager->HandleErmsResult(abilityRequest, int32Param, want);
    dialogSessionManager->HandleErmsResultBySCB(abilityRequest, want);
    dialogSessionManager->IsCreateCloneSelectorDialog(bundleName, int32Param);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        std::cout << "invalid data" << std::endl;
        return 0;
    }

    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char *ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}