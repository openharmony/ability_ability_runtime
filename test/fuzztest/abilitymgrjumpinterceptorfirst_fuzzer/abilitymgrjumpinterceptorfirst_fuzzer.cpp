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

#include "abilitymgrjumpinterceptorfirst_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <functional>

#define private public
#include "interceptor/ability_jump_interceptor.h"
#include "bundle_mgr_helper.h"
#undef private

#include "securec.h"
#include "ability_record.h"
#include "want_params.h"
#include "ability_util.h"

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
constexpr size_t MAX_STR_LEN = 256;
}

uint32_t GetU32Data(const char* ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    return (ptr[INPUT_ZERO] << OFFSET_ZERO) | (ptr[INPUT_ONE] << OFFSET_ONE) |
           (ptr[INPUT_TWO] << OFFSET_TWO) | ptr[INPUT_THREE];
}

Want BuildFuzzWant(const char* data, size_t size)
{
    Want want;
    if (data == nullptr || size == 0) {
        return want;
    }
    std::string bundleName(data, size > MAX_STR_LEN ? MAX_STR_LEN : size);
    std::string abilityName(data + INPUT_THREE, size > INPUT_THREE + MAX_STR_LEN ?
        MAX_STR_LEN : size - INPUT_THREE);
    std::string uri(data + INPUT_TWO, size > INPUT_TWO + MAX_STR_LEN ?
        MAX_STR_LEN : size - INPUT_TWO);
    
    ElementName element(bundleName, abilityName, "entry");
    want.SetElement(element);
    want.SetUri(uri);
    want.SetBundle(bundleName);
    want.SetParam("isAtomicService", true);
    return want;
}

AppJumpControlRule BuildFuzzControlRule(const char* data, size_t size)
{
    AppJumpControlRule rule;
    if (data == nullptr || size == 0) {
        return rule;
    }
    rule.callerPkg = "callerPkg";
    rule.targetPkg = "targetPkg";
    uint32_t jumpModeMax = 2;
    rule.jumpMode = static_cast<AbilityJumpMode>(GetU32Data(data) % jumpModeMax);
    return rule;
}

AbilityInfo BuildFuzzAbilityInfo(const char* data, size_t size)
{
    AbilityInfo info;
    if (data == nullptr || size == 0) {
        return info;
    }
    uint32_t abilityTypeMax = static_cast<uint32_t>(AbilityType::EXTENSION);
    abilityTypeMax = (abilityTypeMax == 0) ? 1 : abilityTypeMax;
    info.type = static_cast<AbilityType>(GetU32Data(data) %
        static_cast<uint32_t>(AbilityType::EXTENSION));
    info.bundleName = "FuzzBundleName";
    info.name = "FuzzInfoName";
    info.applicationInfo.isSystemApp = true;
    info.applicationInfo.accessTokenId = static_cast<uint32_t>(GetU32Data(data));
    return info;
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

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    std::shared_ptr<AbilityJumpInterceptor> interceptor = std::make_shared<AbilityJumpInterceptor>();
    if (interceptor == nullptr) {
        return false;
    }

    std::string jsonStr = "jsonStr";
    Want want = BuildFuzzWant(data, size);
    int requestCode = static_cast<int>(GetU32Data(data));
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    bool isWithUI = (GetU32Data(data) % 2) == 1;
    sptr<IRemoteObject> callerToken = GetFuzzAbilityToken();
    static auto shouldBlockFunc = []() { return false; };
    
    AbilityInterceptorParam param1(want, requestCode, userId, isWithUI, callerToken, shouldBlockFunc);
    auto abilityInfo = std::make_shared<AbilityInfo>(BuildFuzzAbilityInfo(data, size));
    AbilityInterceptorParam param2(want, requestCode, userId, isWithUI, callerToken, abilityInfo);
    
    std::shared_ptr<BundleMgrHelper> bundleMgrHelper = std::make_shared<BundleMgrHelper>();
    AppJumpControlRule controlRule = BuildFuzzControlRule(data, size);
    AbilityInfo targetAbilityInfo = BuildFuzzAbilityInfo(data, size);
    
    (void)interceptor->DoProcess(param1);
    (void)interceptor->DoProcess(param2);
    (void)interceptor->CheckControl(bundleMgrHelper, want, userId, controlRule);
    (void)interceptor->CheckIfJumpExempt(controlRule, userId);
    (void)interceptor->CheckIfExemptByBundleName(jsonStr, jsonStr, userId);
    (void)interceptor->LoadAppLabelInfo(want, controlRule, userId);
    
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        std::cout << "invalid data" << std::endl;
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
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