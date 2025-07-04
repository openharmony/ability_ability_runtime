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

#include "extensionconfig_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "ability_record.h"
#define private public
#include "extension_config.h"
#define private public

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

bool DoSomethingInterestingWithMyAPI(const char *data, size_t size)
{
    std::string strParam(data, size);
    auto extensionConfig = std::make_shared<ExtensionConfig>();
    extensionConfig->LoadExtensionConfiguration();
    extensionConfig->GetExtensionAutoDisconnectTime(strParam);
    extensionConfig->IsExtensionStartThirdPartyAppEnable(strParam);
    extensionConfig->IsExtensionStartServiceEnable(strParam, strParam);
    extensionConfig->HasAbilityAccess(strParam);
    extensionConfig->HasThridPartyAppAccessFlag(strParam);
    extensionConfig->HasServiceAccessFlag(strParam);
    extensionConfig->HasDefaultAccessFlag(strParam);
    extensionConfig->IsExtensionStartServiceEnableNew(strParam, strParam);
    extensionConfig->IsExtensionStartThirdPartyAppEnableNew(strParam, strParam);
    extensionConfig->IsExtensionStartDefaultEnable(strParam, strParam);
    nlohmann::json object;
    extensionConfig->LoadExtensionConfig(object);
    extensionConfig->ReadFileInfoJson(strParam, object);
    extensionConfig->GetExtensionConfigPath();
    extensionConfig->LoadExtensionAutoDisconnectTime(object, strParam);
    extensionConfig->LoadExtensionThirdPartyAppBlockedList(object, strParam);
    extensionConfig->LoadExtensionServiceBlockedList(object, strParam);
    extensionConfig->LoadExtensionAbilityAccess(object, strParam);
    extensionConfig->CheckExtensionUriValid(strParam);
    extensionConfig->LoadExtensionNetworkEnable(object, strParam);
    extensionConfig->LoadExtensionSAEnable(object, strParam);
    extensionConfig->IsExtensionNetworkEnable(strParam);
    extensionConfig->IsExtensionSAEnable(strParam);
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