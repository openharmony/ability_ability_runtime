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

#include "mock_want_utils.h"

#include "ability_util.h"
#include "in_process_call_wrapper.h"
#include "utils/app_mgr_util.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
constexpr int32_t CONVERT_CALLBACK_TIMEOUT_SECONDS = 2; // 2s
constexpr uint32_t TYPE_ATOMIC_SERVICE = 0;
constexpr uint32_t TYPE_APP = 1;
constexpr uint32_t TYPE_IS_SHORTURL = 2;
const std::string NOT_SHORTURL = "NOT_SHORTURL";
const std::string IS_SHORTURL = "IS_SHORTURL";
const std::string CONVERT_FAILED = "CONVERT_FAILED";
const std::string ATOMIC_SERVICE = "ATOMIC_SERVICE";
const std::string APP = "APP";

int32_t WantUtils::GetCallerBundleName(std::string &callerBundleName)
{
    TAG_LOGI(AAFwkTag::TEST, "Mock GetCallerBundleName");
    return ERR_OK;
}

int32_t WantUtils::ConvertToExplicitWant(Want &want, uint32_t &targetType)
{
    TAG_LOGI(AAFwkTag::TEST, "Mock ConvertToExplicitWant");
    int32_t retCode = ERR_OK;
    std::string url = want.GetUriString();
    if (url == CONVERT_FAILED) {
        return CHECK_PERMISSION_FAILED;
    }
    if (url == ATOMIC_SERVICE) {
        targetType = TYPE_ATOMIC_SERVICE;
    }
    if (url == APP) {
        targetType = TYPE_APP;
    }
    if (url == IS_SHORTURL) {
        targetType = TYPE_IS_SHORTURL;
    }
    return retCode;
}

bool WantUtils::IsShortUrl(const Want &want)
{
    TAG_LOGI(AAFwkTag::TEST, "Mock IsShortUrl");
    std::string url = want.GetUriString();
    bool isShortUrl = false;
    if (url != NOT_SHORTURL) {
        isShortUrl = true;
    }
    if (!isShortUrl) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "not short url");
    }
    return isShortUrl;
}

bool WantUtils::IsAtomicService(uint32_t targetType)
{
    TAG_LOGI(AAFwkTag::TEST, "Mock IsAtomicService, targetType %{public}d", targetType);
    return targetType == 0;
}

bool WantUtils::IsNormalApp(uint32_t targetType)
{
    TAG_LOGI(AAFwkTag::TEST, "Mock IsNormalApp, targetType %{public}d", targetType);
    return targetType == 1;
}
}  // namespace AAFwk
}  // namespace OHOS
