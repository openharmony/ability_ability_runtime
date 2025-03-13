/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "bundle_mgr_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const int32_t ERR_OK = 0;
const std::string START_MSG_BUNDLE_NAME1 = "com.test.bundle1";
const std::string START_MSG_BUNDLE_NAME2 = "com.test.bundle2";
}

int32_t BundleMgrHelper::GetAppProvisionInfo(const std::string &bundleName, int32_t userId,
    AppExecFwk::AppProvisionInfo &appProvisionInfo)
{
    std::string jsonString;
    if (bundleName == START_MSG_BUNDLE_NAME1) {
        jsonString = R"({"com.huawei.service.sandboxmode.custom": "test"})";
    }
    if (bundleName == START_MSG_BUNDLE_NAME2) {
        jsonString = R"({"com.test.service.sandboxmode.custom": "test"})";
    }
    appProvisionInfo.appServiceCapabilities = jsonString;
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS