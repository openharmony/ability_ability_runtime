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

#include "mock_app_mgr_impl.h"

namespace OHOS {
namespace AppExecFwk {
int32_t MockAppMgrImpl::retGetAllRunningInstanceKeysByBundleName = 0;
std::vector<std::string> MockAppMgrImpl::retInstanceKeys;

MockAppMgrImpl::MockAppMgrImpl()
{}

MockAppMgrImpl::~MockAppMgrImpl()
{}

int32_t MockAppMgrImpl::GetAllRunningInstanceKeysByBundleName(const std::string &bundleName,
    std::vector<std::string> &instanceKeys, int32_t userId)
{
    instanceKeys = retInstanceKeys;
    return retGetAllRunningInstanceKeysByBundleName;
}
}  // namespace AppExecFwk
}  // namespace OHOS
