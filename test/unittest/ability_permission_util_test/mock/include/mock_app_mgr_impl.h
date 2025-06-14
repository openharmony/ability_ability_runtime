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

#ifndef OHOS_ABILITY_RUNTIME_MOCK_APP_MGR_IMPL_H
#define OHOS_ABILITY_RUNTIME_MOCK_APP_MGR_IMPL_H

#include "app_mgr_stub.h"

namespace OHOS {
namespace AppExecFwk {
class MockAppMgrImpl : public AppMgrStub {
public:
    static int32_t retGetAllRunningInstanceKeysByBundleName;
    static std::vector<std::string> retInstanceKeys;

    MockAppMgrImpl();

    ~MockAppMgrImpl();

    /**
     * GetAllRunningInstanceKeysByBundleName, call GetAllRunningInstanceKeysByBundleName() through proxy project.
     * Obtains running instance keys of multi-instance app that are running on the device.
     *
     * @param bundlename, bundle name in Application record.
     * @param instanceKeys, output instance keys of the multi-instance app.
     * @param userId, user id.
     * @return ERR_OK ,return back success，others fail.
     */
    virtual int32_t GetAllRunningInstanceKeysByBundleName(const std::string &bundleName,
        std::vector<std::string> &instanceKeys, int32_t userId = -1) override;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_MOCK_APP_MGR_IMPL_H
