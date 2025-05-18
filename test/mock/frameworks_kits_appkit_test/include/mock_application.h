/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_MOCK_APPLICATION_H
#define MOCK_OHOS_ABILITY_RUNTIME_MOCK_APPLICATION_H

#include <gtest/gtest.h>
#include "ohos_application.h"

namespace OHOS {
namespace AppExecFwk {
class MockApplication : public OHOSApplication {
public:
    MockApplication();
    virtual ~MockApplication() = default;

    virtual void OnConfigurationUpdated(const Configuration& config);
    virtual void OnMemoryLevel(int level);
    virtual void OnForeground();
    virtual void OnBackground();
    virtual void OnStart();
    virtual void OnTerminate();
    virtual int32_t ScheduleChangeAppGcState(int32_t state, uint64_t tid = 0);

private:
    int level_ = 0;
    std::shared_ptr<Configuration> config_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // MOCK_OHOS_ABILITY_RUNTIME_MOCK_APPLICATION_H
