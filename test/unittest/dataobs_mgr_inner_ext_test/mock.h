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

#ifndef UNITTEST_OHOS_ABILITY_RUNTIME_MOCK_DATA_ABILITY_OBSERVER_STUB_DATAOBS_MGR_INNER_EXT_TEST_H
#define UNITTEST_OHOS_ABILITY_RUNTIME_MOCK_DATA_ABILITY_OBSERVER_STUB_DATAOBS_MGR_INNER_EXT_TEST_H
#include <atomic>
#include "gmock/gmock.h"
#include "semaphore_ex.h"
#include "data_ability_observer_stub.h"
#include "event_handler.h"

namespace OHOS {
namespace DataObsMgrInnerTest {
class MockDataAbilityObserverStub : public AAFwk::DataAbilityObserverStub {
public:
    void OnChange()
    {
    }

    void OnChangeExt(std::list<Uri> uris)
    {
        onChangeCall_ += uris.size();
        uris_ = uris;
    }

    void ReSet()
    {
        onChangeCall_.store(0);
        uris_.clear();
    }
    //MOCK_METHOD0(OnChange, void());

    void Wait()
    {
        std::unique_lock<std::mutex> lck(mtx_);
        while (!flag_) {
            cv_.wait(lck);
        }
    }

    void Notify()
    {
        std::unique_lock<std::mutex> lck(mtx_);
        flag_ = true;
        cv_.notify_one();
    }

private:
    std::atomic_int onChangeCall_ = 0;
    std::list<Uri> uris_;
    std::mutex mtx_;
    std::condition_variable cv_;
    bool flag_ = false;
};

}  // namespace AAFwk
}  // namespace OHOS

#endif  // UNITTEST_OHOS_ABILITY_RUNTIME_MOCK_DATA_ABILITY_OBSERVER_STUB_CALL_H
