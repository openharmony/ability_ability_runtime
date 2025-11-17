/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import { BusinessError, AsyncCallback } from '@ohos.base';
import insightIntent from '@ohos.app.ability.insightIntent';
import AsyncCallbackWrapper from './utils/AbilityUtils';

export default namespace insightIntentProvider {

  loadLibraryWithPermissionCheck("insight_intent_provider_ani_kit.z", "@ohos.app.ability.insightIntentProvider")

  export native function nativeSendExecuteResult(instanceId: int, result: insightIntent.ExecuteResult, callback: AsyncCallbackWrapper<void>): void;

  export function sendExecuteResult(instanceId: int, result: insightIntent.ExecuteResult): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let asyncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        insightIntentProvider.nativeSendExecuteResult(instanceId, result, asyncCall);
      });
    });
  }
}