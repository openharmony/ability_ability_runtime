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

import Want from '@ohos.app.ability.Want';
import wantConstant from '@ohos.app.ability.wantConstant';
import { BusinessError, AsyncCallback } from '@ohos.base';
import insightIntent from './@ohos.app.ability.insightIntent';
import AsyncCallbackWrapper from './utils/AbilityUtils';

export default namespace insightIntentDriver {

  loadLibrary("insight_intent_driver_ani_kit.z")

  export interface ExecuteParam {
    bundleName: string;
    moduleName: string;
    abilityName: string;
    insightIntentName: string;
    insightIntentParam: Record<string, Object>;
    executeMode: insightIntent.ExecuteMode;
    displayId?: number;
    uris?: Array<string>;
    flags?: number;
  }

  export native function nativeExecuteSync(param: ExecuteParam,
    callback: AsyncCallbackWrapper<insightIntent.ExecuteResult>,
    isCallback: boolean): void;

  export function execute(param: ExecuteParam, callback: AsyncCallback<insightIntent.ExecuteResult>): void {
    let pCallback = new AsyncCallbackWrapper<insightIntent.ExecuteResult>(callback);
    taskpool.execute((): void => {
      nativeExecuteSync(param, pCallback, true);
    });
  }

  export function execute(param: ExecuteParam): Promise<insightIntent.ExecuteResult> {
    let pPromise = new Promise<insightIntent.ExecuteResult>((
      resolve: (data: insightIntent.ExecuteResult) => void,
      reject: (error: BusinessError<void>) => void) => {
      let pCallback = new AsyncCallbackWrapper<insightIntent.ExecuteResult>((
        err: BusinessError<void>, data: insightIntent.ExecuteResult) => {
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        nativeExecuteSync(param, pCallback, false);
      });
    });
    return pPromise;
  }
}