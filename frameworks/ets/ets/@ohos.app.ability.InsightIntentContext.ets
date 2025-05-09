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
import Want from '@ohos.app.ability.Want';

export default class InsightIntentContext {
  nativeContext: long;

  public native nativeStartAbilitySync(want: Want): BusinessError<void>;

  startAbility(want: Want, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute((): BusinessError<void> => {
      return this.nativeStartAbilitySync(want);
    });
    p1.then((e: NullishType) => {
      let retError = e as BusinessError<void>;
      callback(retError, undefined);
    }, (err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  startAbility(want: Want): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError<void>) => void): void => {
      let p1 = taskpool.execute((): BusinessError<void> => {
        return this.nativeStartAbilitySync(want);
      });
      p1.then((e: NullishType) => {
        let retError = e as BusinessError<void>;
        if (retError.code === 0) {
          resolve(undefined);
        } else {
          reject(retError);
        }
      }).catch((err: BusinessError): void => {
        reject(err);
      });
    });
    return p;
  }
}