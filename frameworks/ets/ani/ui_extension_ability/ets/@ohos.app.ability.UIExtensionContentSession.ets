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

import { AbilityResult } from 'ability.abilityResult';
import { AsyncCallback } from '@ohos.base';
import { BusinessError } from '@ohos.base';
import { LocalStorage } from '@ohos.arkui.component.CommonTsEtsApi';
import hilog from '@ohos.hilog';

export class AsyncCallbackSessionWrapper<T> {
  myFun_:AsyncCallback<T, void> = (err: BusinessError<void>, data: T) => {}

  constructor(myFun:AsyncCallback<T, void>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<void>, data: T) : void {
    this.myFun_(err, data);
  }
}

export default class UIExtensionContentSession {
  nativeContextSession:long = 0;
  native nativeSendData(data: Record<string, Object>): void;
  native loadContent(path: string, storage?: LocalStorage): void;
  native setWindowBackgroundColor(color: string): void;
  //native getUIExtensionHostWindowProxy(): uiExtensionHost.UIExtensionHostWindowProxy;
  native setReceiveDataCallbackASync(): void;
  native terminateSelfSync(callback:AsyncCallbackSessionWrapper<void>): void;
  native terminateSelfWithResultSync(parameter: AbilityResult, callback:AsyncCallbackSessionWrapper<void>): void;

  sendData(data: Record<string, Object>): void {
    this.nativeSendData(data);
  }

   setReceiveDataCallback(callback: (data: Record<string, Object>) => void): void {
     let p1 = taskpool.execute(():undefined => {this.setReceiveDataCallbackASync(); return undefined});
         p1.then((e: NullishType)=>{
            let result = e as Record<string, Object>;
              callback(result);
         }, (err:Object): void => {
         });
   }

  terminateSelf(callback:AsyncCallback<void>): void {
    let myCall = new AsyncCallbackSessionWrapper<void>(callback);
    launch this.terminateSelfSync(myCall);
  }

  terminateSelf(): Promise<void> {
    let p = new Promise<void>((resolve: () => void, reject:(err: BusinessError<void>) => void): void => {
      let myCall = new AsyncCallbackSessionWrapper<void>((err: BusinessError<void>) => {
        if (err.code == 0) {
          resolve();
        } else {
          reject(err);
        }
      });
      launch this.terminateSelfSync(myCall);
    });
    return p;
  }

  terminateSelfWithResult(parameter: AbilityResult, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackSessionWrapper<void>(callback);
    launch this.terminateSelfWithResultSync(parameter, myCall);
  }

  terminateSelfWithResult(parameter: AbilityResult): Promise<void> {
    let p = new Promise<void>((resolve: (data: undefined) => void, reject:(err: BusinessError<void>) => void): void => {
      let myCall = new AsyncCallbackSessionWrapper<void>((err: BusinessError<void>) => {
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      launch this.terminateSelfWithResultSync(parameter, myCall);
    });
    return p;
  }
}