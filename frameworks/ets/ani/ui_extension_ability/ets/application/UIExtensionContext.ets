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
// import ConnectOptions from '../ability/connectOptions';
// import ExtensionContext from './ExtensionContext';
// import type Want from '../@ohos.app.ability.Want';
// import type StartOptions from '../@ohos.app.ability.StartOptions';
// import type AtomicServiceOptions from '../@ohos.app.ability.AtomicServiceOptions';
// import OpenLinkOptions from '../@ohos.app.ability.OpenLinkOptions';
// import type ConfigurationConstant from '../@ohos.app.ability.ConfigurationConstant';
// import type UIServiceProxy from './UIServiceProxy';
// import type UIServiceExtensionConnectCallback from './UIServiceExtensionConnectCallback';
import hilog from '@ohos.hilog';

export class AsyncCallbackContextWrapper<T> {
  myFun_:AsyncCallback<T, void> = (err: BusinessError<void>, data: T) => {}

  constructor(myFun:AsyncCallback<T, void>){
    console.log("AsyncCallbackContextWrapper");
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<void>, data: T) : void {
    this.myFun_(err, data);
  }
}

export default class UIExtensionContext {
  public nativeUIExtensionContext:long = 0;
  public native  terminateSelfSync(callback:AsyncCallbackContextWrapper<void>): void;
  public native  terminateSelfWithResultSync(parameter: AbilityResult, callback:AsyncCallbackContextWrapper<void>): void;

  terminateSelf(callback:AsyncCallback<void>): void {
    let myCall = new AsyncCallbackContextWrapper<void>(callback);
    launch this.terminateSelfSync(myCall);
  }

  terminateSelf(): Promise<void> {
    let p = new Promise<void>((resolve: () => void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackContextWrapper<void>((err: BusinessError<void>)=>{
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
    hilog.info(0x0000, 'testTag', 'terminateSelfWithResult callback enter');
    let myCall = new AsyncCallbackContextWrapper<void>(callback);
    launch this.terminateSelfWithResultSync(parameter, myCall);
  }

  terminateSelfWithResult(parameter: AbilityResult): Promise<int>{
    hilog.info(0x0000, 'testTag', 'terminateSelfWithResult Promise enter');
    let p = new Promise<int>((resolve: (data: int)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackContextWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(1);
        } else {
          reject(err);
        }
      });
      hilog.info(0x0000, 'testTag', 'terminateSelfWithResult launch');
      launch this.terminateSelfWithResultSync(parameter, myCall);
    });
    hilog.info(0x0000, 'testTag', 'terminateSelfWithResult Promise return');
    return p;
  }
}